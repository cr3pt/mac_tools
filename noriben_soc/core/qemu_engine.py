import asyncio, json, shutil, os, time
from pathlib import Path
from .network_analyzer import analyze_pcap

SHARED = Path(os.getenv('SHARED_DIR', '/shared'))

VM_CONFIG = {
    'win10': {'qcow2': 'win10.qcow2', 'vnc': 1, 'mon_port': 4441, 'vnc_port': 5901, 'netdev_id': 'net10'},
    'win11': {'qcow2': 'win11.qcow2', 'vnc': 2, 'mon_port': 4442, 'vnc_port': 5902, 'netdev_id': 'net11'},
}

async def run_dynamic_analysis(sample: Path, vm: str = 'win10', timeout: int = 300) -> dict:
    cfg   = VM_CONFIG[vm]
    qcow2 = SHARED / 'vms' / cfg['qcow2']
    if not qcow2.exists():
        return _empty(vm, f'{cfg["qcow2"]} not found')

    dst = SHARED / 'samples' / sample.name
    shutil.copy2(sample, dst)

    accel      = os.getenv('QEMU_ACCEL', 'tcg')
    accel_flag = ['-accel', 'kvm'] if accel == 'kvm' else ['-accel', 'tcg,thread=multi']
    pcap_file  = SHARED / 'results' / f'{sample.stem}_{vm}.pcap'

    # Sieć: tap z tcpdump przechwytujacym cały ruch VM
    # restrict=on = brak dostepu do hosta/LAN (bezpieczenstwo)
    # smb= = udostepnia /shared jako C:\shared w VM (Windows)
    netdev = (f'user,id={cfg["netdev_id"]},restrict=on,'
              f'smb={SHARED}')

    cmd = [
        'qemu-system-x86_64',
        '-name', f'noriben-{vm}',
        '-machine', 'type=q35',
        '-cpu', 'max',
        '-smp', 'cores=4,threads=1',
        '-m', '4096',
        '-drive', f'file={qcow2},format=qcow2,if=virtio,index=0,media=disk,snapshot=on',
        '-netdev', netdev,
        '-device', f'virtio-net-pci,netdev={cfg["netdev_id"]}',
        '-object', f'filter-dump,id=dump{cfg["vnc"]},netdev={cfg["netdev_id"]},file={pcap_file}',
        '-vnc', f'0.0.0.0:{cfg["vnc"]},password',
        '-virtfs', f'local,path={SHARED},mount_tag=shared,security_model=none',
        '-monitor', f'tcp:0.0.0.0:{cfg["mon_port"]},server,nowait',
        '-usbdevice', 'tablet',
        '-vga', 'std',
        '-daemonize',
    ] + accel_flag

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        return _empty(vm, stderr.decode()[:500])

    # Ustaw haslo VNC przez monitor
    await asyncio.sleep(3)
    await _set_vnc_password(cfg['mon_port'], 'noriben')

    await asyncio.sleep(15)

    # Wyzwol Noriben przez run.bat w shared folder
    stem = sample.stem
    bat_content = (
        '@echo off\n'
        'cd C:\\noriben\n'
        f'python noriben.py -t {timeout} '
        f'--output C:\\shared\\results\\{stem}_{vm}.pml '
        f'--cmd C:\\shared\\samples\\{sample.name}\n'
    )
    (SHARED / f'run_{vm}.bat').write_text(bat_content)

    # Czekaj na wynik Noriben
    result_file = SHARED / 'results' / f'{stem}_{vm}_noriben.json'
    for _ in range(timeout // 5):
        await asyncio.sleep(5)
        if result_file.exists():
            data = json.loads(result_file.read_text())
            data['vm'] = vm
            # Analizuj PCAP
            if pcap_file.exists():
                data['network_iocs'] = analyze_pcap(pcap_file)
            return data

    # Timeout — przynajmniej parsuj PCAP jesli jest
    result = _empty(vm, 'timeout')
    if pcap_file.exists():
        result['network_iocs'] = analyze_pcap(pcap_file)
    return result

async def _set_vnc_password(mon_port: int, password: str):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', mon_port), timeout=5)
        await reader.read(1024)
        writer.write(f'change vnc password {password}\n'.encode())
        await writer.drain()
        writer.close()
    except Exception:
        pass

def _empty(vm: str, reason: str = '') -> dict:
    return {'vm': vm, 'behavior_score': 0, 'error': reason,
            'network': [], 'network_iocs': [], 'files_dropped': [],
            'processes': [], 'registry': []}
