import asyncio, json, shutil, os, time, shlex, subprocess
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

    # Przygotuj tymczasową kopię qcow2 (backing file) by izolować bazowy obraz
    tmp_dir = SHARED / 'tmp_vms'
    tmp_dir.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    tmp_qcow2 = tmp_dir / f"{cfg['qcow2']}.{sample.stem}.{timestamp}.qcow2"

    # szybkie stworzenie pliku z backingiem (szybsze niż pełna kopia)
    try:
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-b', str(qcow2), str(tmp_qcow2)], check=True)
    except Exception as e:
        return _empty(vm, f'failed creating tmp qcow2: {e}')

    # Sieć: domyślnie wyłączona chyba że explicite ustawione
    allow_net = os.getenv('QEMU_ALLOW_NETWORK', 'false').lower() in ('1', 'true', 'yes')
    proxy_server = None
    wpad_server = None
    dns_server = None
    if allow_net:
        netdev = (f'user,id={cfg["netdev_id"]},restrict=on,'
                  f'smb={SHARED}')
        # Start host-side proxy and WPAD/DNS helpers
        try:
            from .net_proxy import start_proxy, stop_proxy
            from .wpad import start_wpad, stop_wpad
            from .simple_dns import start_dns, stop_dns
            # start proxy and wpad/dns on localhost
            proxy_server = await start_proxy()
            try:
                wpad_server = await start_wpad()
            except Exception:
                wpad_server = None
            try:
                dns_server = await start_dns()
            except Exception:
                dns_server = None
        except Exception:
            # If imports fail, continue without proxy
            proxy_server = None
    else:
        netdev = None

    cmd = [
        'qemu-system-x86_64',
        '-name', f'noriben-{vm}',
        '-machine', 'type=q35',
        '-cpu', 'max',
        '-smp', 'cores=4,threads=1',
        '-m', '4096',
        '-drive', f'file={tmp_qcow2},format=qcow2,if=virtio,index=0,media=disk',
    ]

    if netdev:
        cmd += [
            '-netdev', netdev,
            '-device', f'virtio-net-pci,netdev={cfg["netdev_id"]}',
            '-object', f'filter-dump,id=dump{cfg["vnc"]},netdev={cfg["netdev_id"]},file={pcap_file}',
        ]
    else:
        pcap_file = None

    cmd += [
        '-vnc', f'0.0.0.0:{cfg["vnc"]},password',
        '-virtfs', f'local,path={SHARED},mount_tag=shared,security_model=none',
        '-monitor', f'tcp:0.0.0.0:{cfg["mon_port"]},server,nowait',
        '-usbdevice', 'tablet',
        '-vga', 'std',
        '-daemonize',
    ] + accel_flag

    # Uruchom QEMU w shellu by móc ustawić ograniczenia zasobów (ulimit)
    mem_kb = int(os.getenv('QEMU_RLIMIT_VMEM_KB', str(8 * 1024 * 1024)))
    cpu_sec = int(os.getenv('QEMU_RLIMIT_CPU_SEC', '900'))
    # zbuduj command string bezpiecznie
    cmd_str = ' '.join(shlex.quote(p) for p in cmd)
    shell_cmd = f'ulimit -v {mem_kb} -t {cpu_sec} && exec {cmd_str}'

    proc = await asyncio.create_subprocess_shell(shell_cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        # jeśli qemu nie wystartował, spróbuj usunąć tmp
        try:
            tmp_qcow2.unlink()
        except Exception:
            pass
        return _empty(vm, stderr.decode()[:500])

    # Ustaw haslo VNC przez monitor (może nie działać od razu)
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
            if pcap_file and pcap_file.exists():
                data['network_iocs'] = analyze_pcap(pcap_file)

            # Po uzyskaniu wyniku spróbuj zatrzymać VM i usunąć tymczasowy obraz
            try:
                await _monitor_command(cfg['mon_port'], 'quit')
            except Exception:
                pass
            try:
                tmp_qcow2.unlink()
            except Exception:
                pass

            # stop helpers if started
            try:
                if wpad_server:
                    await stop_wpad()
            except Exception:
                pass
            try:
                if dns_server:
                    await stop_dns(dns_server)
            except Exception:
                pass
            try:
                if proxy_server:
                    await stop_proxy()
            except Exception:
                pass

            return data

    # Timeout — przynajmniej parsuj PCAP jesli jest
    result = _empty(vm, 'timeout')
    if pcap_file and pcap_file.exists():
        result['network_iocs'] = analyze_pcap(pcap_file)

    # spróbuj wyłączyć VM i oczyścić tmp image
    try:
        await _monitor_command(cfg['mon_port'], 'quit')
    except Exception:
        pass
    try:
        tmp_qcow2.unlink()
    except Exception:
        pass

    # stop helpers if started
    try:
        if wpad_server:
            await stop_wpad()
    except Exception:
        pass
    try:
        if dns_server:
            await stop_dns(dns_server)
    except Exception:
        pass
    try:
        if proxy_server:
            await stop_proxy()
    except Exception:
        pass
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

async def _monitor_command(mon_port: int, command: str):
    """Send a command to QEMU monitor (e.g., 'quit')"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', mon_port), timeout=5)
        # consume banner
        await reader.read(1024)
        writer.write(f'{command}\n'.encode())
        await writer.drain()
        writer.close()
    except Exception:
        pass

def _empty(vm: str, reason: str = '') -> dict:
    return {'vm': vm, 'behavior_score': 0, 'error': reason,
            'network': [], 'network_iocs': [], 'files_dropped': [],
            'processes': [], 'registry': []}
