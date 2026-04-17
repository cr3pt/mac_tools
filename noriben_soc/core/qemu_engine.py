import asyncio, json, shutil
from pathlib import Path

SHARED = Path('/shared')
VM_IMG = SHARED / 'vms/win10.qcow2'

async def run_dynamic_analysis(sample: Path, timeout: int = 300) -> dict:
    dst = SHARED / 'samples' / sample.name
    shutil.copy2(sample, dst)
    cmd = ['qemu-system-x86_64','-machine','q35','-cpu','host',
           '-smp','4','-m','4096',
           f'-drive', f'file={VM_IMG},if=virtio,snapshot=on',
           '-netdev','user,id=net0','-device','virtio-net-pci,netdev=net0',
           '-vnc',':0,password',
           '-virtfs',f'local,path={SHARED},mount_tag=shared,security_model=none',
           '-monitor','tcp:0.0.0.0:4444,server,nowait','-daemonize']
    proc = await asyncio.create_subprocess_exec(*cmd)
    await asyncio.sleep(15)
    bat = SHARED / 'run.bat'
    bat.write_text(
        f'@echo off\ncd C:\\noriben\n'
        f'python noriben.py -t {timeout} '
        f'--output C:\\shared\\results\\{sample.stem}.pml '
        f'--cmd C:\\shared\\samples\\{sample.name}\n')
    result_file = SHARED / 'results' / f'{sample.stem}_noriben.json'
    for _ in range(timeout // 5):
        await asyncio.sleep(5)
        if result_file.exists():
            return json.loads(result_file.read_text())
    return {'behavior_score':0,'network':[],'files_dropped':[],'processes':[],'registry':[]}
