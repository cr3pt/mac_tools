import asyncio, json, shutil, os
from pathlib import Path
SHARED = Path('/shared')
async def run_dynamic_analysis(sample: Path, timeout: int = 300) -> dict:
    shutil.copy2(sample, SHARED / 'samples' / sample.name)
    accel = os.getenv('QEMU_ACCEL','tcg')
    af = '-accel kvm' if accel == 'kvm' else '-accel tcg,thread=multi'
    cmd = (f'qemu-system-x86_64 -machine q35 {af} -cpu max -smp 4 -m 4096 '
           f'-drive file={SHARED}/vms/win10.qcow2,if=virtio,snapshot=on '
           f'-netdev user,id=net0,restrict=on -device virtio-net-pci,netdev=net0 '
           f'-vnc 0.0.0.0:0,password '
           f'-virtfs local,path={SHARED},mount_tag=shared,security_model=none '
           f'-monitor tcp:0.0.0.0:4444,server,nowait -daemonize').split()
    await asyncio.create_subprocess_exec(*cmd)
    await asyncio.sleep(15)
    (SHARED / 'run.bat').write_text(
        f'@echo off\ncd C:\\noriben\npython noriben.py -t {timeout} '
        f'--output C:\\shared\\results\\{sample.stem}.pml '
        f'--cmd C:\\shared\\samples\\{sample.name}\n')
    result_file = SHARED / 'results' / f'{sample.stem}_noriben.json'
    for _ in range(timeout // 5):
        await asyncio.sleep(5)
        if result_file.exists(): return json.loads(result_file.read_text())
    return {'behavior_score':0,'network':[],'files_dropped':[],'processes':[],'registry':[]}
