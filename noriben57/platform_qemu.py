import os, shutil, sys

def detect_host():
    return {
        'platform': sys.platform,
        'arch': os.uname().machine,
        'is_macos': sys.platform == 'darwin',
        'is_linux': sys.platform.startswith('linux'),
        'has_hvf': sys.platform == 'darwin',
        'has_kvm': sys.platform.startswith('linux') and os.path.exists('/dev/kvm'),
    }

def choose_accel(host, guest_arch, mode='auto'):
    if mode and mode != 'auto':
        return mode
    if host['is_macos']:
        return 'hvf' if guest_arch == 'aarch64' or host['arch'] != 'arm64' else 'tcg'
    if host['is_linux']:
        return 'kvm' if host['has_kvm'] else 'tcg'
    return 'tcg'

def qemu_binary(guest_arch):
    return shutil.which('qemu-system-aarch64') if guest_arch == 'aarch64' else shutil.which('qemu-system-x86_64')

def build_qemu_cmd(vm, accel, host):
    qbin = qemu_binary(vm.arch)
    if not qbin:
        raise RuntimeError(f'Brak QEMU binary dla {vm.arch}')
    if vm.arch == 'aarch64':
        machine = 'virt'
        cpu = 'host' if accel in {'hvf','kvm'} and host['arch'] == 'arm64' else 'max'
        device = 'virtio-net-device,netdev=net0'
        drive_if = 'virtio'
    else:
        machine = 'q35'
        cpu = 'host' if accel in {'hvf','kvm'} and host['arch'] in {'x86_64','amd64'} else 'qemu64'
        device = 'virtio-net-pci,netdev=net0'
        drive_if = 'virtio'
    accel_part = f'{accel}:tcg' if accel in {'hvf','kvm'} else 'tcg'
    return [
        qbin, '-machine', f'{machine},accel={accel_part}', '-cpu', cpu,
        '-m', str(vm.mem), '-smp', str(vm.smp),
        '-drive', f'file={vm.disk},format=qcow2,if={drive_if},cache=writeback',
        '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{vm.ssh_port}-:22,restrict=on',
        '-device', device,
        '-monitor', f'tcp:127.0.0.1:{vm.monitor_port},server,nowait',
        '-display', 'none', '-daemonize', '-pidfile', str(vm.pidfile)
    ]
