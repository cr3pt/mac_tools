from pathlib import Path
from noriben57.models import VMConfig
from noriben57.platform_qemu import choose_accel, build_qemu_cmd

def test_choose_accel_linux():
    host = {'is_linux': True, 'is_macos': False, 'arch': 'x86_64', 'has_kvm': True, 'has_hvf': False}
    assert choose_accel(host, 'x86_64', 'auto') == 'kvm'

def test_build_qemu_cmd_shape(tmp_path, monkeypatch):
    import noriben57.platform_qemu as pq
    monkeypatch.setattr(pq, 'qemu_binary', lambda arch: '/usr/bin/qemu-system-x86_64')
    host = {'is_linux': True, 'is_macos': False, 'arch': 'x86_64', 'has_kvm': True, 'has_hvf': False}
    vm = VMConfig('vm2', 'x86_64', Path('/tmp/test.qcow2'), 'snap', '8G', 4, 2223, 4445, tmp_path/'vm.pid', tmp_path/'vm.log')
    cmd = build_qemu_cmd(vm, 'kvm', host)
    assert '/usr/bin/qemu-system-x86_64' in cmd[0]
    assert '-machine' in cmd
