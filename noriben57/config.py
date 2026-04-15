import json
from pathlib import Path

DEFAULT_CONFIG = {
    'analysis_timeout': 300,
    'analysis_profile': 'balanced',
    'dual_vm_mode': False,
    'parallel_dual_vm': True,
    'preflight_strict': True,
    'retry_count': 3,
    'retry_delay': 3,
    'qemu_accel_mode': 'auto',
    'platform_profile': 'auto',
    'qemu_disk': str(Path.home() / 'NoribenTools' / 'windows_arm_sandbox.qcow2'),
    'qemu_snapshot': 'Baseline_Clean',
    'qemu_mem': '16G',
    'qemu_smp': 4,
    'qemu_ssh_port': 2222,
    'qemu_monitor_port': 4444,
    'qemu_disk_x86': str(Path.home() / 'NoribenTools' / 'windows_x86_sandbox.qcow2'),
    'qemu_snapshot_x86': 'Baseline_Clean',
    'qemu_mem_x86': '8G',
    'qemu_smp_x86': 4,
    'qemu_ssh_port_x86': 2223,
    'qemu_monitor_port_x86': 4445,
    'vm_user': 'Administrator',
    'vm_python': r'C:\\Python3\\python.exe',
    'vm_noriben': r'C:\\Tools\\Noriben.py',
    'vm_malware_dir': r'C:\\Malware',
    'vm_output_dir': r'C:\\NoribenLogs',
}

def load_config(path=None):
    cfg = dict(DEFAULT_CONFIG)
    if not path:
        return cfg
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    text = p.read_text(encoding='utf-8', errors='ignore').strip()
    if text.startswith('{'):
        data = json.loads(text)
        for k, v in data.items():
            if k in cfg:
                cfg[k] = v
        return cfg
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line and '=' not in line:
            k, v = line.split(':', 1)
        elif '=' in line:
            k, v = line.split('=', 1)
        else:
            continue
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k in cfg:
            cur = cfg[k]
            if isinstance(cur, bool): cfg[k] = v.lower() in {'1','true','yes','y'}
            elif isinstance(cur, int): cfg[k] = int(v)
            else: cfg[k] = v
    return cfg
