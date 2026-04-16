import json, shutil
from pathlib import Path
from .platform_qemu import detect_host, recommend_profile

INSTALL_HINTS = {
    'macos-arm64': {
        'package_manager': 'brew',
        'commands': ['brew update', 'brew install qemu python openssh', 'which qemu-system-aarch64 qemu-img ssh scp python3'],
        'notes': ['Preferuj Windows ARM guest dla lepszej wydajności', 'Guest x86_64 na Apple Silicon traktuj jako wolniejszy fallback']
    },
    'ubuntu-x86_64': {
        'package_manager': 'apt',
        'commands': ['sudo apt-get update', 'sudo apt-get install -y qemu-system-x86 qemu-utils openssh-client python3 python3-venv', 'which qemu-system-x86_64 qemu-img ssh scp python3'],
        'notes': ['Jeśli możesz, upewnij się że /dev/kvm jest dostępne', 'Preferuj Windows x86_64 guest jako główny profil']
    },
    'ubuntu-arm64': {
        'package_manager': 'apt',
        'commands': ['sudo apt-get update', 'sudo apt-get install -y qemu-system-arm qemu-efi-aarch64 qemu-utils openssh-client python3 python3-venv', 'which qemu-system-aarch64 qemu-img ssh scp python3'],
        'notes': ['Preferuj Windows ARM guest', 'Zweryfikuj zgodność obrazu guest z hostem ARM']
    },
    'generic': {
        'package_manager': 'manual',
        'commands': ['python3 --version', 'ssh -V', 'qemu-img --version'],
        'notes': ['Dobierz właściwe binaria qemu-system-* ręcznie', 'Ustal czy guest ma być ARM czy x86_64']
    }
}

GUEST_CHECKLIST = {
    'common': [
        'Włącz OpenSSH Server w Windows guest',
        'Utwórz lub zweryfikuj konto Administrator do połączeń SSH',
        'Zainstaluj Python 3 w guest i potwierdź ścieżkę vm_python',
        'Skopiuj Noriben.py lub przygotuj host_tools_dir/Noriben.py',
        'Utwórz katalogi C:\\Tools, C:\\Malware i C:\\NoribenLogs',
        'Zweryfikuj reguły firewall dla SSH',
        'Przygotuj clean snapshot o nazwie zgodnej z qemu_snapshot',
    ],
    'windows-analysis': [
        'Sprawdź czy Noriben uruchamia się ręcznie w guest',
        'Zweryfikuj czy próbki zapisują logi do vm_output_dir',
        'Potwierdź że snapshot wraca do czystego stanu po analizie',
        'Przetestuj kopiowanie plików przez scp do i z guest',
    ]
}

def prepare_environment(cfg):
    host = detect_host()
    profile = cfg.get('platform_profile', 'auto')
    if profile == 'auto':
        profile = recommend_profile(host)
    tools_dir = Path(cfg['host_tools_dir'])
    results_dir = Path(cfg['host_results_dir'])
    tools_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    tool_status = {t: bool(shutil.which(t)) for t in ['python3', 'ssh', 'scp', 'qemu-img', 'qemu-system-aarch64', 'qemu-system-x86_64']}
    install = INSTALL_HINTS.get(profile, INSTALL_HINTS['generic'])
    plan = {
        'host': host,
        'recommended_profile': profile,
        'tool_status': tool_status,
        'host_tools_dir': str(tools_dir),
        'host_results_dir': str(results_dir),
        'package_manager': install['package_manager'],
        'install_commands': install['commands'],
        'notes': install['notes'],
        'guest_checklist': GUEST_CHECKLIST,
    }
    prep_file = results_dir / 'prepare_plan.json'
    prep_script = results_dir / 'prepare_commands.sh'
    guest_file = results_dir / 'windows_guest_checklist.txt'
    prep_script.write_text('#!/usr/bin/env bash\nset -e\n' + '\n'.join(plan['install_commands']) + '\n', encoding='utf-8')
    guest_lines = ['Windows guest checklist', '']
    for section, items in GUEST_CHECKLIST.items():
        guest_lines.append(f'[{section}]')
        for item in items:
            guest_lines.append(f'- {item}')
        guest_lines.append('')
    guest_file.write_text('\n'.join(guest_lines), encoding='utf-8')
    prep_file.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding='utf-8')
    return prep_file, prep_script, guest_file, plan
