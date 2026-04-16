import json, shutil, sys
from pathlib import Path
from .platform_qemu import detect_host, recommend_profile

PREPARE_NOTES = {
    'macos-arm64': [
        'Zainstaluj qemu, openssh i python3, np. przez Homebrew',
        'Preferuj Windows ARM guest dla lepszej wydajności',
        'x86_64 guest na Apple Silicon zostaw jako wolniejszy fallback',
        'Sprawdź dostępność qemu-system-aarch64 i qemu-img',
    ],
    'ubuntu-x86_64': [
        'Zainstaluj qemu-system-x86, qemu-utils, openssh-client i python3',
        'Jeśli możliwe, włącz /dev/kvm dla wydajności',
        'Preferuj Windows x86_64 guest jako główny profil',
        'Sprawdź qemu-system-x86_64, qemu-img, ssh i scp',
    ],
    'ubuntu-arm64': [
        'Zainstaluj qemu-system-arm lub qemu-system-aarch64 oraz qemu-utils',
        'Preferuj Windows ARM guest',
        'Zweryfikuj zgodność obrazu gościa z hostem ARM',
        'Sprawdź qemu-system-aarch64, qemu-img, ssh i scp',
    ],
    'generic': [
        'Zainstaluj python3, ssh, scp, qemu-img i odpowiednie binaria qemu-system-*',
        'Ustal, czy guest ma być ARM czy x86_64',
    ],
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
    plan = {
        'host': host,
        'recommended_profile': profile,
        'tool_status': tool_status,
        'host_tools_dir': str(tools_dir),
        'host_results_dir': str(results_dir),
        'notes': PREPARE_NOTES.get(profile, PREPARE_NOTES['generic']),
    }
    prep_file = results_dir / 'prepare_plan.json'
    prep_file.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding='utf-8')
    return prep_file, plan
