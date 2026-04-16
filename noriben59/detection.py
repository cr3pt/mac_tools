import re
from .models import Finding, TimelineEvent

MITRE_MAP = {
    'powershell': 'T1059.001', 'rundll32': 'T1218.011', 'regsvr32': 'T1218.010', 'mshta': 'T1218.005', 'wmic': 'T1047',
    'certutil': 'T1105', 'bitsadmin': 'T1197', 'lsass': 'T1003.001', 'MiniDumpWriteDump': 'T1003.001', 'Set-MpPreference': 'T1562.001',
    'vssadmin': 'T1490', 'CurrentVersion\\Run': 'T1547.001', 'schtasks': 'T1053.005', 'wevtutil': 'T1070.001', 'AmsiUtils': 'T1562.001',
    'CreateRemoteThread': 'T1055', 'WriteProcessMemory': 'T1055', 'WinHttpOpen': 'T1105', 'URLDownloadToFile': 'T1105',
    'ipconfig': 'T1016', 'systeminfo': 'T1082', 'whoami': 'T1033', 'nltest': 'T1018', 'tasklist': 'T1057', 'quser': 'T1033'
}
SIGMA_RULES = {
    'Suspicious PowerShell': ['powershell', '-enc', 'FromBase64String', 'DownloadString', 'Invoke-WebRequest'],
    'LOLBins Download or Exec': ['rundll32', 'regsvr32', 'mshta', 'wmic', 'certutil', 'bitsadmin'],
    'Credential Access': ['lsass', 'MiniDumpWriteDump', 'sekurlsa', 'LogonPasswords'],
    'Defense Evasion': ['Set-MpPreference', 'DisableRealtimeMonitoring', 'vssadmin', 'wevtutil cl', 'AmsiUtils'],
    'Persistence': [r'CurrentVersion\\Run', r'CurrentVersion\\RunOnce', 'schtasks', 'Startup'],
    'Process Injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtMapViewOfSection'],
    'Downloader Activity': ['WinHttpOpen', 'InternetOpenUrl', 'URLDownloadToFile', 'DownloadFile'],
    'Discovery Commands': ['whoami', 'ipconfig', 'systeminfo', 'tasklist', 'nltest', 'quser'],
}
PATTERNS = {
    'Nowe procesy': r'Process Create|CreateProcess|Spawned',
    'Sieć': r'TCP|UDP|Connect|DNS|HTTP|HTTPS',
    'Persistence': r'RunOnce|CurrentVersion\\Run|schtasks|Startup|Services',
    'Injection': r'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection',
    'Defense evasion': r'Set-MpPreference|DisableRealtimeMonitoring|vssadmin|wevtutil|AmsiUtils',
    'Downloads': r'WinHttpOpen|InternetOpenUrl|URLDownloadToFile|bitsadmin|certutil',
    'Discovery': r'whoami|ipconfig|systeminfo|net user|tasklist|quser|nltest',
    'Credential Access': r'lsass|MiniDumpWriteDump|sekurlsa|LogonPasswords',
}

def map_mitre(text, session):
    hits = []
    for k, v in MITRE_MAP.items():
        if k.lower() in text.lower() and v not in hits:
            hits.append(v)
    for h in hits:
        if h not in session.mitre_hits:
            session.mitre_hits.append(h)
    return ','.join(hits)

def analyze_text(text, vm_name, session):
    for cat, rx in PATTERNS.items():
        matches = re.findall(rx + r'.*', text, flags=re.I)
        if matches:
            mitre = map_mitre('\n'.join(matches), session)
            session.dynamic_findings.append(Finding('dynamic', f'{vm_name}: {cat}', 12, vm=vm_name, mitre=mitre))
            session.dynamic_score += 12
            for m in matches[:5]:
                session.timeline.append(TimelineEvent(vm_name, cat, m.strip(), vm=vm_name, mitre=mitre))
    for title, pats in SIGMA_RULES.items():
        matched = []
        for pat in pats:
            for line in text.splitlines():
                if pat.lower() in line.lower() and line.strip() not in matched:
                    matched.append(line.strip())
        if matched:
            mitre = map_mitre('\n'.join(matched), session)
            session.sigma_hits.append(f'{vm_name}:{title}')
            session.dynamic_findings.append(Finding('dynamic', f'SIGMA-like: {title}', 8, vm=vm_name, mitre=mitre))
            session.dynamic_score += 8
            for m in matched[:5]:
                session.timeline.append(TimelineEvent('SIGMA', title, m, vm=vm_name, mitre=mitre))
