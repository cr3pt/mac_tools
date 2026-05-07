
# Backward-compatible simple keywords; will be extended by rules_manager patterns when available
KEYWORDS = {
    'HIGH':   ['lsass','mimikatz','sekurlsa','invoke-mimikatz'],
    'MEDIUM': ['powershell -enc','certutil -decode','wscript','mshta','regsvr32'],
    'LOW':    ['cmd.exe','wevtutil','net user'],
}

def run_sigma_scan(text: str) -> list:
    t = text.lower()
    hits = []
    # first use rules_manager patterns if available
    try:
        from .. import rules_manager
        patterns = rules_manager.get_sigma_patterns()
        for p in patterns:
            if p in t:
                hits.append(dict(rule=p, severity='MEDIUM', type='SIGMA'))
    except Exception:
        patterns = []
    # fall back to static KEYWORDS
    for sev,kws in KEYWORDS.items():
        for kw in kws:
            if kw in t:
                hits.append(dict(rule=kw, severity=sev, type='SIGMA'))
    return hits
