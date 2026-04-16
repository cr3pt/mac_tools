MITRE_MAP = {'powershell':'T1059.001','rundll32':'T1218.011','regsvr32':'T1218.010','mshta':'T1218.005','wmic':'T1047','certutil':'T1105','bitsadmin':'T1197','lsass':'T1003.001','Set-MpPreference':'T1562.001','vssadmin':'T1490','CurrentVersion\\Run':'T1547.001','schtasks':'T1053.005','wevtutil':'T1070.001','CreateRemoteThread':'T1055','WriteProcessMemory':'T1055','URLDownloadToFile':'T1105'}
SEVERITY_ORDER = ['low','medium','high','critical']
def mitre_from_text(text):
    hits=[]
    low=text.lower()
    for k,v in MITRE_MAP.items():
        if k.lower() in low and v not in hits: hits.append(v)
    return hits
def score_session(text, yara_hits, sigma_hits):
    base = 0
    if yara_hits: base += 20
    if sigma_hits: base += 20
    mitre = mitre_from_text(text)
    base += min(40, len(mitre)*8)
    if 'lsass' in text.lower(): base += 15
    if 'wevtutil' in text.lower() or 'Set-MpPreference'.lower() in text.lower(): base += 10
    if base >= 70: return 'high', 'high', mitre, base
    if base >= 40: return 'medium', 'medium', mitre, base
    return 'low', 'low', mitre, base
