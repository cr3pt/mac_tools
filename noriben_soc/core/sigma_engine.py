KEYWORDS = {
    'HIGH':   ['lsass','mimikatz','sekurlsa','invoke-mimikatz'],
    'MEDIUM': ['powershell -enc','certutil -decode','wscript','mshta','regsvr32'],
    'LOW':    ['cmd.exe','wevtutil','net user'],
}
def run_sigma_scan(text: str) -> list:
    t = text.lower()
    return [dict(rule=kw, severity=sev, type='SIGMA')
            for sev,kws in KEYWORDS.items() for kw in kws if kw in t]
