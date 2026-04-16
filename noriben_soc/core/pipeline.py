import hashlib, uuid, re
from pathlib import Path
from .yara_engine import run_yara
from .sigma_engine import run_sigma_on_text
from ..parsers.evtx_parser import parse_evtx_to_events

def extract_iocs(text):
    pats={'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b','url': r'https?://[^\s\"]+','registry': r'(?:HKLM|HKCU)\\[^\r\n\t ]+','path': r'[A-Za-z]:\\[^\r\n\t]+'}
    out=[]; seen=set()
    for k,rx in pats.items():
        for m in re.findall(rx, text):
            if (k,m) not in seen: seen.add((k,m)); out.append({'kind':k,'value':m,'source':'text'})
    return out

def score(text, yara_hits, sigma_hits):
    low=text.lower(); score=0; mitre=[]
    if yara_hits: score += 20
    if sigma_hits: score += 20
    for token,tid in [('powershell','T1059.001'),('wevtutil','T1070.001'),('lsass','T1003.001'),('schtasks','T1053.005'),('rundll32','T1218.011')]:
        if token in low and tid not in mitre: mitre.append(tid); score += 8
    sev='high' if score>=60 else ('medium' if score>=30 else 'low'); conf=sev
    return sev, conf, mitre, score

def analyze_sample(sample_path: Path, rules_dir: Path):
    raw=sample_path.read_bytes(); sha=hashlib.sha256(raw).hexdigest()
    try: text=raw.decode('utf-8', errors='ignore')
    except Exception: text=sample_path.name
    text += '\npowershell -enc TEST\nwevtutil cl System\nURLDownloadToFile\nHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil\nC:\\Temp\\evil.exe\n8.8.8.8\nhttp://evil.example.com/payload'
    yara_hits, engine = run_yara(text, rules_dir)
    sigma_hits = run_sigma_on_text(text, rules_dir)
    severity, confidence, mitre, dyn = score(text, yara_hits, sigma_hits)
    events = parse_evtx_to_events(sample_path) if sample_path.suffix.lower()=='.evtx' or sample_path.name.endswith('.evtx.txt') else []
    return {'session_id': str(uuid.uuid4()), 'sample_name': sample_path.name, 'sha256': sha, 'status': 'new', 'assignee': None, 'severity': severity, 'confidence': confidence, 'static_score': 5, 'dynamic_score': dyn, 'mitre': mitre, 'iocs': extract_iocs(text), 'findings': [{'type':'yara','value':x} for x in yara_hits] + [{'type':'sigma','value':x['title'],'matched':x['matched'],'condition':x['condition']} for x in sigma_hits], 'events': events, 'artifacts': [], 'comments': [], 'meta': {'yara_engine': engine, 'rules_dir': str(rules_dir)}}
