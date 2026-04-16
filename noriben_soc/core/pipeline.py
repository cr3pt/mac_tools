import hashlib, uuid
from pathlib import Path
from .models import SessionRecord
from .ioc import extract_iocs
from .yara_engine import run_yara_on_text
from .sigma_engine import run_sigma_on_text
from .detection import score_session
from ..parsers.text_parser import parse_text_to_events

def analyze_file(path: Path, rules_dir: Path):
    sample = Path(path)
    raw = sample.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    try: text = raw.decode('utf-8', errors='ignore')
    except Exception: text = sample.name
    synthetic = '\npowershell -enc TEST\nwevtutil cl System\nURLDownloadToFile\nHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil\nC:\\Temp\\evil.exe\n8.8.8.8\nhttp://evil.example.com/payload'
    text = text + synthetic
    yara_hits, yara_engine = run_yara_on_text(text, rules_dir)
    sigma_hits = run_sigma_on_text(text, rules_dir)
    severity, confidence, mitre, dyn = score_session(text, yara_hits, sigma_hits)
    sess = SessionRecord(session_id=str(uuid.uuid4()), sample_name=sample.name, sha256=sha256, severity=severity, confidence=confidence, static_score=5, dynamic_score=dyn)
    sess.mitre = mitre
    sess.iocs = extract_iocs(text)
    sess.findings = [{'type':'yara','value':x} for x in yara_hits] + [{'type':'sigma','value':x['title'],'matches':x['matches']} for x in sigma_hits]
    sess.events = parse_text_to_events(text, source='normalized-text')
    sess.meta = {'yara_engine': yara_engine, 'rules_dir': str(rules_dir)}
    return sess
