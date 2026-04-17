import yara
from pathlib import Path
RULES_DIR = Path('/shared/yara_rules/rules')
def run_yara_scan(data: bytes) -> list:
    hits = []
    for f in RULES_DIR.rglob('*.yar'):
        try:
            for m in yara.compile(str(f)).match(data=data):
                hits.append(dict(rule=m.rule, tags=list(m.tags), severity=_sev(m.tags), type='YARA'))
        except Exception: pass
    return hits
def _sev(tags):
    t = [x.lower() for x in tags]
    return 'HIGH' if 'high' in t or 'critical' in t else ('MEDIUM' if 'medium' in t else 'LOW')
