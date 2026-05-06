try:
    import yara
except Exception:
    yara = None

from pathlib import Path

RULES_DIR = Path('/shared/yara_rules')


def run_yara_scan(data: bytes) -> list:
    """Run YARA rules against given data. If python-yara is not installed or rules path
    does not exist, silently return an empty list so callers can still run in test
    or restricted environments."""
    hits = []
    if yara is None or not RULES_DIR.exists():
        return hits
    for f in RULES_DIR.rglob('*.yar'):
        try:
            rules = yara.compile(str(f))
            for m in rules.match(data=data):
                hits.append(dict(rule=m.rule, tags=list(m.tags), severity=_sev(m.tags), type='YARA'))
        except Exception:
            continue
    return hits


def _sev(tags):
    t = [x.lower() for x in tags]
    if 'high' in t or 'critical' in t:
        return 'HIGH'
    if 'medium' in t:
        return 'MEDIUM'
    return 'LOW'
