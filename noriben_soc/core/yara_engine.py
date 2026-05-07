try:
    import yara
except Exception:
    yara = None

from pathlib import Path

# Prefer repo-local rules directory but allow explicit shared mount
RULES_DIR = Path('rules/yara') if Path('rules/yara').exists() else Path('/shared/yara_rules')


def run_yara_scan(data: bytes) -> list:
    """Run YARA rules against given data. Uses compiled rules from rules_manager if available
    to avoid recompiling on every call. If python-yara is not installed or no rules exist,
    returns an empty list.
    """
    hits = []
    try:
        from .. import rules_manager
        compiled = rules_manager.get_compiled_yara()
        if compiled is None:
            # fallback: attempt single-file compile if yara available
            if yara is None:
                return hits
            # scan files directly
            rd = RULES_DIR
            if not rd.exists():
                return hits
            for f in rd.rglob('*.yar'):
                try:
                    rules = yara.compile(str(f))
                    for m in rules.match(data=data):
                        hits.append(dict(rule=m.rule, tags=list(m.tags), severity=_sev(m.tags), type='YARA'))
                except Exception:
                    continue
            return hits
        # compiled is a yara.Rules object (supports match)
        for m in compiled.match(data=data):
            hits.append(dict(rule=m.rule, tags=list(m.tags), severity=_sev(m.tags), type='YARA'))
        return hits
    except Exception:
        # last-resort fallback to previous behaviour
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