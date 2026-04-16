from pathlib import Path

def try_import_yara():
    try:
        import yara
        return yara
    except Exception:
        return None

def run_yara_on_text(text, rules_dir):
    yara = try_import_yara()
    ydir = Path(rules_dir) / 'yara'
    if yara and ydir.exists():
        filepaths = {p.stem: str(p) for p in sorted(ydir.glob('*.yar'))}
        if filepaths:
            compiled = yara.compile(filepaths=filepaths)
            return [m.rule for m in compiled.match(data=text.encode('utf-8', errors='ignore'))], 'yara-python'
    hits = []
    low = text.lower()
    for p in sorted(ydir.glob('*.yar')) if ydir.exists() else []:
        rule_text = p.read_text(encoding='utf-8', errors='ignore').lower()
        if any(tok in low for tok in ['powershell','lsass','wevtutil','download','url'] if tok in rule_text): hits.append(p.stem)
    return hits, 'fallback'
