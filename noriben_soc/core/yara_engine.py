from pathlib import Path

def try_import_yara():
    try:
        import yara
        return yara
    except Exception:
        return None

def run_yara(text, rules_dir):
    yara=try_import_yara(); ydir=Path(rules_dir)/'yara'
    if yara and ydir.exists():
        fps={p.stem:str(p) for p in sorted(ydir.glob('*.yar'))}
        if fps:
            compiled=yara.compile(filepaths=fps)
            return [m.rule for m in compiled.match(data=text.encode('utf-8', errors='ignore'))], 'yara-python'
    hits=[]; low=text.lower()
    for p in sorted(ydir.glob('*.yar')) if ydir.exists() else []:
        rt=p.read_text(encoding='utf-8', errors='ignore').lower()
        if any(tok in low for tok in ['powershell','lsass','wevtutil','download'] if tok in rt): hits.append(p.stem)
    return hits, 'fallback'
