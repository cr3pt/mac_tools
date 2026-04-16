from pathlib import Path
import re

def parse_sigma_rule(path):
    text = Path(path).read_text(encoding='utf-8', errors='ignore')
    title = Path(path).stem
    tokens = []
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith('title:'): title = s.split(':',1)[1].strip()
        tokens.extend(re.findall(r'[A-Za-z0-9_.\\/-]{4,}', s))
    tokens = [x for x in dict.fromkeys(tokens) if x.lower() not in {'title','detection','condition','selection'}]
    return {'title': title, 'tokens': tokens[:25]}

def run_sigma_on_text(text, rules_dir):
    hits = []
    low = text.lower()
    sdir = Path(rules_dir) / 'sigma'
    for p in sorted(sdir.glob('*.yml')) if sdir.exists() else []:
        rule = parse_sigma_rule(p)
        matched = [t for t in rule['tokens'] if t.lower() in low]
        if matched:
            hits.append({'title': rule['title'], 'matches': matched[:5]})
    return hits
