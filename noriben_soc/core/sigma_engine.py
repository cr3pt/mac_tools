from pathlib import Path
import re

def parse_sigma_rule(path):
    text = Path(path).read_text(encoding='utf-8', errors='ignore')
    title = Path(path).stem; detections = {}; condition = 'selection'; in_detection=False; current=None
    for line in text.splitlines():
        st=line.strip()
        if st.lower().startswith('title:'): title=st.split(':',1)[1].strip()
        elif st.lower().startswith('detection:'): in_detection=True
        elif in_detection and st.lower().startswith('condition:'): condition=st.split(':',1)[1].strip()
        elif in_detection and re.match(r'^[A-Za-z0-9_]+:\s*$', st): current=st[:-1]; detections[current]=[]
        elif in_detection and current and ':' in st:
            _,val=st.split(':',1); detections[current].append(val.strip())
    return {'title':title,'detections':detections,'condition':condition}

def eval_selection(values, text):
    low=text.lower(); checks=[]
    for raw in values:
        v=raw.strip('"').strip("'")
        if not v: continue
        needle=v.replace('*','').lower()
        checks.append(needle in low)
    return any(checks)

def eval_condition(rule, text):
    res={name: eval_selection(vals, text) for name, vals in rule['detections'].items()}
    expr=rule['condition']
    for name,val in sorted(res.items(), key=lambda x: -len(x[0])):
        expr=re.sub(rf'\b{name}\b', str(val), expr)
    try: return bool(eval(expr, {'__builtins__': {}}, {})), res
    except Exception: return any(res.values()), res

def run_sigma_on_text(text, rules_dir):
    hits=[]; sdir=Path(rules_dir)/'sigma'
    for p in sorted(sdir.glob('*.yml')) if sdir.exists() else []:
        rule=parse_sigma_rule(p); ok,res=eval_condition(rule,text)
        if ok: hits.append({'title': rule['title'], 'matched': [k for k,v in res.items() if v], 'condition': rule['condition']})
    return hits
