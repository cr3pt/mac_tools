from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
import shutil, json
from ..core.store import Store
from ..core.pipeline import analyze_file

ROOT = Path.home() / 'NoribenSOC'
RULES = Path(__file__).resolve().parents[1] / 'rules'
STORE = Store(ROOT)
app = FastAPI(title='Noriben SOC Starter', version='7.1.0')

@app.get('/health')
def health():
    return {'status':'ok'}

@app.get('/sessions')
def list_sessions():
    return STORE.list_sessions()

@app.get('/sessions/{session_id}')
def get_session(session_id: str):
    try: return STORE.load_session(session_id).to_dict()
    except Exception as e: raise HTTPException(status_code=404, detail=str(e))

@app.get('/sessions/{session_id}/events')
def get_events(session_id: str):
    try: return [e.to_dict() for e in STORE.load_session(session_id).events]
    except Exception as e: raise HTTPException(status_code=404, detail=str(e))

@app.get('/sessions/{session_id}/iocs')
def get_iocs(session_id: str):
    try: return STORE.load_session(session_id).iocs
    except Exception as e: raise HTTPException(status_code=404, detail=str(e))

@app.post('/sessions')
def create_session_from_path(path: str):
    p = Path(path).expanduser().resolve()
    if not p.is_file(): raise HTTPException(status_code=400, detail='invalid file path')
    sess = analyze_file(p, RULES)
    STORE.save_session(sess)
    return {'session_id': sess.session_id, 'severity': sess.severity, 'confidence': sess.confidence}

@app.post('/upload')
def upload_sample(file: UploadFile = File(...)):
    up_dir = ROOT / 'uploads'; up_dir.mkdir(parents=True, exist_ok=True)
    dest = up_dir / file.filename
    with dest.open('wb') as f: shutil.copyfileobj(file.file, f)
    sess = analyze_file(dest, RULES)
    STORE.save_session(sess)
    return {'session_id': sess.session_id, 'severity': sess.severity, 'confidence': sess.confidence}

@app.get('/', response_class=HTMLResponse)
def dashboard():
    sessions = STORE.list_sessions()
    rows = ''.join(f"<tr><td><a href='/sessions/{s['session_id']}' target='_blank'>{s['session_id']}</a></td><td>{s['sample_name']}</td><td>{s['severity']}</td><td>{s['confidence']}</td><td>{s['static_score']}</td><td>{s['dynamic_score']}</td></tr>" for s in sessions)
    return f'''<html><head><meta charset="utf-8"><style>body{{font-family:Arial;background:#0f172a;color:#e2e8f0;padding:20px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #334155;padding:8px}}input,button{{padding:8px;margin:4px}}</style><script>async function submitPath(){{const p=document.getElementById('path').value;const r=await fetch('/sessions?path='+encodeURIComponent(p),{{method:'POST'}});const j=await r.json();location.reload();}}</script></head><body><h1>Noriben SOC Starter</h1><p>Utwórz sesję z lokalnej ścieżki lub przez /upload.</p><input id='path' placeholder='/path/to/sample.txt' size='60'><button onclick='submitPath()'>Analyze path</button><table><thead><tr><th>Session</th><th>Sample</th><th>Severity</th><th>Confidence</th><th>Static</th><th>Dynamic</th></tr></thead><tbody>{rows}</tbody></table></body></html>'''
