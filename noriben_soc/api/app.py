from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse
from pathlib import Path
import shutil, uuid
from ..core.db import DB
from ..core.config import settings
from ..core.pipeline import analyze_sample
from ..core.queue_backend import LocalOrchestrator
from ..core.observability import Observability
from ..security.auth import ensure_default_users, login, require_role
from ..security.isolation import isolated_dir
from ..security.secrets import SecretsProvider

ROOT = Path.home() / 'NoribenSOCPlatform90'; ROOT.mkdir(parents=True, exist_ok=True)
DBH = DB(settings.db_url if settings.db_url.startswith('sqlite') else 'sqlite:///' + str(ROOT/'soc_platform_v9.db'))
ensure_default_users(DBH)
OBS = Observability(ROOT)
RULES = Path(__file__).resolve().parents[1] / 'rules'
SECRETS = SecretsProvider()

def handler(payload, trace_id):
    sample_path = Path(payload['path']); iso = isolated_dir(ROOT, payload['job_id']); result = analyze_sample(sample_path, RULES); result['meta']['trace_id']=trace_id; result['meta']['isolated_dir']=str(iso); DBH.upsert_analysis(result); OBS.inc('sessions_total'); OBS.log('INFO', f"session stored {result['session_id']}", trace_id); return {'session_id': result['session_id']}

ORCH = LocalOrchestrator(handler, OBS, size=2)
app = FastAPI(title='Noriben SOC Platform 9.0', version='9.0.0')

@app.post('/auth/login')
def auth_login(username: str, password: str):
    out = login(DBH, username, password)
    if not out: raise HTTPException(status_code=401, detail='bad credentials')
    return out

@app.get('/health')
def health(ctx=Depends(require_role(DBH,'tier1'))):
    return {'status':'ok','metrics':OBS.get_metrics(),'user':ctx['user'],'db_url':settings.db_url,'redis_url':settings.redis_url,'has_secret': bool(SECRETS.get('NORIBEN_SECRET',''))}

@app.get('/metrics')
def metrics():
    return Response(content=OBS.prometheus_text(), media_type='text/plain')

@app.get('/sessions')
def list_sessions(ctx=Depends(require_role(DBH,'tier1'))):
    return DBH.list_analysis()

@app.get('/sessions/{session_id}')
def get_session(session_id: str, ctx=Depends(require_role(DBH,'tier1'))):
    s = DBH.get_analysis(session_id)
    if not s: raise HTTPException(status_code=404, detail='not found')
    return s

@app.post('/sessions')
def create_session(path: str, ctx=Depends(require_role(DBH,'tier2'))):
    p = Path(path).expanduser().resolve()
    if not p.is_file(): raise HTTPException(status_code=400, detail='invalid file path')
    trace_id = OBS.trace_id(); job_id = str(uuid.uuid4()); ORCH.submit(job_id, {'path': str(p), 'job_id': job_id}, trace_id); OBS.log('INFO', f'queued {job_id}', trace_id); return {'job_id': job_id, 'trace_id': trace_id, 'status':'queued'}

@app.get('/jobs/{job_id}')
def get_job(job_id: str, ctx=Depends(require_role(DBH,'tier1'))):
    return ORCH.get(job_id)

@app.post('/upload')
def upload(file: UploadFile = File(...), ctx=Depends(require_role(DBH,'tier2'))):
    up = ROOT/'uploads'; up.mkdir(exist_ok=True); dest = up/file.filename
    with dest.open('wb') as f: shutil.copyfileobj(file.file, f)
    trace_id = OBS.trace_id(); job_id = str(uuid.uuid4()); ORCH.submit(job_id, {'path': str(dest), 'job_id': job_id}, trace_id); OBS.log('INFO', f'upload queued {job_id}', trace_id); return {'job_id': job_id, 'trace_id': trace_id, 'status':'queued'}

@app.get('/logs')
def logs(ctx=Depends(require_role(DBH,'admin'))):
    p = ROOT/'aggregated.log'
    return p.read_text(encoding='utf-8').splitlines()[-100:] if p.exists() else []

@app.get('/', response_class=HTMLResponse)
def dashboard():
    rows = ''.join(f"<tr><td>{s['session_id']}</td><td>{s['sample_name']}</td><td>{s['severity']}</td><td>{s['confidence']}</td><td>{s['status']}</td><td>{s['assignee'] or ''}</td></tr>" for s in DBH.list_analysis())
    return f'''<html><head><meta charset="utf-8"><style>body{{font-family:Arial;background:#0f172a;color:#e2e8f0;padding:20px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #334155;padding:8px}}</style></head><body><h1>Noriben SOC Platform 9.0</h1><p>Deployment foundation z DB/queue/metrics/auth.</p><table><thead><tr><th>Session</th><th>Sample</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Assignee</th></tr></thead><tbody>{rows}</tbody></table></body></html>'''
