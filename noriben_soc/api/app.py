from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Response, Header
from fastapi.responses import HTMLResponse
from pathlib import Path
import shutil, uuid
from celery.result import AsyncResult
from ..core.db import DB
from ..core.config import settings
from ..core.observability import Observability
from ..core.tasks import run_analysis
from ..security.auth import ensure_default_users, login, logout, require_role
from ..security.secrets import SecretsProvider

ROOT = Path.home() / 'NoribenSOCPlatform101'; ROOT.mkdir(parents=True, exist_ok=True)
DBH = DB(settings.db_url)
ensure_default_users(DBH)
OBS = Observability(ROOT)
SECRETS = SecretsProvider()

app = FastAPI(title='Noriben SOC Platform 10.1', version='10.1.0')

@app.post('/auth/login')
def auth_login(username: str, password: str):
    out = login(DBH, username, password)
    if not out: raise HTTPException(status_code=401, detail='bad credentials')
    return out

@app.post('/auth/logout')
def auth_logout(authorization: str = Header(default='')):
    if not authorization.startswith('Bearer '): raise HTTPException(status_code=401, detail='missing bearer token')
    logout(authorization.split(' ',1)[1])
    return {'ok': True}

@app.get('/health')
def health(ctx=Depends(require_role('tier1'))):
    return {'status':'ok','user':ctx['user'],'db_url':settings.db_url,'redis_url':settings.redis_url,'vault_backend':settings.secret_backend,'has_secret': bool(SECRETS.get('NORIBEN_SECRET',''))}

@app.get('/metrics')
def metrics():
    return Response(content=OBS.prometheus_text(), media_type='text/plain')

@app.post('/sessions')
def create_session(path: str, ctx=Depends(require_role('tier2'))):
    p = Path(path).expanduser().resolve()
    if not p.is_file(): raise HTTPException(status_code=400, detail='invalid file path')
    trace_id = OBS.trace_id(); job_id = str(uuid.uuid4())
    async_result = run_analysis.delay(str(p), job_id, trace_id)
    DBH.upsert_job(job_id, async_result.id, trace_id, 'queued')
    OBS.log('INFO', f'celery queued {job_id}', trace_id)
    return {'job_id': job_id, 'celery_id': async_result.id, 'trace_id': trace_id, 'status':'queued'}

@app.get('/jobs/{job_id}')
def get_job(job_id: str, ctx=Depends(require_role('tier1'))):
    j = DBH.get_job(job_id)
    if not j: raise HTTPException(status_code=404, detail='unknown job')
    result = AsyncResult(j['celery_id'])
    DBH.upsert_job(job_id, j['celery_id'], j['trace_id'], result.state)
    return {'job_id': job_id, 'celery_id': j['celery_id'], 'state': result.state, 'result': result.result if result.ready() else None, 'trace_id': j['trace_id']}

@app.post('/upload')
def upload(file: UploadFile = File(...), ctx=Depends(require_role('tier2'))):
    up = ROOT/'uploads'; up.mkdir(exist_ok=True); dest = up/file.filename
    with dest.open('wb') as f: shutil.copyfileobj(file.file, f)
    trace_id = OBS.trace_id(); job_id = str(uuid.uuid4())
    async_result = run_analysis.delay(str(dest), job_id, trace_id)
    DBH.upsert_job(job_id, async_result.id, trace_id, 'queued')
    OBS.log('INFO', f'celery upload queued {job_id}', trace_id)
    return {'job_id': job_id, 'celery_id': async_result.id, 'trace_id': trace_id, 'status':'queued'}

@app.get('/sessions')
def list_sessions(ctx=Depends(require_role('tier1'))):
    return DBH.list_analysis()

@app.get('/sessions/{session_id}')
def get_session(session_id: str, ctx=Depends(require_role('tier1'))):
    s = DBH.get_analysis(session_id)
    if not s: raise HTTPException(status_code=404, detail='not found')
    return s

@app.get('/logs')
def logs(ctx=Depends(require_role('admin'))):
    p = ROOT/'aggregated.log'
    return p.read_text(encoding='utf-8').splitlines()[-100:] if p.exists() else []

@app.get('/traces')
def traces(ctx=Depends(require_role('admin'))):
    p = ROOT/'traces.jsonl'
    return p.read_text(encoding='utf-8').splitlines()[-100:] if p.exists() else []

@app.get('/', response_class=HTMLResponse)
def dashboard():
    rows = ''.join(f"<tr><td>{s['session_id']}</td><td>{s['sample_name']}</td><td>{s['severity']}</td><td>{s['confidence']}</td><td>{s['status']}</td><td>{s['assignee'] or ''}</td></tr>" for s in DBH.list_analysis())
    return f'''<html><head><meta charset="utf-8"><style>body{{font-family:Arial;background:#0f172a;color:#e2e8f0;padding:20px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #334155;padding:8px}}</style></head><body><h1>Noriben SOC Platform 10.1</h1><p>Production closure foundation: durable jobs, JWT revocation, Celery retries.</p><table><thead><tr><th>Session</th><th>Sample</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Assignee</th></tr></thead><tbody>{rows}</tbody></table></body></html>'''
