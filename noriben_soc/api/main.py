from fastapi import FastAPI, UploadFile, File, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio, json, os
from pathlib import Path
from ..tasks import run_analysis_task
import asyncpg
from ..config import settings
import tempfile
import logging

logger = logging.getLogger(__name__)

app = FastAPI(title='Noriben SOC v6.8')
app.mount('/static', StaticFiles(directory='browser_ui'), name='static')
from .admin import router as admin_router
app.include_router(admin_router, prefix='/admin')

@app.get('/')
async def index():
    return FileResponse('browser_ui/index.html')


@app.post('/upload')
async def upload(file: UploadFile = File(...)):
    # ensure upload dir exists
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(file.filename).suffix or ''
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=str(upload_dir), suffix=suffix)
    try:
        tmp.write(await file.read())
        tmp.flush()
    finally:
        tmp.close()
    logger.info('Received upload %s -> %s', file.filename, tmp.name)
    job = run_analysis_task.delay(tmp.name, file.filename)
    return {'job_id': str(job.id), 'filename': file.filename, 'status': 'queued'}


@app.get('/job/{job_id}')
async def job_status(job_id: str):
    from celery.result import AsyncResult
    r = AsyncResult(job_id)
    return {'status': r.status, 'result': r.result if r.ready() else None}


@app.get('/sessions')
async def sessions(limit: int = 50):
    conn = await asyncpg.connect(settings.DATABASE_URL)
    rows = await conn.fetch('SELECT * FROM analysis_sessions ORDER BY created_at DESC LIMIT $1', limit)
    await conn.close()
    return [dict(r) for r in rows]


@app.get('/sessions/{sha256}')
async def session(sha256: str):
    conn = await asyncpg.connect(settings.DATABASE_URL)
    row = await conn.fetchrow('SELECT result_json FROM analysis_sessions WHERE sha256=$1', sha256)
    await conn.close()
    return json.loads(row['result_json']) if row else {}


@app.websocket('/ws')
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    while True:
        try:
            conn = await asyncpg.connect(settings.DATABASE_URL)
            rows = await conn.fetch(
                'SELECT sha256,severity,filename,created_at FROM analysis_sessions '
                'ORDER BY created_at DESC LIMIT 20')
            await conn.close()
            await ws.send_text(json.dumps([dict(r) for r in rows], default=str))
        except Exception:
            pass
        await asyncio.sleep(3)


@app.get('/health')
async def health():
    return {'status': 'ok', 'version': '6.8', 'env': settings.NORIBEN_ENV}
