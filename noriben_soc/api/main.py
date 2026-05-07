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
from .admin_extra import router as admin_extra_router
app.include_router(admin_router, prefix='/admin')
app.include_router(admin_extra_router, prefix='/admin')

# Optional metrics endpoint
try:
    from noriben_soc import metrics as metrics_mod
    if getattr(metrics_mod, 'PROMETHEUS_AVAILABLE', False) and getattr(metrics_mod, 'registry', None) is not None:
        @app.get('/metrics')
        async def metrics():
            from fastapi.responses import PlainTextResponse
            data = metrics_mod.registry.generate_latest()
            return PlainTextResponse(data, media_type='text/plain; version=0.0.4')
except Exception:
    pass


# background maintenance (prune old logs/audit)
try:
    from .. import maintenance
    @app.on_event('startup')
    async def _start_maintenance():
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(maintenance.prune_loop())
        except Exception:
            pass
except Exception:
    # maintenance optional
    pass

@app.get('/')
async def index():
    return FileResponse('browser_ui/index.html')


@app.post('/upload')
async def upload(file: UploadFile = File(...)):
    # increment metrics if available
    try:
        from .. import metrics
        if getattr(metrics, 'uploads', None) is not None:
            metrics.uploads.inc()
    except Exception:
        pass
    # ensure upload and quarantine dir exist
    upload_dir = Path(settings.UPLOAD_DIR)
    quarantine = Path(getattr(settings, 'QUARANTINE_DIR', 'quarantine'))
    upload_dir.mkdir(parents=True, exist_ok=True)
    quarantine.mkdir(parents=True, exist_ok=True)
    # size check
    content = await file.read()
    max_size = int(getattr(settings, 'MAX_UPLOAD_SIZE', 50 * 1024 * 1024))
    if len(content) > max_size:
        raise HTTPException(status_code=413, detail=f'File too large (max {max_size} bytes)')
    # optional MIME check (python-magic)
    mime = None
    try:
        import magic
        mime = magic.from_buffer(content, mime=True)
    except Exception:
        mime = None
    # write to quarantine first
    suffix = Path(file.filename).suffix or ''
    qpath = quarantine / (Path(file.filename).name)
    qpath.write_bytes(content)
    logger.info('Received upload %s -> quarantine %s mime=%s', file.filename, qpath, mime)
    # move to upload dir and queue for analysis
    dest = upload_dir / qpath.name
    qpath.replace(dest)
    # enqueue
    from ..tasks import run_analysis_task
    job = run_analysis_task.delay(str(dest), file.filename)
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
