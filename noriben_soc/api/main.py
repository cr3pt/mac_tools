from fastapi import FastAPI, UploadFile, File, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio, json, tempfile, os
from pathlib import Path
from ..core.pipeline import analyze_sample
from ..tasks import run_analysis_task
import asyncpg

app = FastAPI(title="Noriben SOC v6.4")
app.mount("/static", StaticFiles(directory="browser_ui"), name="static")

@app.get("/")
async def index():
    return FileResponse("browser_ui/index.html")

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        tmp.write(await file.read())
    job = run_analysis_task.delay(tmp.name, file.filename)
    return {"job_id": str(job.id), "filename": file.filename, "status": "queued"}

@app.get("/job/{job_id}")
async def job_status(job_id: str):
    from celery.result import AsyncResult
    r = AsyncResult(job_id)
    return {"status": r.status, "result": r.result if r.ready() else None}

@app.get("/sessions")
async def sessions(limit: int = 50):
    conn = await asyncpg.connect(os.getenv("DATABASE_URL"))
    rows = await conn.fetch("SELECT * FROM analysis_sessions ORDER BY created_at DESC LIMIT $1", limit)
    await conn.close()
    return [dict(r) for r in rows]

@app.get("/sessions/{sha256}")
async def session(sha256: str):
    conn = await asyncpg.connect(os.getenv("DATABASE_URL"))
    row  = await conn.fetchrow("SELECT result_json FROM analysis_sessions WHERE sha256=$1", sha256)
    await conn.close()
    return json.loads(row["result_json"]) if row else {}

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    while True:
        conn = await asyncpg.connect(os.getenv("DATABASE_URL"))
        rows = await conn.fetch("SELECT sha256,severity,filename,created_at FROM analysis_sessions ORDER BY created_at DESC LIMIT 20")
        await conn.close()
        await ws.send_text(json.dumps([dict(r) for r in rows], default=str))
        await asyncio.sleep(3)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "6.4"}