from fastapi import APIRouter, Depends, HTTPException, Response
from ..config import settings
from .admin import admin_required
from ..admin_tasks import get_task
from .. import task_audit
import os
import pathlib

router = APIRouter()

@router.get('/run-setup/list')
async def list_tasks(user: str = Depends(admin_required)):
    # return audit rows plus log existence
    rows = task_audit.list_tasks(200)
    for r in rows:
        logp = pathlib.Path('logs/tasks') / f"{r['task_id']}.log"
        r['log_exists'] = logp.exists()
    return rows

@router.delete('/run-setup/logs/{task_id}')
async def delete_task(task_id: str, user: str = Depends(admin_required)):
    # delete log file and audit record
    logp = pathlib.Path('logs/tasks') / f"{task_id}.log"
    ok_file = False
    try:
        if logp.exists():
            logp.unlink()
            ok_file = True
    except Exception:
        ok_file = False
    ok_db = task_audit.delete_task(task_id)
    return {'ok_file': ok_file, 'ok_db': ok_db}


@router.get('/run-setup/export')
async def export_tasks(user: str = Depends(admin_required)):
    rows = task_audit.list_tasks(1000)
    # build CSV
    import io
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['task_id','script','initiator','start_time','end_time','status','returncode'])
    for r in rows:
        w.writerow([r.get('task_id'), r.get('script'), r.get('initiator'), r.get('start_time'), r.get('end_time'), r.get('status'), r.get('returncode')])
    from fastapi.responses import StreamingResponse
    buf.seek(0)
    return StreamingResponse(buf, media_type='text/csv', headers={'Content-Disposition': 'attachment; filename="tasks_audit.csv"'})
