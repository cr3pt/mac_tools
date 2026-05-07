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


@router.post('/run-setup/prune')
async def prune_now(user: str = Depends(admin_required), days: int = None):
    """Trigger immediate pruning of logs and audit records. If `days` provided, use it for both logs and audit."""
    from .. import maintenance
    from ..config import settings as cfg
    d_logs = int(days) if days is not None else int(getattr(cfg, 'LOG_RETENTION_DAYS', 30))
    d_audit = int(days) if days is not None else int(getattr(cfg, 'AUDIT_RETENTION_DAYS', 90))
    removed_logs = maintenance.prune_logs_older_than(d_logs)
    removed_db = maintenance.prune_audit_older_than(d_audit)
    return {'ok': True, 'removed_logs': removed_logs, 'removed_db': removed_db}
