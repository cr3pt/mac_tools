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


@router.get('/run-setup/prune/status')
async def prune_status(user: str = Depends(admin_required)):
    from .. import maintenance
    st = maintenance.get_prune_status()
    return {'ok': True, 'status': st}


@router.post('/settings/retention')
async def set_retention(payload: dict, user: str = Depends(admin_required)):
    """Set LOG_RETENTION_DAYS and AUDIT_RETENTION_DAYS via admin UI and persist to .env."""
    from ..config import save_env_file, update_settings, settings as cfg
    try:
        logs = int(payload.get('LOG_RETENTION_DAYS', payload.get('logs', getattr(cfg, 'LOG_RETENTION_DAYS', 30))))
        audit = int(payload.get('AUDIT_RETENTION_DAYS', payload.get('audit', getattr(cfg, 'AUDIT_RETENTION_DAYS', 90))))
    except Exception:
        raise HTTPException(status_code=400, detail='invalid values')
    save_env_file({'LOG_RETENTION_DAYS': logs, 'AUDIT_RETENTION_DAYS': audit})
    update_settings({'LOG_RETENTION_DAYS': logs, 'AUDIT_RETENTION_DAYS': audit})
    return {'ok': True, 'LOG_RETENTION_DAYS': logs, 'AUDIT_RETENTION_DAYS': audit}


@router.get('/settings')
async def get_settings(user: str = Depends(admin_required)):
    from ..config import get_settings_dict
    return get_settings_dict()


@router.get('/rules/list')
async def list_rules(user: str = Depends(admin_required)):
    import pathlib
    base = pathlib.Path('rules')
    out = {'yara': [], 'sigma': []}
    for t in ('yara','sigma'):
        p = base / t
        p.mkdir(parents=True, exist_ok=True)
        for f in sorted(p.iterdir()):
            if f.is_file():
                out[t].append({'name': f.name, 'size': f.stat().st_size})
    return out


@router.post('/rules/yara/upload')
async def upload_yara(file: 'UploadFile' , user: str = Depends(admin_required)):
    from fastapi import UploadFile, File
    import pathlib
    import shutil
    p = pathlib.Path('rules/yara')
    p.mkdir(parents=True, exist_ok=True)
    name = pathlib.Path((getattr(file, 'filename', '') or '')).name or f'yara_{uuid.uuid4().hex}.yara'
    dest = p / name
    with open(dest, 'wb') as wf:
        shutil.copyfileobj(file.file, wf)
    # validate yara syntax if possible
    valid = False
    try:
        import yara
        yara.compile(str(dest))
        valid = True
    except Exception:
        valid = False
    # write metadata
    meta = {'filename': dest.name, 'valid': valid}
    try:
        import json
        with open(str(dest)+'.meta','w',encoding='utf-8') as mf:
            mf.write(json.dumps(meta))
    except Exception:
        pass
    # reload rules
    try:
        from .. import rules_manager
        rules_manager.reload_rules()
    except Exception:
        pass
    return {'ok': True, 'path': str(dest), 'valid': valid}


@router.post('/rules/yara/from_url')
async def yara_from_url(payload: dict, user: str = Depends(admin_required)):
    url = (payload or {}).get('url')
    if not url:
        raise HTTPException(status_code=400, detail='missing url')
    import pathlib, uuid, urllib.request, urllib.parse
    p = pathlib.Path('rules/yara')
    p.mkdir(parents=True, exist_ok=True)
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        data = resp.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'fetch failed: {e}')
    name = pathlib.Path(urllib.parse.urlparse(url).path).name or f'yara_{uuid.uuid4().hex}.yara'
    dest = p / name
    with open(dest, 'wb') as wf:
        wf.write(data)
    # try reload rules manager if available
    try:
        from .. import rules_manager
        rules_manager.reload_rules()
    except Exception:
        pass
    return {'ok': True, 'path': str(dest)}


@router.post('/rules/sigma/upload')
async def upload_sigma(file: 'UploadFile' , user: str = Depends(admin_required)):
    from fastapi import UploadFile, File
    import pathlib
    import shutil
    p = pathlib.Path('rules/sigma')
    p.mkdir(parents=True, exist_ok=True)
    name = pathlib.Path((getattr(file, 'filename', '') or '')).name or f'sigma_{uuid.uuid4().hex}.yml'
    dest = p / name
    with open(dest, 'wb') as wf:
        shutil.copyfileobj(file.file, wf)
    # validate YAML if possible
    valid = False
    try:
        import yaml
        with open(dest, 'r', encoding='utf-8') as rf:
            yaml.safe_load(rf)
        valid = True
    except Exception:
        valid = False
    meta = {'filename': dest.name, 'valid': valid}
    try:
        import json
        with open(str(dest)+'.meta','w',encoding='utf-8') as mf:
            mf.write(json.dumps(meta))
    except Exception:
        pass
    try:
        from .. import rules_manager
        rules_manager.reload_rules()
    except Exception:
        pass
    return {'ok': True, 'path': str(dest), 'valid': valid}


@router.post('/rules/sigma/from_url')
async def sigma_from_url(payload: dict, user: str = Depends(admin_required)):
    url = (payload or {}).get('url')
    if not url:
        raise HTTPException(status_code=400, detail='missing url')
    import pathlib, uuid, urllib.request, urllib.parse
    p = pathlib.Path('rules/sigma')
    p.mkdir(parents=True, exist_ok=True)
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        data = resp.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'fetch failed: {e}')
    name = pathlib.Path(urllib.parse.urlparse(url).path).name or f'sigma_{uuid.uuid4().hex}.yml'
    dest = p / name
    with open(dest, 'wb') as wf:
        wf.write(data)
    try:
        from .. import rules_manager
        rules_manager.reload_rules()
    except Exception:
        pass
    return {'ok': True, 'path': str(dest)}


@router.get('/rules/download/{rtype}/{name}')
async def download_rule(rtype: str, name: str, user: str = Depends(admin_required)):
    import pathlib
    from fastapi.responses import FileResponse
    base = pathlib.Path('rules')
    if rtype not in ('yara','sigma'):
        raise HTTPException(status_code=400, detail='invalid type')
    p = base / rtype / name
    if not p.exists():
        raise HTTPException(status_code=404, detail='not found')
    return FileResponse(str(p), media_type='application/octet-stream', filename=name)


@router.delete('/rules/{rtype}/{name}')
async def delete_rule(rtype: str, name: str, user: str = Depends(admin_required)):
    import pathlib
    base = pathlib.Path('rules')
    if rtype not in ('yara','sigma'):
        raise HTTPException(status_code=400, detail='invalid type')
    p = base / rtype / name
    if not p.exists():
        raise HTTPException(status_code=404, detail='not found')
    try:
        p.unlink()
    except Exception:
        raise HTTPException(status_code=500, detail='delete failed')
    # attempt reload
    try:
        from .. import rules_manager
        rules_manager.reload_rules()
    except Exception:
        pass
    return {'ok': True}


@router.post('/rules/reload')
async def reload_rules(user: str = Depends(admin_required)):
    try:
        from .. import rules_manager
        res = rules_manager.reload_rules()
        # metrics
        try:
            from .. import metrics
            if getattr(metrics, 'rules_loaded', None) is not None:
                metrics.rules_loaded.inc()
        except Exception:
            pass
        return {'ok': True, 'result': res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
