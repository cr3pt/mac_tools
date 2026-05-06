from fastapi import APIRouter, Request, Depends, HTTPException, WebSocket, WebSocketDisconnect, Response
from typing import Dict
from ..config import settings, save_env_file, update_settings, get_settings_dict
import subprocess, os, json
import pathlib
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import time
from ..admin_tasks import start_script, get_task, read_lines, task_status, cancel_task
import asyncio
import uuid
from ..admin_tokens import issue_token, validate_token, revoke_token

security = HTTPBasic()
router = APIRouter()


def admin_required(creds: HTTPBasicCredentials = Depends(security)):
    user = getattr(settings, 'ADMIN_USER', None) or os.getenv('ADMIN_USER')
    pwd = getattr(settings, 'ADMIN_PASS', None) or os.getenv('ADMIN_PASS')
    if not user or not pwd:
        raise HTTPException(status_code=500, detail='Admin credentials not set on server')
    is_user = secrets.compare_digest(creds.username, user)
    is_pass = secrets.compare_digest(creds.password, pwd)
    if not (is_user and is_pass):
        raise HTTPException(status_code=401, detail='Unauthorized', headers={'WWW-Authenticate': 'Basic'})
    return True


@router.get('/', dependencies=[Depends(admin_required)])
async def admin_ui():
    return pathlib.Path('browser_ui/admin.html').read_text()


@router.get('/config', dependencies=[Depends(admin_required)])
async def get_config():
    return get_settings_dict()


@router.post('/config', dependencies=[Depends(admin_required)])
async def post_config(payload: Dict[str, str]):
    mapping = {
        'NORIBEN_ENV':'NORIBEN_ENV',
        'DATABASE_URL':'DATABASE_URL',
        'CELERY_BROKER':'CELERY_BROKER',
        'LOG_LEVEL':'LOG_LEVEL',
        'LOG_JSON':'LOG_JSON',
        'UPLOAD_DIR':'UPLOAD_DIR',
        'VIRUSTOTAL_API_KEY':'VIRUSTOTAL_API_KEY',
        'OTX_API_KEY':'OTX_API_KEY'
    }
    updates = {}
    for k, v in payload.items():
        if k in mapping:
            updates[mapping[k]] = v
    save_env_file(updates)
    update_settings(updates)
    upload_dir = getattr(settings, 'UPLOAD_DIR', '/tmp/noriben_uploads')
    try:
        pathlib.Path(upload_dir).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return {'ok': True, 'saved': updates}


@router.post('/setup-db', dependencies=[Depends(admin_required)])
async def setup_db():
    out = {'steps': []}
    try:
        from urllib.parse import urlparse
        url = urlparse(getattr(settings, 'DATABASE_URL'))
        dbname = (url.path or '').lstrip('/') or 'noriben'
        user = url.username or 'noriben'
    except Exception:
        dbname = 'noriben'
        user = 'noriben'
    try:
        p = subprocess.run(['createdb', dbname], capture_output=True, text=True)
        out['steps'].append({'cmd': f'createdb {dbname}', 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    except FileNotFoundError:
        out['steps'].append({'cmd': 'createdb', 'error': 'command not found'})
    try:
        p = subprocess.run(['createuser', '--no-createdb', user], capture_output=True, text=True)
        out['steps'].append({'cmd': f'createuser --no-createdb {user}', 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    except FileNotFoundError:
        out['steps'].append({'cmd': 'createuser', 'error': 'command not found'})
    if any(s.get('rc', 1) != 0 for s in out['steps'] if 'rc' in s):
        out['suggestion'] = f"Manual SQL to run as postgres superuser:\nCREATE USER {user} WITH PASSWORD 'noriben123';\nCREATE DATABASE {dbname} OWNER {user};"
    return out


@router.post('/run-setup', dependencies=[Depends(admin_required)])
async def run_setup():
    script = os.path.join(os.getcwd(), 'scripts', 'setup_env.sh')
    if not os.path.exists(script):
        return {'ok': False, 'error': 'script not found'}
    task_id = await start_script(script)
    return {'ok': True, 'task_id': task_id}


@router.get('/run-setup/status/{task_id}', dependencies=[Depends(admin_required)])
async def run_setup_status(task_id: str):
    return task_status(task_id)


@router.post('/token', dependencies=[Depends(admin_required)])
async def issue_token():
    token = issue_token()
    return {'token': token}


@router.post('/run-setup/cancel/{task_id}', dependencies=[Depends(admin_required)])
async def cancel_run(task_id: str):
    ok = cancel_task(task_id)
    return {'ok': ok}


@router.get('/run-setup/logs/{task_id}', dependencies=[Depends(admin_required)])
async def get_log(task_id: str):
    task = get_task(task_id)
    if not task:
        return Response(status_code=404, content='Not found')
    log_file = task.get('log_file')
    if not log_file or not os.path.exists(log_file):
        return Response(status_code=404, content='Log not found')
    from fastapi.responses import FileResponse
    return FileResponse(log_file, media_type='text/plain', filename=f"{task_id}.log")


@router.websocket('/run-setup/ws/{task_id}')
async def ws_logs(ws: WebSocket, task_id: str):
    # token auth via query param
    query = ws.scope.get('query_string', b'').decode()
    params = dict(item.split('=') for item in query.split('&') if '=' in item) if query else {}
    token = params.get('token')
    if not token or not validate_token(token):
        await ws.close(code=1008)
        return
    await ws.accept()
    task = get_task(task_id)
    if not task:
        await ws.send_text('Task not found')
        await ws.close()
        return
    try:
        async for line in read_lines(task_id):
            try:
                await ws.send_text(line)
            except Exception:
                break
    except WebSocketDisconnect:
        return
    await ws.close()


