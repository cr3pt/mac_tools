from fastapi import APIRouter, Request
from typing import Dict
from ..config import settings, save_env_file, update_settings, get_settings_dict
import subprocess, os, json
import pathlib

router = APIRouter()

@router.get('/config')
async def get_config():
    return get_settings_dict()

@router.post('/config')
async def post_config(payload: Dict[str, str]):
    # Map common names to env keys
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
    # persist to .env
    save_env_file(updates)
    # apply in-memory
    update_settings(updates)
    # ensure upload dir exists
    upload_dir = getattr(settings, 'UPLOAD_DIR', '/tmp/noriben_uploads')
    try:
        pathlib.Path(upload_dir).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return {'ok': True, 'saved': updates}

@router.post('/setup-db')
async def setup_db():
    """Best-effort attempt to create Postgres role and DB using system tools."""
    out = {'steps': []}
    # parse DATABASE_URL
    try:
        from urllib.parse import urlparse
        url = urlparse(getattr(settings, 'DATABASE_URL'))
        dbname = (url.path or '').lstrip('/') or 'noriben'
        user = url.username or 'noriben'
    except Exception:
        dbname = 'noriben'
        user = 'noriben'
    # try createdb
    try:
        p = subprocess.run(['createdb', dbname], capture_output=True, text=True)
        out['steps'].append({'cmd': f'createdb {dbname}', 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    except FileNotFoundError:
        out['steps'].append({'cmd': 'createdb', 'error': 'command not found'})
    # try createuser (non-interactive fallback)
    try:
        p = subprocess.run(['createuser', '--no-createdb', user], capture_output=True, text=True)
        out['steps'].append({'cmd': f'createuser --no-createdb {user}', 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    except FileNotFoundError:
        out['steps'].append({'cmd': 'createuser', 'error': 'command not found'})
    # Return suggested SQL if steps failed
    if any(s.get('rc', 1) != 0 for s in out['steps'] if 'rc' in s):
        out['suggestion'] = f"Manual SQL to run as postgres superuser:\nCREATE USER {user} WITH PASSWORD 'noriben123';\nCREATE DATABASE {dbname} OWNER {user};"
    return out

@router.post('/run-setup')
async def run_setup():
    script = os.path.join(os.getcwd(), 'scripts', 'setup_env.sh')
    if not os.path.exists(script):
        return {'ok': False, 'error': 'script not found'}
    try:
        p = subprocess.run([script], capture_output=True, text=True, timeout=900)
        return {'ok': True, 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
