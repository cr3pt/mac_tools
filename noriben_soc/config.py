import os
from typing import Optional, Dict, Any

try:
    from pydantic import BaseSettings
    class Settings(BaseSettings):
        NORIBEN_ENV: str = 'development'
        DATABASE_URL: str = 'postgresql://noriben:noriben123@localhost/noriben'
        CELERY_BROKER: str = 'redis://localhost:6379/0'
        LOG_LEVEL: str = 'INFO'
        LOG_JSON: bool = False
        UPLOAD_DIR: str = '/tmp/noriben_uploads'
        VIRUSTOTAL_API_KEY: Optional[str] = None
        OTX_API_KEY: Optional[str] = None
        REDIS_URL: Optional[str] = None

        class Config:
            env_file = '.env'

    settings = Settings()
except Exception:
    # Fallback minimal settings if pydantic is not available
    class Settings:
        NORIBEN_ENV = os.getenv('NORIBEN_ENV', 'development')
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://noriben:noriben123@localhost/noriben')
        CELERY_BROKER = os.getenv('CELERY_BROKER', 'redis://localhost:6379/0')
        LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        LOG_JSON = os.getenv('LOG_JSON', 'False').lower() in ('1','true','yes')
        UPLOAD_DIR = os.getenv('UPLOAD_DIR', '/tmp/noriben_uploads')
        VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
        OTX_API_KEY = os.getenv('OTX_API_KEY')
        REDIS_URL = os.getenv('REDIS_URL')

    settings = Settings()


def _read_env_file(path: str = '.env') -> Dict[str, str]:
    env = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if '=' in ln:
                    k, v = ln.split('=', 1)
                    env[k.strip()] = v.strip().strip('"\'')
    except FileNotFoundError:
        pass
    return env


def save_env_file(updates: Dict[str, Any], path: str = '.env') -> None:
    """Merge existing .env with updates and write back to disk."""
    env = _read_env_file(path)
    for k, v in updates.items():
        env[k] = str(v) if v is not None else ''
    # write file
    lines = [f"{k}={env[k]}" for k in sorted(env.keys())]
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def update_settings(updates: Dict[str, Any]) -> None:
    """Apply updates to os.environ and the in-memory settings object."""
    for k, v in updates.items():
        os.environ[k] = str(v) if v is not None else ''
        # try to set attribute on settings object
        try:
            setattr(settings, k, v)
        except Exception:
            try:
                # fallback for pydantic: use __dict__ update
                if hasattr(settings, '__dict__'):
                    settings.__dict__[k] = v
            except Exception:
                pass


def get_settings_dict() -> Dict[str, Any]:
    """Return a serializable dict of current settings."""
    keys = ['NORIBEN_ENV','DATABASE_URL','CELERY_BROKER','LOG_LEVEL','LOG_JSON','UPLOAD_DIR','VIRUSTOTAL_API_KEY','OTX_API_KEY']
    out = {}
    for k in keys:
        out[k] = getattr(settings, k, os.getenv(k))
    return out
