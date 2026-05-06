import os
from typing import Optional

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

    settings = Settings()
