from pydantic import BaseSettings
from typing import Optional

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
