import os
class Settings:
    db_url = os.getenv('NORIBEN_DB_URL', 'sqlite:///soc_platform_v9.db')
    redis_url = os.getenv('NORIBEN_REDIS_URL', 'redis://localhost:6379/0')
    secret_backend = os.getenv('NORIBEN_SECRET_BACKEND', 'env')
    jwt_secret = os.getenv('NORIBEN_JWT_SECRET', 'change-me')
    telemetry_service_name = os.getenv('NORIBEN_TELEMETRY_SERVICE_NAME', 'noriben-soc-platform')
settings = Settings()
