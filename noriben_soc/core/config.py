import os
class Settings:
    db_url = os.getenv('NORIBEN_DB_URL', 'postgresql://noriben:noriben@localhost:5432/noriben_soc')
    redis_url = os.getenv('NORIBEN_REDIS_URL', 'redis://localhost:6379/0')
    celery_broker_url = os.getenv('NORIBEN_CELERY_BROKER_URL', redis_url)
    celery_result_backend = os.getenv('NORIBEN_CELERY_RESULT_BACKEND', redis_url)
    jwt_secret = os.getenv('NORIBEN_JWT_SECRET', 'change-me')
    jwt_issuer = os.getenv('NORIBEN_JWT_ISSUER', 'noriben-soc-platform')
    secret_backend = os.getenv('NORIBEN_SECRET_BACKEND', 'env')
    vault_addr = os.getenv('NORIBEN_VAULT_ADDR', '')
    vault_token = os.getenv('NORIBEN_VAULT_TOKEN', '')
    telemetry_service_name = os.getenv('NORIBEN_TELEMETRY_SERVICE_NAME', 'noriben-soc-platform')
settings = Settings()
