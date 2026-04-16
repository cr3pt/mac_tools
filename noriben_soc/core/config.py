import os
class Settings:
    db_url = os.getenv("NORIBEN_DB_URL", "postgresql://noriben:noriben@localhost:5432/noriben_soc")
    redis_url = os.getenv("NORIBEN_REDIS_URL", "redis://localhost:6379/0")
    secret_backend = os.getenv("NORIBEN_SECRET_BACKEND", "env")
    vault_addr = os.getenv("NORIBEN_VAULT_ADDR", "")
    vault_token = os.getenv("NORIBEN_VAULT_TOKEN", "")
settings = Settings()
