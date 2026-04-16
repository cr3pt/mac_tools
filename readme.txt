Noriben SOC Platform 10.1

Production closure foundation:
- durable job tracking in DB
- Celery retries/backoff/jitter
- JWT bearer auth with logout/revocation
- PostgreSQL-first SQLAlchemy backend
- Redis/Celery production wiring
- metrics/logs/traces endpoints

Uruchomienie:
1. pip install -r requirements.txt
2. ustaw NORIBEN_DB_URL, NORIBEN_REDIS_URL, NORIBEN_JWT_SECRET
3. uruchom worker: celery -A noriben_soc.core.tasks worker -Q analysis --loglevel=info
4. uruchom API: PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload
