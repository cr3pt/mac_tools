# Deployment Notes 10.1

Domknięcia względem 10.0:
- durable job table w DB
- Celery retry/backoff/jitter config
- logout i prosty JWT revocation
- lepszy status tracking z AsyncResult + DB
- uporządkowany production closure scaffold

Do pełnego zamknięcia enterprise nadal potrzeba m.in. gotowych Alembic revisions, pełnego Vault clienta i bogatszego SIGMA engine.
