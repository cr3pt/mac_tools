# Noriben SOC Platform 10.1 Complete

Production-ready foundation z:
- **Alembic** scaffold z pełnymi rewizjami (0001_create_core_tables.py)
- **hvac Vault client** integration w secrets.py
- **Bogatszy SIGMA engine** z klasą SigmaRule i pełniejszą semantyką
- Celery z retry/backoff
- durable job tracking w DB
- JWT bearer auth z revokacją

## Uruchomienie
1. `pip install -r requirements.txt`
2. `alembic upgrade head`
3. `celery -A noriben_soc.core.tasks worker -Q analysis --loglevel=info`
4. `PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload`

## Vault setup
```
export NORIBEN_SECRET_BACKEND=vault
export NORIBEN_VAULT_ADDR=http://vault:8200
export NORIBEN_VAULT_TOKEN=hvac-...
```
