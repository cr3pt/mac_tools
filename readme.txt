Noriben SOC Platform 9.0

Wersja 9.0 zawiera foundation pod wdrożenie:
- konfigurowalna warstwa DB
- ORM models gotowe pod PostgreSQL
- auth z bcrypt-ready fallback
- queue backend gotowy do wymiany na Celery/Redis
- metrics endpoint pod Prometheus
- observability/log aggregation foundation
- secret backend wrapper i isolation layer

Uruchomienie developerskie:
1. pip install -r requirements.txt
2. PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload
3. POST /auth/login i używaj x-session-token
