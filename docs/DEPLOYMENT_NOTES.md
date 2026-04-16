# Deployment Notes 9.0

Cel tej wersji to foundation pod wdrożenie:
- SQLAlchemy + configurable DB URL
- bcrypt-ready auth fallback
- metrics endpoint pod Prometheus
- local queue backend gotowy do zastąpienia przez Celery/Redis
- secret backend wrapper
- Alembic-ready structure

Kolejne ruchy produkcyjne:
- PostgreSQL jako obowiązkowy backend
- Alembic migrations
- Redis/RabbitMQ + Celery workers
- OpenTelemetry exporter
- Vault integration
