
# Noriben SOC Platform 10.1 Complete — Instrukcja użytkowania

## 🎯 **Co to jest**
Platforma SOC do automatycznej analizy próbek malware z:
- **YARA/SIGMA rules** detection
- **MITRE ATT&CK mapping** 
- **PostgreSQL + Alembic** trwałe storage
- **Celery/Redis** distributed processing
- **Vault integration** secrets management
- **JWT RBAC** tier1/tier2/admin

## 🚀 **Szybki start (5 minut)**

### 1. Przygotowanie środowiska
```bash
# Pobierz i rozpakuj
unzip noriben_soc_platform_v10_1_complete.zip
cd noriben_soc_platform_v10_1_complete

# Zainstaluj zależności
pip install -r requirements.txt
```

### 2. PostgreSQL + migracje
```bash
# Uruchom PostgreSQL (docker)
docker run -d --name noriben_pg \
  -e POSTGRES_DB=noriben_soc \
  -e POSTGRES_USER=noriben \
  -e POSTGRES_PASSWORD=noriben \
  -p 5432:5432 \
  postgres:15-alpine

# Migracje Alembic  
alembic upgrade head
```

### 3. Redis + Celery
```bash
# Redis (docker)
docker run -d --name noriben_redis -p 6379:6379 redis:7-alpine

# Celery worker (terminal 1)
celery -A noriben_soc.core.tasks worker -Q analysis --loglevel=info
```

### 4. API server
```bash
# Terminal 2
PYTHONPATH=. uvicorn noriben_soc.api.app:app --host 0.0.0.0 --port 8000 --reload
```

## 🔐 **Uwierzytelnienie**

### Logowanie
```bash
curl -X POST "http://localhost:8000/auth/login?username=tier1&password=tier1pass"
```
**Odpowiedź**:
```json
{"token": "eyJ...", "username": "tier1", "role": "tier1"}
```

### Healthcheck
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:8000/health
```

### Logout
```bash
curl -X POST -H "Authorization: Bearer eyJ..." http://localhost:8000/auth/logout
```

**Role**:
- `tier1` → read-only (`/sessions`, `/jobs/{id}`)
- `tier2` → upload + sessions (`/upload`, `/sessions` POST)  
- `admin` → logs/traces (`/logs`, `/traces`)

## 📤 **Analiza próbek**

### 1. Upload pliku
```bash
curl -X POST -H "Authorization: Bearer eyJ..." \
  -F "file=@suspicious.exe" \
  http://localhost:8000/upload
```
**Odpowiedź**:
```json
{"job_id": "uuid", "celery_id": "celery@...", "trace_id": "trace", "status": "queued"}
```

### 2. Monitorowanie joba
```bash
curl -H "Authorization: Bearer eyJ..." \
  "http://localhost:8000/jobs/{job_id}"
```

### 3. Lista sesji
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:8000/sessions
```

### 4. Szczegóły sesji
```bash
curl -H "Authorization: Bearer eyJ..." \
  "http://localhost:8000/sessions/{session_id}"
```

## 🔍 **Wyniki analizy**

**Pełny payload** zawiera:
```
- sha256 hash
- severity/confidence scores  
- MITRE ATT&CK tactics (T1059, T1003...)
- YARA hits (powershell_loader, lsass...)
- SIGMA alerts (PowerShell exec, wevtutil...)
- IOCs (IPs, URLs, paths, registry)
- Parsed EVTX events
```

## 🗄️ **Vault integration (opcjonalne)**

```bash
# Vault dev server
docker run -d --name vault -p 8200:8200 vault

# W Vault UI (localhost:8200) → Secrets → noriben → Create
vault kv put noriben NORIBEN_SECRET=supersecret NORIBEN_JWT_SECRET=prod-jwt-key

# Environment
export NORIBEN_SECRET_BACKEND=vault
export NORIBEN_VAULT_ADDR=http://localhost:8200
export NORIBEN_VAULT_TOKEN=$(vault print token)

# Restart API → /health pokaże has_secret: true
```

## 📊 **Monitoring**

```
Prometheus scrape: http://localhost:8000/metrics
Grafana logs: http://localhost:8000/logs  
Grafana traces: http://localhost:8000/traces  
```

## 🛠️ **Development commands**

```bash
# Lint
make lint

# Tests
make test

# Production deploy
make migrate && make run-worker & make run-api
```

## 📁 **Struktura plików**

```
noriben_soc_platform_v10_1_complete/
├── alembic/                 # Migracje
│   ├── env.py              # Alembic env
│   └── versions/
│       └── 0001_create_core_tables.py
├── noriben_soc/
│   ├── core/
│   │   ├── sigma_engine.py # SigmaRule class
│   │   └── models.py       # SQLAlchemy ORM
│   ├── security/
│   │   └── secrets.py      # hvac Vault client
│   └── api/app.py          # FastAPI endpoints
├── requirements.txt
└── README.md
```

## 🚨 **Przykładowe użycie**

```bash
# 1. Login tier2
TOKEN=$(curl -s -X POST "http://localhost:8000/auth/login?username=tier2&password=tier2pass" | jq -r .token)

# 2. Upload złośliwa próbka
JOB_ID=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -F "file=@powershell_malware.exe" http://localhost:8000/upload | jq -r .job_id)

# 3. Czekaj na wynik
watch "curl -s -H \"Authorization: Bearer $TOKEN\" http://localhost:8000/jobs/$JOB_ID | jq"

# 4. Wynik sesji
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions/$(curl -s http://localhost:8000/sessions | jq -r '.[0].session_id')" | jq .
```

## 🎉 **Gotowe!**

Platforma jest **production-ready** z pełnym stackiem SOC:
- **Alembic** ✅ migracje
- **Vault hvac** ✅ secrets  
- **SIGMA** ✅ rules engine
- **Celery** ✅ distributed tasks
- **PostgreSQL** ✅ durable storage

**Następne kroki**: Grafana dashboard, SigmaHQ sync, MITRE navigator.
