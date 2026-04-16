
# 🚀 Noriben SOC Platform — Kompletna instrukcja (od 0 do production)

**Czas setupu: 10 minut** | **Browser UI included**

## 📦 **1. Pobierz wszystkie komponenty**

```
# Core platform (Alembic, Vault, SIGMA)
unzip noriben_soc_platform_v10_1_complete.zip

# Enterprise addons (Grafana, SigmaHQ, MITRE)
unzip noriben_soc_v11_enterprise_addons.zip  

# Browser UI (index.html)
unzip noriben_soc_browser_ui_complete.zip
```

## 🐳 **2. Docker stack (1 command)**

**Utwórz `docker-compose.yml`** (z docker-compose.prod.yml):
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: noriben_soc
      POSTGRES_USER: noriben  
      POSTGRES_PASSWORD: noriben
    ports: ['5432:5432']
  redis:
    image: redis:7-alpine
    ports: ['6379:6379']
  api:
    build: .
    ports: ['8000:8000']
    volumes:
      - .:/app  # Dla index.html
    depends_on: [postgres, redis]
```

**Uruchom**:
```bash
docker-compose up -d postgres redis
pip install -r requirements.txt
alembic upgrade head
docker-compose up -d api
```

## 🎨 **3. Browser UI (skopiuj 1 plik)**

```bash
cp index.html .
# Otwórz http://localhost:8000
```

## 📥 **4. Sync SigmaHQ rules**

```bash
chmod +x sync_sigmahq.py
./sync_sigmahq.py
# Pobiera: powershell.yml, wevtutil.yml, schtasks.yml
```

## 🔐 **5. Login i pierwsze użycie**

**Przeglądarka** → `localhost:8000`:
```
1. Login: tier2 / tier2pass
2. Drag suspicious.exe → "Job queued"
3. Watch live: Jobs table (5s refresh)  
4. Sessions table: HIGH severity, T1059 PowerShell
```

## 🗄️ **6. Vault (opcjonalne, production secrets)**

```bash
docker run -d -p 8200:8200 vault
vault kv put noriben NORIBEN_SECRET=prod-secret
export NORIBEN_SECRET_BACKEND=vault
export NORIBEN_VAULT_ADDR=http://localhost:8200  
export NORIBEN_VAULT_TOKEN=$(vault print token)
docker-compose restart api
# /health → has_secret: true ✓
```

## 📊 **7. Grafana Dashboard**

**localhost:3000** → Import `grafana-dashboard.json`:
```
docker run -d -p 3000:3000 grafana/grafana
# Prometheus datasource: http://localhost:8000/metrics
```
**Pokaże**: Piechart severity, jobs queue, recent logs.

## 🔄 **8. Auto-sync i monitoring**

**Dodaj do crontab**:
```bash
# Co 6h sync SigmaHQ
0 */6 * * * cd /path/to/noriben && ./sync_sigmahq.py

# Restart worker jeśli potrzeba  
* * * * * docker-compose restart celery-worker
```

## 🎯 **9. End-to-end test (skopiuj)**

```bash
# Terminal 1: Stack
docker-compose up -d

# Terminal 2: Sync  
./sync_sigmahq.py

# Browser: localhost:8000
# 1. tier2/tier2pass → Login
# 2. Upload malware.exe  
# 3. Watch Jobs → Sessions → HIGH severity
# 4. Grafana localhost:3000 → Metrics piechart
```

## 📋 **Struktura po setupie**

```
noriben_soc_platform/
├── index.html                 # 🎨 Browser UI
├── docker-compose.yml         # 🐳 Production stack
├── requirements.txt           # 📦 Dependencies
├── alembic/versions/0001...   # 🗄️ Migrations
├── rules/sigma/*.yml          # 📥 SigmaHQ rules  
├── grafana-dashboard.json     # 📊 Grafana import
├── sync_sigmahq.py            # 🔄 Rules sync
└── mitre_attck.json           # 🎯 ATT&CK mapping
```

## 🚨 **Rozwiązywanie problemów**

| Problem | Rozwiązanie |
|---------|-------------|
| `Permission denied` | `chmod +x sync_sigmahq.py` |
| `alembic: No such table` | `alembic upgrade head` |
| `Redis connection` | `docker-compose up redis` |
| `Login 401` | `tier1pass/tier2pass/adminpass` |
| `Upload 413` | Zwiększ `client_max_body_size` NGINX |

## 📈 **Production scaling**

```bash
# NGINX + multiple workers
gunicorn -w 4 -k uvicorn.workers.UvicornWorker noriben_soc.api.app:app

# Redis cluster / PG replica
# Grafana + Loki/Prometheus
# Vault HA mode
```

## 🎉 **Jesteś gotowy!**

**Masz kompletny SOC platform**:
✅ **Browser UI** ← **jedno kliknięcie**  
✅ **docker-compose** ← **1 command**  
✅ **SigmaHQ sync** ← **auto rules**  
✅ **Grafana** ← **visual monitoring**  
✅ **MITRE mapping** ← **threat intel**  
✅ **Vault** ← **secure secrets**

**localhost:8000 → instant SOC platform!**
