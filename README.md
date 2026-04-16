
# 🎯 NORIBEN SOC PLATFORM v11 — OSTATECZNA INSTRUKCJA (2026-04-16)

**Czas wdrożenia: 5 minut** | **Wszystko w jednym repo** | **Browser UI included**

## 📦 1. Pobierz i przygotuj
```bash
wget Noriben-SOC-GitHub-Ready_v11.zip  # lub git clone
unzip Noriben-SOC-GitHub-Ready_v11.zip
cd Noriben-SOC-Platform
```

## 🐳 2. Docker stack (1 linia)
```bash
docker-compose up -d
# Sprawdza: docker ps → postgres, redis, app
```

## 🔧 3. Pierwsze uruchomienie
```bash
pip install -r requirements.txt
cd noriben_soc
alembic upgrade head          # ✅ Baza utworzona
cd ..
cp browser_ui/* .             # ✅ WebSocket UI v2
make dev                      # Sync SigmaHQ + restart
```

## 🌐 4. UŻYWAJ w przeglądarce
```
http://localhost:8000

1. 🔐 Login: tier2 / tier2pass
2. 🟢 WebSocket LIVE (pasek górny)
3. 📤 Drag wiele plików (.exe/.evtx/.ps1)
4. 📊 Live jobs table (bez refresh!)
5. 📋 Sessions + kolorowe severity
6. 📄 CSV / PDF export (1 klik)
```

## 📥 5. SigmaHQ rules (auto-sync)
```bash
make sync-rules               # Pobiera powershell.yml, wevtutil.yml
# Cron: 0 */6 * * * make sync-rules
```

## 📊 6. Grafana (opcjonalne)
```bash
docker run -d -p 3000:3000 grafana/grafana
# localhost:3000 → Import addons/grafana-dashboard.json
# Prometheus: localhost:8000/metrics
```

## 🗄️ 7. Vault production secrets
```bash
docker run -d -p 8200:8200 vault
vault kv put noriben NORIBEN_SECRET=prod-key
export NORIBEN_SECRET_BACKEND=vault
export NORIBEN_VAULT_ADDR=http://localhost:8200
export NORIBEN_VAULT_TOKEN=$(vault print token)
docker-compose restart app
# /health → "has_secret": true ✓
```

## 🧪 8. END-TO-END TEST (copy-paste)
```bash
# 1. Full clean start
docker-compose down -v && docker-compose up -d
pip install -r requirements.txt
cd noriben_soc && alembic upgrade head && cd ..

# 2. UI + rules
cp browser_ui/* . && make dev

# 3. Browser test
curl localhost:8000/health     # ok
# localhost:8000 → Login → Upload → Live ✓
```

## 🚨 Troubleshooting
| Problem | Fix |
|---------|-----|
| `No module named noriben_soc` | `PYTHONPATH=.` |
| `alembic table exists` | `alembic current` |
| `Redis connection refused` | `docker-compose up redis` |
| `Login 401` | `tier1pass/tier2pass/adminpass` |
| `Upload 413` | NGINX: `client_max_body_size 100M` |
| `WebSocket failed` | `/ws` endpoint w app.py |

## 📈 Production hardening
```nginx
# NGINX reverse proxy
server {
  listen 443 ssl;
  location / {
    proxy_pass http://localhost:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";  # WebSocket
  }
}
```

## 🏆 FINAL STACK CHECKLIST
- [x] **FastAPI + Alembic PostgreSQL** — Production DB
- [x] **hvac Vault** — Secure secrets  
- [x] **SigmaHQ + YARA** — Rules engines + sync
- [x] **Celery/Redis** — Async analysis
- [x] **WebSocket UI v2** — Live multi-upload/export
- [x] **Grafana** — Metrics visualization
- [x] **MITRE ATT&CK** — Tactics mapping

## 🎉 JESTEŚ GOTOWY!
```
docker-compose up → make dev → localhost:8000
                           ↓
Full enterprise SOC platform z live browser UI! 🚀
```

**Repo: git clone → 5 min → PRODUCTION SOC TOOL ✓**
