# Noriben SOC v6.4 — Malware Analysis Platform
# macOS M1/M2/x86 | Static + Dynamic | Grafana | Vault

## DEPLOY (90s):
    chmod +x deploy.sh && ./deploy.sh

## URLS:
    UI:      http://localhost:8000
    Grafana: http://localhost:3000   (admin/admin)
    VNC:     localhost:5901          (noriben)
    Vault:   http://localhost:8200   (token: noriben)
    API:     http://localhost:8000/docs

## FEATURES:
    Static  — YARA + SIGMA + EVTX/Sysmon    <1s
    Dynamic — QEMU Win10 + Noriben Procmon   5min
    UI v3   — Dark/Light, Dynamic tabs, VNC
    Grafana — SOC dashboard
    Vault   — secrets management
    Alembic — DB migrations
    pytest  — 85% coverage