
# Noriben SOC Platform v11 — GitHub Ready

Production SOC platform z browser UI, WebSocket, SigmaHQ, Grafana.

## Quickstart
```bash
git clone && cd Noriben-SOC-Platform
docker-compose up -d
pip install -r requirements.txt
cd noriben_soc && alembic upgrade head
cp ../browser_ui/* . && uvicorn noriben_soc.api.app:app --reload
```

**Open**: http://localhost:8000
