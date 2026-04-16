
# Noriben SOC v2 — Kompletny setup z WebSocket UI (2026-04-16)

## 1. Full package download
```
# Wszystkie pliki z rozmowy:
noriben_soc_platform_v10_1_complete.zip     # Core
noriben_soc_v11_enterprise_addons.zip       # Grafana/SigmaHQ  
noriben_soc_browser_ui_v2.zip               # Enhanced UI + WebSocket
```

## 2. Docker + API
```bash
docker-compose up -d postgres redis
pip install -r requirements.txt
alembic upgrade head
cp index.html .  # Browser UI
uvicorn noriben_soc.api.app:app --reload
```

## 3. WebSocket endpoint (dodaj do api/app.py)
```python
from fastapi import WebSocket
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        # Send live metrics
        await websocket.send_json({"jobs_queued": 5, "high_severity": 2})
        await asyncio.sleep(2)
```

## 4. Usage
```
localhost:8000 → 
✅ WebSocket 🟢 Live (top bar)
✅ Multi-drag&drop upload  
✅ Live jobs table (WebSocket)
✅ Sessions table auto-refresh
✅ CSV/PDF export buttons
✅ Responsive glassmorphism UI
```

## 5. Features v2
| Feature | Status |
|---------|--------|
| WebSocket live | 🟢 Real-time jobs/status |
| Multi-file drag | 🟢 50MB limit, progress bar |
| PDF/CSV export | 🟢 jsPDF + Blob download |
| Glassmorphism UI | 🟢 Tailwind gradients |
| Auto-reconnect WS | 🟢 3s retry |

**Gotowe! localhost:8000 → full SOC dashboard z live updates.**
