# Noriben SOC v11.0 Enterprise Addons

## Grafana (localhost:3000)
1. Import grafana-dashboard.json
2. Prometheus datasource: http://localhost:8000/metrics

## SigmaHQ Sync
chmod +x sync_sigmahq.py && ./sync_sigmahq.py

## MITRE ATT&CK
Integrate mitre_attck.json into pipeline.py

## Production
docker-compose -f docker-compose.prod.yml up -d
