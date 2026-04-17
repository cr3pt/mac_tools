#!/bin/bash
set -e
echo '🚀 Noriben SOC v6.5 deploy...'
docker volume create noriben_pg noriben_redis noriben_grafana 2>/dev/null || true
mkdir -p vms/{yara_rules,samples,results} grafana/provisioning
[ -d vms/yara_rules/rules ] || git clone https://github.com/Yara-Rules/rules vms/yara_rules/rules
docker-compose up -d
sleep 45
docker-compose exec api alembic upgrade head 2>/dev/null || true
echo '✅ LIVE: localhost:8000 | Grafana: localhost:3000'
