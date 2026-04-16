#!/bin/bash
set -e
echo "Noriben SOC v6.4 — Mac Deploy"
[ "$(uname -m)" = "arm64" ] && softwareupdate --install-rosetta --agree-to-license 2>/dev/null || true
docker volume create noriben_pg noriben_redis noriben_grafana 2>/dev/null || true
mkdir -p vms/{yara_rules,samples,win10_sandbox,results} grafana/provisioning
[ -d vms/yara_rules/rules ] || git clone https://github.com/Yara-Rules/rules vms/yara_rules/rules
docker-compose up -d postgres redis api celery qemu grafana vault
sleep 45
docker-compose exec api alembic upgrade head
echo "LIVE: http://localhost:8000 | Grafana: http://localhost:3000 | VNC: localhost:5901"