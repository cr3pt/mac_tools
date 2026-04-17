#!/bin/bash
# Noriben SOC v6.6 — deploy.sh — Cr3pT
set -e
cd "$(dirname "$0")"
echo "============================================"
echo "  Noriben SOC v6.6 — Auto Deploy"
echo "============================================"
source scripts/detect_env.sh
case "$NORIBEN_ENV" in
  APPLE_*)
    command -v brew &>/dev/null || { echo "Homebrew wymagany: https://brew.sh"; exit 1; }
    [[ "$NORIBEN_ENV" == "APPLE_M"* ]] && softwareupdate --install-rosetta --agree-to-license 2>/dev/null || true ;;
  LINUX_*)
    if [ "$NORIBEN_ENV" = "LINUX_NO_KVM" ]; then
        sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || true
        sudo usermod -aG kvm $USER 2>/dev/null || true
        sudo chmod 666 /dev/kvm 2>/dev/null || true
    fi ;;
esac
bash scripts/generate_compose.sh
[ -f "vms/win10.qcow2" ] && echo "win10.qcow2 istnieje" || bash scripts/win10_setup.sh
mkdir -p vms/{yara_rules,samples,results} grafana/provisioning
[ -d vms/yara_rules/rules ] || git clone https://github.com/Yara-Rules/rules vms/yara_rules/rules
docker volume create noriben_pg noriben_grafana 2>/dev/null || true
docker-compose up -d
sleep 45
docker-compose exec api alembic upgrade head 2>/dev/null || true
echo ""
echo "============================================"
echo "  NORIBEN SOC v6.6 LIVE! [$NORIBEN_ENV]"
echo "  UI:      http://localhost:8000"
echo "  Grafana: http://localhost:3000"
echo "  VNC:     localhost:5901 (haslo: noriben)"
echo "  API:     http://localhost:8000/docs"
echo "============================================"
