#!/bin/bash
# Noriben SOC v6.8 — deploy.sh — Cr3pT
set -e
cd "$(dirname "$0")"
echo "============================================"
echo "  Noriben SOC v6.8 — Auto Deploy"
echo "============================================"
source scripts/detect_env.sh

# Install system build dependencies for Python extensions
sudo apt-get update -qq && sudo apt-get install -y libpq-dev python3-dev build-essential curl
# Install Rust toolchain (required for pydantic-core)
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi
# Install Python dependencies (including native wheels)
python3 -m venv venv && source venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

[ "$NORIBEN_ENV" = "LINUX_NO_KVM" ] && {
    sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || true
    sudo usermod -aG kvm $USER 2>/dev/null || true
    sudo chmod 666 /dev/kvm 2>/dev/null || true
}

python3 scripts/gen_compose.py "$NORIBEN_ENV"
bash scripts/win_setup.sh
mkdir -p vms/{samples,results} grafana/provisioning
[ -d vms/yara_rules ] || git clone --depth=1 https://github.com/Yara-Rules/rules vms/yara_rules
docker volume create noriben_pg      2>/dev/null || true
docker volume create noriben_grafana 2>/dev/null || true
docker compose up -d
sleep 30
docker compose exec api alembic upgrade head 2>/dev/null || true

echo ""
echo "============================================"
echo "  NORIBEN SOC v6.8 LIVE! [$NORIBEN_ENV]"
echo "  UI:        http://localhost:8000"
echo "  Grafana:   http://localhost:3000  admin/admin"
echo "  Win10 VNC: localhost:5901  (instalacja: bez hasla)"
echo "  Win11 VNC: localhost:5902  bez hasla (instalacja)"
echo "  API docs:  http://localhost:8000/docs"
echo "============================================"
