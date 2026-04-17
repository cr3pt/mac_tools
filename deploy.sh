#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "  Noriben SOC v6.6 — Auto Deploy"
echo "============================================"

# 1. Wykryj środowisko
source scripts/detect_env.sh

# 2. Zainstaluj zależności systemowe
case "$NORIBEN_ENV" in
  APPLE_*)
    if ! command -v brew &>/dev/null; then
      echo "❌ Homebrew wymagany. Zainstaluj: https://brew.sh"
      exit 1
    fi
    # Włącz Rosetta 2 na ARM
    if [[ "$NORIBEN_ENV" == "APPLE_M"* ]]; then
      echo "[deploy] Aktywuję Rosetta 2..."
      softwareupdate --install-rosetta --agree-to-license 2>/dev/null || true
      # Włącz Rosetta w Docker Desktop (jeśli dostępne)
      defaults write ~/Library/Group\ Containers/group.com.docker/settings.json useRosetta -bool true 2>/dev/null || true
    fi
    ;;
  LINUX_*)
    if [ "$NORIBEN_ENV" = "LINUX_NO_KVM" ]; then
      echo "[deploy] Próbuję aktywować KVM..."
      sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || true
      sudo usermod -aG kvm $USER 2>/dev/null || true
      sudo chmod 666 /dev/kvm 2>/dev/null || true
    fi
    ;;
esac

# 3. Wygeneruj właściwy docker-compose.yml
bash scripts/generate_compose.sh

# 4. Pobierz i przygotuj Win10 qcow2
if [ ! -f "vms/win10.qcow2" ]; then
  echo "[deploy] Win10 qcow2 nie znaleziono — uruchamiam setup..."
  bash scripts/win10_setup.sh
else
  echo "[deploy] ✅ win10.qcow2 istnieje"
fi

# 5. YARA rules
mkdir -p vms/{yara_rules,samples,results} grafana/provisioning
[ -d vms/yara_rules/rules ] || git clone https://github.com/Yara-Rules/rules vms/yara_rules/rules

# 6. Docker volumes
docker volume create noriben_pg noriben_redis noriben_grafana 2>/dev/null || true

# 7. Docker stack
echo "[deploy] Startuję Docker Compose ($NORIBEN_ENV)..."
docker-compose up -d

sleep 45
docker-compose exec api alembic upgrade head 2>/dev/null || true

echo ""
echo "============================================"
echo "  ✅ NORIBEN SOC v6.6 LIVE!"
echo "  Środowisko: $NORIBEN_ENV"
echo "============================================"
echo "  🌐 UI:      http://localhost:8000"
echo "  📊 Grafana: http://localhost:3000  (admin/admin)"
echo "  🖥️  VNC:     localhost:5901         (noriben)"
echo "  📈 API:     http://localhost:8000/docs"
echo "============================================"
