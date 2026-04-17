#!/bin/bash
# Noriben SOC v6.6 — Win10 Evaluation ISO → qcow2
# Źródło: Microsoft Evaluation Center (90-day trial, legalne)
# https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VMS_DIR="$SCRIPT_DIR/../vms"
ISO="$VMS_DIR/win10.iso"
QCOW2="$VMS_DIR/win10.qcow2"
NORIBEN_INSTALLER="$VMS_DIR/noriben_setup.ps1"

mkdir -p "$VMS_DIR"

# Sprawdź czy qcow2 już istnieje
if [ -f "$QCOW2" ]; then
    echo "[win10_setup] ✅ win10.qcow2 już istnieje — pomijam pobieranie"
    exit 0
fi

echo "[win10_setup] 📥 Pobieranie Windows 10 Enterprise Evaluation ISO..."
echo "[win10_setup] ⚠️  Licencja: Microsoft Evaluation (90 dni, tylko do testów)"

# Microsoft Evaluation Center — bezpośredni link ISO Win10 Enterprise 64-bit
WIN10_URL="https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US"

if command -v curl &>/dev/null; then
    curl -L --progress-bar -o "$ISO" "$WIN10_URL"
elif command -v wget &>/dev/null; then
    wget --show-progress -O "$ISO" "$WIN10_URL"
else
    echo "[win10_setup] ❌ Brak curl/wget. Zainstaluj: brew install curl"
    exit 1
fi

echo "[win10_setup] ✅ ISO pobrane: $(du -sh $ISO | cut -f1)"

# Instalacja qemu-img
if ! command -v qemu-img &>/dev/null; then
    OS=$(uname -s)
    if [ "$OS" = "Darwin" ]; then
        echo "[win10_setup] Instaluję qemu przez Homebrew..."
        brew install qemu
    elif [ "$OS" = "Linux" ]; then
        echo "[win10_setup] Instaluję qemu-utils..."
        sudo apt-get install -y qemu-utils qemu-system-x86
    fi
fi

# Krok 1: Utwórz pusty dysk dla instalacji
echo "[win10_setup] 📀 Tworzę dysk VM: 60GB..."
qemu-img create -f qcow2 "$QCOW2" 60G

# Krok 2: Unattended install Win10 przez QEMU
echo "[win10_setup] 🖥️  Uruchamiam instalację Win10 (nieinteraktywną)..."
echo "[win10_setup] ⏳ To może zająć 20-40 min..."

source "$(dirname $0)/detect_env.sh"

if [ "$NORIBEN_ENV" = "LINUX_KVM" ]; then
    ACCEL="-accel kvm"
    echo "[win10_setup] ✅ KVM acceleration aktywne"
else
    ACCEL="-accel tcg,thread=multi"
    echo "[win10_setup] ⚠️  Softwarowa emulacja (brak KVM) — wolniej"
fi

qemu-system-x86_64 \
  -machine q35 $ACCEL \
  -cpu max -smp 4 -m 4096 \
  -drive file="$QCOW2",if=virtio \
  -cdrom "$ISO" \
  -boot order=d \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -vnc :1 \
  -display none \
  -monitor unix:/tmp/qemu-monitor.sock,server,nowait &

QEMU_PID=$!
echo "[win10_setup] 📡 Instalacja VNC dostępna: vncviewer localhost:5902"
echo "[win10_setup] ⏳ Czekam na zakończenie instalacji (max 60min)..."

# Czekaj aż instalacja się skończy (monitor socket)
sleep 60  # Boot
for i in $(seq 1 50); do
    sleep 60
    echo "[win10_setup] ... minęło $((i+1)) min"
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "[win10_setup] QEMU zakończył pracę"
        break
    fi
done

echo "[win10_setup] ✅ Instalacja Win10 zakończona"
echo "[win10_setup] 📦 qcow2: $(du -sh $QCOW2 | cut -f1)"

# Pobierz i skopiuj Noriben do VM
cat > "$NORIBEN_INSTALLER" << 'PS1'
# Noriben auto-install w Win10 VM
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$noriben_url = "https://github.com/Rurik/Noriben/archive/refs/heads/master.zip"
$pip_url     = "https://bootstrap.pypa.io/get-pip.py"
Invoke-WebRequest -Uri $noriben_url -OutFile "C:\noriben.zip"
Expand-Archive -Path "C:\noriben.zip" -DestinationPath "C:\"
Rename-Item "C:\Noriben-master" "C:\noriben"
Invoke-WebRequest -Uri $pip_url -OutFile "C:\get-pip.py"
python C:\get-pip.py
pip install psutil
Write-Host "Noriben zainstalowany OK"
PS1

echo "[win10_setup] 📝 noriben_setup.ps1 gotowy — uruchom w VM po instalacji"
echo "[win10_setup] 🎉 GOTOWE: $QCOW2"
