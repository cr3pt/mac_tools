#!/bin/bash
# Noriben SOC v6.6 — win10_setup.sh — Cr3pT
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VMS_DIR="$SCRIPT_DIR/../vms"
ISO="$VMS_DIR/win10.iso"
QCOW2="$VMS_DIR/win10.qcow2"
VNC_PORT=5901; VNC_DISPLAY=1
mkdir -p "$VMS_DIR"

# qcow2 juz istnieje?
if [ -f "$QCOW2" ]; then
    echo "[win10_setup] win10.qcow2 juz istnieje ($(du -sh $QCOW2|cut -f1)) — pomijam"
    exit 0
fi

# ISO: sprawdz / pobierz
DOWNLOAD_ISO=false
if [ -f "$ISO" ]; then
    ISO_SIZE=$(stat -f%z "$ISO" 2>/dev/null || stat -c%s "$ISO" 2>/dev/null || echo 0)
    if [ "$ISO_SIZE" -gt 3221225472 ]; then
        echo "[win10_setup] win10.iso juz istnieje ($(du -sh $ISO|cut -f1)) — pomijam pobieranie"
    else
        echo "[win10_setup] ISO niekompletne (${ISO_SIZE}B) — pobieram ponownie"
        rm -f "$ISO"; DOWNLOAD_ISO=true
    fi
else
    DOWNLOAD_ISO=true
fi

if [ "$DOWNLOAD_ISO" = "true" ]; then
    echo "[win10_setup] Pobieranie Win10 Enterprise Evaluation (~4.5 GB)..."
    WIN10_URL="https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US"
    if command -v curl &>/dev/null; then
        curl -L --progress-bar --retry 3 --retry-delay 5 -o "$ISO" "$WIN10_URL"
    elif command -v wget &>/dev/null; then
        wget --show-progress --tries=3 --wait=5 -O "$ISO" "$WIN10_URL"
    else
        echo "Brak curl/wget. macOS: brew install curl | Ubuntu: sudo apt install curl"; exit 1
    fi
    ISO_SIZE=$(stat -f%z "$ISO" 2>/dev/null || stat -c%s "$ISO" 2>/dev/null || echo 0)
    [ "$ISO_SIZE" -lt 3221225472 ] && { echo "ISO niekompletne. Sprawdz lacze."; exit 1; }
    echo "[win10_setup] ISO OK: $(du -sh $ISO|cut -f1)"
fi

# Zainstaluj qemu jesli brak
if ! command -v qemu-img &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
    OS=$(uname -s)
    if [ "$OS" = "Darwin" ]; then
        brew install qemu
    elif [ "$OS" = "Linux" ]; then
        echo "[win10_setup] Potrzebuje sudo — masz 60 sekund na wpisanie hasla:"
        sudo -v -p "[sudo] haslo dla %u: " || { echo "Brak sudo"; exit 1; }
        ( while true; do sudo -v -n 2>/dev/null; sleep 55; done ) &
        SUDO_KEEPALIVE=$!
        sudo apt-get install -y qemu-utils qemu-system-x86 ovmf
        kill $SUDO_KEEPALIVE 2>/dev/null || true
    fi
fi

qemu-img create -f qcow2 "$QCOW2" 60G

source "$(dirname $0)/detect_env.sh"
[ "$NORIBEN_ENV" = "LINUX_KVM" ] && ACCEL="-accel kvm" || ACCEL="-accel tcg,thread=multi"

# Sprawdz wolny port VNC
if lsof -i :$VNC_PORT &>/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -q ":$VNC_PORT "; then
    VNC_PORT=5902; VNC_DISPLAY=2
    echo "[win10_setup] Port 5901 zajety — uzywam 5902"
fi

echo ""
echo "================================================"
echo "  Instalacja Windows 10 przez QEMU"
echo "  VNC: localhost:$VNC_PORT (BEZ hasla)"
echo "  macOS:  open vnc://localhost:$VNC_PORT"
echo "  Linux:  vncviewer localhost:$VNC_PORT"
echo "  TigerVNC: vncviewer localhost::$VNC_PORT"
echo "================================================"
echo ""

# 0.0.0.0 = bind na wszystkich interfejsach; brak ,password = bez hasla
qemu-system-x86_64 \
  -machine q35 $ACCEL -cpu max -smp 4 -m 4096 \
  -drive file="$QCOW2",if=virtio \
  -cdrom "$ISO" -boot order=d \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -vnc 0.0.0.0:$VNC_DISPLAY \
  -monitor tcp:0.0.0.0:4445,server,nowait \
  -name "Noriben-Win10-Install" &

QEMU_PID=$!
echo "[win10_setup] QEMU PID: $QEMU_PID — VNC aktywny na :$VNC_PORT"

sleep 60
for i in $(seq 1 59); do
    sleep 60
    echo "[win10_setup] ... $((i+1)) min / 60"
    ! kill -0 $QEMU_PID 2>/dev/null && echo "Instalacja gotowa" && break
done

echo "[win10_setup] qcow2: $(du -sh $QCOW2|cut -f1)"
cat > "$VMS_DIR/noriben_setup.ps1" << 'PS1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://github.com/Rurik/Noriben/archive/refs/heads/master.zip" -OutFile "C:\noriben.zip"
Expand-Archive "C:\noriben.zip" "C:\"
Rename-Item "C:\Noriben-master" "C:\noriben"
python -m pip install psutil
Write-Host "Noriben gotowy w C:\noriben"
PS1
echo "================================================"
echo "  GOTOWE: $QCOW2"
echo "  W VM: Set-ExecutionPolicy Bypass -Scope Process"
echo "        C:\\shared\\noriben_setup.ps1"
echo "================================================"
