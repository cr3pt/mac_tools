#!/bin/bash
# Noriben SOC v6.8 — win_setup.sh
# Win10: pobiera ISO Microsoft -> instalacja na qcow2 przez VNC
# Win11: pobiera gotowy qcow2 (pre-installed, bez TPM)
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
VMS="$DIR/vms"
mkdir -p "$VMS"
source "$DIR/scripts/detect_env.sh"
[ "$NORIBEN_ENV" = "LINUX_KVM" ] && ACCEL="-accel kvm" || ACCEL="-accel tcg,thread=multi"

# ─── WIN11 — gotowy qcow2 ─────────────────────────────────
setup_win11() {
    local QCOW2="$VMS/win11.qcow2"
    if [ -f "$QCOW2" ] && [ "$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2")" -gt 1073741824 ]; then
        echo "[win11] qcow2 istnieje ($(du -sh $QCOW2|cut -f1)) — pomijam"
        return 0
    fi
    echo "[win11] Pobieranie gotowego obrazu Win11 (qcow2, bez TPM)..."
    # Obraz: Windows 11 Enterprise Eval pre-installed qcow2 (~8 GB skompresowany)
    # Zrodlo: https://archive.org/details/windows-11-enterprise-eval-qcow2
    WIN11_URL="https://archive.org/download/windows-11-enterprise-eval-qcow2/win11_enterprise_eval_notpm.qcow2.zst"
    TMPFILE="$VMS/win11.qcow2.zst"
    if command -v curl &>/dev/null; then
        curl -L --retry 3 --progress-bar -o "$TMPFILE" "$WIN11_URL"
    else
        wget --tries=3 --show-progress -O "$TMPFILE" "$WIN11_URL"
    fi
    # Rozpakuj zstd jeśli potrzeba
    if command -v zstd &>/dev/null; then
        zstd -d "$TMPFILE" -o "$QCOW2" && rm "$TMPFILE"
    else
        mv "$TMPFILE" "$QCOW2"
    fi
    echo "[win11] qcow2 OK: $(du -sh $QCOW2|cut -f1)"
}

# ─── WIN10 — pobierz ISO + utwórz dysk + instalacja ─────────
setup_win10() {
    local QCOW2="$VMS/win10.qcow2"
    local ISO="$VMS/win10.iso"

    if [ -f "$QCOW2" ] && [ "$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2")" -gt 1073741824 ]; then
        echo "[win10] qcow2 istnieje ($(du -sh $QCOW2|cut -f1)) — pomijam"
        return 0
    fi

    # Pobierz ISO jeśli brak lub niekompletny
    local NEED_ISO=false
    if [ ! -f "$ISO" ]; then
        NEED_ISO=true
    else
        ISO_SIZE=$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null || echo 0)
        [ "$ISO_SIZE" -lt 3221225472 ] && { echo "[win10] ISO niekompletny — ponowne pobieranie"; rm -f "$ISO"; NEED_ISO=true; }
    fi

    if [ "$NEED_ISO" = "true" ]; then
        echo "[win10] Pobieranie Win10 Enterprise Evaluation ISO (~4.5 GB)..."
        WIN10_URL="https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US"
        if command -v curl &>/dev/null; then
            curl -L --retry 3 --progress-bar -o "$ISO" "$WIN10_URL"
        else
            wget --tries=3 --show-progress -O "$ISO" "$WIN10_URL"
        fi
        ISO_SIZE=$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null || echo 0)
        [ "$ISO_SIZE" -lt 3221225472 ] && { echo "[win10] ISO za maly — sprawdz lacze internetowe"; exit 1; }
        echo "[win10] ISO OK: $(du -sh $ISO|cut -f1)"
    fi

    # Utwórz dysk 60 GB
    echo "[win10] Tworzenie dysku qcow2 (60 GB)..."
    qemu-img create -f qcow2 "$QCOW2" 60G
    echo "[win10] Dysk OK: $(du -sh $QCOW2|cut -f1)"

    # Sprawdź wolny port VNC
    VNC_DISP=1; VNC_PORT=5901
    ss -tlnp 2>/dev/null | grep -q ":5901 " && { VNC_DISP=11; VNC_PORT=5811; }

    echo ""
    echo "======================================================"
    echo "  Win10 — Instalacja przez QEMU + VNC"
    echo "  VNC: localhost:$VNC_PORT  (BEZ hasla)"
    echo "  macOS:  open vnc://localhost:$VNC_PORT"
    echo "  Linux:  vncviewer localhost:$VNC_PORT"
    echo "======================================================"
    echo ""

    # QEMU z dyskiem (index=0) + ISO (index=1) + VirtIO
    qemu-system-x86_64 \
      -name "win10-install" \
      -machine type=q35 \
      $ACCEL \
      -cpu max \
      -smp cores=4,threads=1 \
      -m 4096 \
      -drive file="$QCOW2",format=qcow2,if=virtio,index=0,media=disk \
      -drive file="$ISO",format=raw,if=none,id=cdrom0,readonly=on \
      -device ide-cd,bus=ide.1,drive=cdrom0 \
      -boot order=dc,menu=on \
      -netdev user,id=net0 \
      -device virtio-net-pci,netdev=net0 \
      -vnc 0.0.0.0:$VNC_DISP \
      -monitor tcp:0.0.0.0:4440,server,nowait \
      -usbdevice tablet \
      -vga std \
      -daemonize

    echo "[win10] QEMU uruchomiony — polacz VNC i zainstaluj system"
    echo "[win10] Po instalacji: skopiuj C:\\shared\\noriben_setup.ps1 i uruchom"
}

setup_win11
setup_win10

echo ""
echo "======================================================="
echo "  Win11 VNC: localhost:5902  haslo: noriben (sandbox)"
echo "  Win10 VNC: localhost:5901  haslo: brak   (instalacja)"
echo "======================================================="
