#!/bin/bash
# Noriben SOC v6.8 — win_setup.sh — Cr3pT
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
VMS="$DIR/vms"
mkdir -p "$VMS"
source "$DIR/scripts/detect_env.sh"
[ "$NORIBEN_ENV" = "LINUX_KVM" ] && ACCEL="-accel kvm" || ACCEL="-accel tcg,thread=multi"

# ─── Pomocnicze: pobierz plik z wieloma próbami ────────────
download_file() {
    local URL=$1 OUT=$2 MIN_SIZE=$3 DESC=$4
    local ATTEMPT=0 MAX=10
    while [ $ATTEMPT -lt $MAX ]; do
        ATTEMPT=$((ATTEMPT + 1))
        echo "[$DESC] Proba $ATTEMPT/$MAX..."
        if command -v curl &>/dev/null; then
            curl -L --retry 0 --max-time 3600 --connect-timeout 30 \
                 --progress-bar -o "$OUT" "$URL" && true || true
        else
            wget --tries=1 --timeout=3600 --show-progress -O "$OUT" "$URL" || true
        fi
        if [ -f "$OUT" ]; then
            FSIZE=$(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT" 2>/dev/null || echo 0)
            if [ "$FSIZE" -gt "$MIN_SIZE" ]; then
                echo "[$DESC] Pobrano OK: $(du -sh $OUT | cut -f1)"
                return 0
            else
                echo "[$DESC] Plik za maly (${FSIZE}B) — ponawiam za 5s..."
                rm -f "$OUT"
            fi
        else
            echo "[$DESC] Brak pliku — ponawiam za 5s..."
        fi
        sleep 5
    done
    echo "[$DESC] BLAD: nie udalo sie pobrac po $MAX probach"
    return 1
}

# ─── WIN11 — gotowy qcow2 ──────────────────────────────────
setup_win11() {
    local QCOW2="$VMS/win11.qcow2"
    if [ -f "$QCOW2" ]; then
        FSIZE=$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2" 2>/dev/null || echo 0)
        if [ "$FSIZE" -gt 1073741824 ]; then
            echo "[win11] qcow2 istnieje ($(du -sh $QCOW2|cut -f1)) — pomijam"
            return 0
        fi
        rm -f "$QCOW2"
    fi

    echo "[win11] Pobieranie gotowego obrazu Win11..."

    # Próbujemy kolejno kilka źródeł
    URLS=(
        "https://archive.org/download/windows-11-enterprise-eval-qcow2/win11_enterprise_eval.qcow2"
        "https://archive.org/download/win11-qcow2/win11.qcow2"
        "https://github.com/dockur/windows/releases/download/4.0/win11.qcow2"
    )

    for URL in "${URLS[@]}"; do
        echo "[win11] Próba URL: $URL"
        download_file "$URL" "$QCOW2" 1073741824 "win11" && return 0 || true
        rm -f "$QCOW2"
    done

    # Żadne źródło nie zadziałało — utwórz pusty dysk i poinformuj
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  [win11] Automatyczne pobranie nie powiodlo sie      ║"
    echo "║  Dostarcz recznie:                                   ║"
    echo "║    cp /path/to/win11.qcow2 $VMS/win11.qcow2  ║"
    echo "║  lub konwertuj z VirtualBox/VMware:                  ║"
    echo "║    qemu-img convert -f vdi -O qcow2 win11.vdi \\      ║"
    echo "║      $VMS/win11.qcow2                        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "[win11] Tworzę pusty dysk (60 GB) jako placeholder..."
    qemu-img create -f qcow2 "$QCOW2" 60G
}

# ─── WIN10 — pobierz ISO + utwórz dysk + instalacja ──────
setup_win10() {
    local QCOW2="$VMS/win10.qcow2"
    local ISO="$VMS/win10.iso"

    if [ -f "$QCOW2" ]; then
        FSIZE=$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2" 2>/dev/null || echo 0)
        if [ "$FSIZE" -gt 1073741824 ]; then
            echo "[win10] qcow2 istnieje ($(du -sh $QCOW2|cut -f1)) — pomijam"
            return 0
        fi
        rm -f "$QCOW2"
    fi

    # ISO — pobierz jeśli brak lub niekompletny
    local NEED_ISO=true
    if [ -f "$ISO" ]; then
        FSIZE=$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null || echo 0)
        [ "$FSIZE" -gt 3221225472 ] && NEED_ISO=false || { echo "[win10] ISO niekompletny — ponawiam"; rm -f "$ISO"; }
    fi

    if [ "$NEED_ISO" = "true" ]; then
        WIN10_URLS=(
            "https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US"
            "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409"
        )
        local DOWNLOADED=false
        for URL in "${WIN10_URLS[@]}"; do
            download_file "$URL" "$ISO" 3221225472 "win10-iso" && DOWNLOADED=true && break || rm -f "$ISO"
        done
        if [ "$DOWNLOADED" = "false" ]; then
            echo "[win10] BLAD: nie udalo sie pobrac ISO"
            echo "[win10] Pobierz recznie: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise"
            echo "[win10]   i zapisz jako: $ISO"
            return 1
        fi
    fi

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
}

setup_win11
setup_win10

echo ""
echo "======================================================="
echo "  Win11 VNC: localhost:5902  haslo: noriben (sandbox)"
echo "  Win10 VNC: localhost:5901  bez hasla (instalacja)"
echo "======================================================="
