#!/bin/bash
# Noriben SOC v6.8 — win_setup.sh — Cr3pT
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
VMS="$DIR/vms"
mkdir -p "$VMS"
source "$DIR/scripts/detect_env.sh"
[ "$NORIBEN_ENV" = "LINUX_KVM" ] && ACCEL="-accel kvm" || ACCEL="-accel tcg,thread=multi"

download_file() {
    local URL=$1 OUT=$2 MIN_SIZE=$3 DESC=$4
    local ATTEMPT=0 MAX=10
    while [ $ATTEMPT -lt $MAX ]; do
        ATTEMPT=$((ATTEMPT + 1))
        echo "[$DESC] Pobieranie — proba $ATTEMPT/$MAX..."
        if command -v curl &>/dev/null; then
            curl -L --max-time 7200 --connect-timeout 60 --retry 0 --progress-bar -o "$OUT" "$URL" || true
        else
            wget --tries=1 --timeout=7200 --show-progress -O "$OUT" "$URL" || true
        fi
        if [ -f "$OUT" ]; then
            FSIZE=$(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT" 2>/dev/null || echo 0)
            if [ "$FSIZE" -gt "$MIN_SIZE" ]; then
                echo "[$DESC] OK: $(du -sh $OUT | cut -f1)"
                return 0
            else
                echo "[$DESC] Niekompletny (${FSIZE}B < ${MIN_SIZE}B) — ponawiam za 10s..."
                rm -f "$OUT"
            fi
        fi
        sleep 10
    done
    echo "[$DESC] BLAD: nie udalo sie pobrac po $MAX probach"
    return 1
}

next_free_port() {
    local p=$1
    while ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":$p$"; do p=$((p+1)); done
    echo $p
}

install_vm() {
    local NAME=$1 ISO=$2 QCOW2=$3 VNC_DISP=$4 MON_PORT=$5
    local VNC_PORT=$((5900 + VNC_DISP))
    local MP=$MON_PORT
    while ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":$MP$"; do MP=$((MP+1)); done

    qemu-img create -f qcow2 "$QCOW2" 60G
    echo "[$NAME] Dysk OK: $(du -sh $QCOW2 | cut -f1)"

    if ss -tlnp 2>/dev/null | grep -q ":$VNC_PORT "; then
        VNC_DISP=$((VNC_DISP + 10)); VNC_PORT=$((5900 + VNC_DISP))
        echo "[$NAME] Port zajety — uzywam VNC :$VNC_DISP (port $VNC_PORT)"
    fi

    echo ""
    echo "======================================================"
    echo "  $NAME — Instalacja przez QEMU + VNC"
    echo "  VNC: localhost:$VNC_PORT  (BEZ hasla)"
    echo "  macOS:  open vnc://localhost:$VNC_PORT"
    echo "  Linux:  vncviewer localhost:$VNC_PORT"
    echo "======================================================"

    qemu-system-x86_64 \
      -name "$NAME-install" \
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
      -monitor tcp:0.0.0.0:$MP,server,nowait \
      -usbdevice tablet \
      -vga std \
      -daemonize

    echo "[$NAME] QEMU uruchomiony — monitor port: $MP"
}

setup_win10() {
    local QCOW2="$VMS/win10.qcow2" ISO="$VMS/win10.iso"
    if [ -f "$QCOW2" ] && [ "$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2")" -gt 1073741824 ]; then
        echo "[win10] qcow2 istnieje — pomijam"; return 0
    fi
    if [ ! -f "$ISO" ] || [ "$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null || echo 0)" -lt 3221225472 ]; then
        rm -f "$ISO"
        download_file "https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US" "$ISO" 3221225472 "win10-iso" || {
            echo "[win10] Pobierz ISO recznie: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise"
            echo "[win10] Zapisz jako: $ISO"
            return 1
        }
    fi
    install_vm "win10" "$ISO" "$QCOW2" 1 4440
}

setup_win11() {
    local QCOW2="$VMS/win11.qcow2" ISO="$VMS/win11.iso"
    if [ -f "$QCOW2" ] && [ "$(stat -c%s "$QCOW2" 2>/dev/null || stat -f%z "$QCOW2")" -gt 1073741824 ]; then
        echo "[win11] qcow2 istnieje — pomijam"; return 0
    fi
    echo "[win11] UWAGA: Gotowy qcow2 Win11 nie jest publicznie dostepny."
    echo "[win11] Opcje: A) wlasny qcow2 B) instalacja z ISO C) konwersja z VDI/VMDK/VHDX"
    if [ ! -f "$ISO" ] || [ "$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null || echo 0)" -lt 3221225472 ]; then
        rm -f "$ISO"
        download_file "https://go.microsoft.com/fwlink/?linkid=2156292" "$ISO" 3221225472 "win11-iso" || {
            echo "[win11] Pobierz ISO recznie: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise"
            echo "[win11] Zapisz jako: $ISO"
            qemu-img create -f qcow2 "$QCOW2" 60G
            return 0
        }
    fi
    echo ""
    echo "[win11] Bypass TPM podczas instalacji:"
    echo "  Shift+F10 i wpisz:"
    echo "    reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f"
    echo "    reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f"
    echo "    reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f"
    echo ""
    install_vm "win11" "$ISO" "$QCOW2" 2 4441
}

setup_win10
setup_win11

echo ""
echo "======================================================="
echo "  Win10 VNC: localhost:5901  bez hasla (instalacja)"
echo "  Win11 VNC: localhost:5902  bez hasla (instalacja)"
echo "  Po instalacji sandbox VNC: haslo = noriben"
echo "  Po instalacji uruchom w VM: C:\\shared\\noriben_setup.ps1"
echo "======================================================="
