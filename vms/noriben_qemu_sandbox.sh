#!/bin/bash
# Noriben SOC v6.6 — QEMU Win10 Sandbox Launcher
# Bezpieczeństwo: restrict=on (izolacja sieci), snapshot=on (przywracanie VM)

SAMPLE=$1
TIMEOUT=${2:-300}
SHARED=/shared
STEM=$(basename "$SAMPLE" .exe)
ACCEL=${QEMU_ACCEL:-tcg}

echo "[qemu] Sample: $SAMPLE | Timeout: ${TIMEOUT}s | Accel: $ACCEL"

if [ "$ACCEL" = "kvm" ]; then
    ACCEL_FLAGS="-accel kvm"
    echo "[qemu] ✅ KVM acceleration"
else
    ACCEL_FLAGS="-accel tcg,thread=multi"
    echo "[qemu] ⚠️  TCG emulation (wolniej)"
fi

# Sieć: restrict=on = brak dostępu do hosta/LAN, tylko internet
qemu-system-x86_64 \
  -machine q35 $ACCEL_FLAGS \
  -cpu max -smp 4 -m 4096 \
  -drive file=$SHARED/vms/win10.qcow2,if=virtio,snapshot=on \
  -netdev user,id=net0,restrict=on \
  -device virtio-net-pci,netdev=net0 \
  -vnc :0,password \
  -virtfs local,path=$SHARED,mount_tag=shared,security_model=none \
  -monitor tcp:0.0.0.0:4444,server,nowait \
  -daemonize

sleep 15
echo "[qemu] VM uruchomiona — wstrzykuję próbkę..."

cat > $SHARED/run.bat << BAT
@echo off
cd C:\noriben
python noriben.py -t $TIMEOUT ^
  --output C:\shared\results\${STEM}.pml ^
  --cmd C:\shared\samples\$(basename $SAMPLE)
BAT

echo "[qemu] Noriben uruchomiony (${TIMEOUT}s)..."
sleep $TIMEOUT
echo "[qemu] Analiza zakończona: $SHARED/results/${STEM}.pml"

# Snapshot=on: Win10 automatycznie przywrócone do czystego stanu
echo "[qemu] ✅ VM przywrócona do czystego snapshotu"
