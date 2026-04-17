#!/bin/bash
# Noriben SOC v6.5 — QEMU Win10 Sandbox Launcher
SAMPLE=$1
TIMEOUT=${2:-300}
SHARED=/shared
STEM=$(basename "$SAMPLE" .exe)

echo "[*] QEMU Win10 — sample: $SAMPLE  timeout: ${TIMEOUT}s"

qemu-system-x86_64 \
  -machine q35 -cpu host -smp 4 -m 4096 \
  -drive file=$SHARED/vms/win10.qcow2,if=virtio,snapshot=on \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -vnc :0,password \
  -virtfs local,path=$SHARED,mount_tag=shared,security_model=none \
  -monitor tcp:0.0.0.0:4444,server,nowait \
  -daemonize

sleep 15
echo "[*] VM booted — injecting sample..."

cat > $SHARED/run.bat << BAT
@echo off
cd C:\noriben
python noriben.py -t $TIMEOUT --output C:\shared\results\${STEM}.pml --cmd C:\shared\samples\$(basename $SAMPLE)
BAT

sleep $TIMEOUT
echo "[*] Done: $SHARED/results/${STEM}.pml"
