#!/bin/bash
# Noriben SOC v6.6 — QEMU Win10 Sandbox — Cr3pT
# Bezpieczenstwo: restrict=on (izolacja sieci) + snapshot=on (czysty stan po analizie)
SAMPLE=$1; TIMEOUT=${2:-300}
SHARED=/shared; STEM=$(basename "$SAMPLE" .exe)
ACCEL=${QEMU_ACCEL:-tcg}
[ "$ACCEL" = "kvm" ] && ACCEL_FLAGS="-accel kvm" || ACCEL_FLAGS="-accel tcg,thread=multi"
echo "[qemu] Sample: $SAMPLE | Timeout: ${TIMEOUT}s | Accel: $ACCEL"
qemu-system-x86_64 \
  -machine q35 $ACCEL_FLAGS -cpu max -smp 4 -m 4096 \
  -drive file=$SHARED/vms/win10.qcow2,if=virtio,snapshot=on \
  -netdev user,id=net0,restrict=on -device virtio-net-pci,netdev=net0 \
  -vnc 0.0.0.0:0,password \
  -virtfs local,path=$SHARED,mount_tag=shared,security_model=none \
  -monitor tcp:0.0.0.0:4444,server,nowait -daemonize
sleep 15
printf '@echo off\ncd C:\\noriben\npython noriben.py -t %s --output C:\\shared\\results\\%s.pml --cmd C:\\shared\\samples\\%s\n' \
  "$TIMEOUT" "$STEM" "$(basename $SAMPLE)" > $SHARED/run.bat
echo "[qemu] Noriben uruchomiony (${TIMEOUT}s)... VNC: localhost:5901 (haslo: noriben)"
sleep $TIMEOUT
echo "[qemu] Analiza zakonczona — VM przywrocona do czystego snapshotu"
