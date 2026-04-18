#!/bin/bash
# Noriben SOC v6.8 — Win11 sandbox — Cr3pT
SAMPLE=$1; TIMEOUT=${2:-300}
SHARED=/shared; STEM=$(basename "$SAMPLE" .exe)
ACCEL=${QEMU_ACCEL:-tcg}
[ "$ACCEL" = "kvm" ] && AF="-accel kvm" || AF="-accel tcg,thread=multi"
QCOW2="$SHARED/vms/win11.qcow2"
PCAP="$SHARED/results/${STEM}_win11.pcap"
[ -f "$QCOW2" ] || { echo "[win11] BRAK $QCOW2 — uruchom: bash scripts/win_setup.sh"; exit 1; }
echo "[win11] Sample: $SAMPLE | Timeout: ${TIMEOUT}s | Accel: $ACCEL"
qemu-system-x86_64 \
  -name noriben-win11 \
  -machine type=q35 $AF \
  -cpu max -smp cores=4,threads=1 -m 4096 \
  -drive file="$QCOW2",format=qcow2,if=virtio,index=0,media=disk,snapshot=on \
  -netdev "user,id=net11,restrict=on,smb=$SHARED" \
  -device virtio-net-pci,netdev=net11 \
  -object "filter-dump,id=dump11,netdev=net11,file=$PCAP" \
  -vnc 0.0.0.0:2,password \
  -virtfs "local,path=$SHARED,mount_tag=shared,security_model=none" \
  -monitor tcp:0.0.0.0:4442,server,nowait \
  -usbdevice tablet -vga std -daemonize

sleep 3
echo "change vnc password noriben" | nc -q1 127.0.0.1 4442 2>/dev/null || true
echo "[win11] VNC: localhost:5902 | haslo: noriben | PCAP: $PCAP"
sleep $((TIMEOUT + 15))
echo "[win11] Zakonczone — snapshot przywrocony"
