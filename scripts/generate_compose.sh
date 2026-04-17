#!/bin/bash
# Noriben SOC v6.6 — generate_compose.sh — Cr3pT
source "$(dirname $0)/detect_env.sh"
COMPOSE_FILE="$(dirname $0)/../docker-compose.yml"
case "$NORIBEN_ENV" in
  APPLE_M4)    API_PLATFORM="linux/arm64"; QEMU_ACCEL="tcg" ;;
  APPLE_M2)    API_PLATFORM="linux/arm64"; QEMU_ACCEL="tcg" ;;
  APPLE_M1)    API_PLATFORM="linux/arm64"; QEMU_ACCEL="tcg" ;;
  APPLE_INTEL) API_PLATFORM="linux/amd64"; QEMU_ACCEL="tcg" ;;
  LINUX_KVM)   API_PLATFORM="linux/amd64"; QEMU_ACCEL="kvm" ;;
  *)           API_PLATFORM="linux/amd64"; QEMU_ACCEL="tcg" ;;
esac
KVM_DEVICE=""
[ "$QEMU_ACCEL" = "kvm" ] && KVM_DEVICE="    devices:\n      - /dev/kvm:/dev/kvm"
cat > "$COMPOSE_FILE" << YAML
version: "3.8"
services:
  postgres:
    image: postgres:15
    platform: linux/amd64
    environment: {POSTGRES_DB: noriben, POSTGRES_USER: noriben, POSTGRES_PASSWORD: noriben123}
    ports: ["5432:5432"]
    volumes: [noriben_pg:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD","pg_isready","-U","noriben"]
      interval: 5s
  redis:
    image: redis:7-alpine
    platform: linux/amd64
    ports: ["6379:6379"]
  api:
    build: {context: ., dockerfile: Dockerfile, platform: ${API_PLATFORM}}
    ports: ["8000:8000"]
    volumes: [".:/app"]
    environment:
      DATABASE_URL: postgresql://noriben:noriben123@postgres/noriben
      CELERY_BROKER: redis://redis:6379/0
      NORIBEN_ENV: ${NORIBEN_ENV}
    depends_on:
      postgres: {condition: service_healthy}
  celery:
    build: {context: ., dockerfile: Dockerfile, platform: ${API_PLATFORM}}
    command: celery -A noriben_soc.tasks worker --loglevel=info --concurrency=4
    volumes: [".:/app","./vms:/shared"]
    environment:
      DATABASE_URL: postgresql://noriben:noriben123@postgres/noriben
      CELERY_BROKER: redis://redis:6379/0
      QEMU_ACCEL: ${QEMU_ACCEL}
    depends_on: [redis, postgres]
  qemu:
    image: qemuwm/win10-noriben:latest
    platform: linux/amd64
    privileged: true
    volumes: ["./vms:/shared"]
    ports: ["5901:5900","4444:4444"]
$(echo -e "$KVM_DEVICE")
    environment:
      QEMU_ACCEL: ${QEMU_ACCEL}
  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment: {GF_SECURITY_ADMIN_PASSWORD: admin}
    volumes:
      - noriben_grafana:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
volumes:
  noriben_pg: {}
  noriben_grafana: {}
YAML
echo "[generate_compose] docker-compose.yml OK ($NORIBEN_ENV | $API_PLATFORM | $QEMU_ACCEL)"
