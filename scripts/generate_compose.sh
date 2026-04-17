#!/bin/bash
# Generuje docker-compose.yml dostosowany do środowiska
source "$(dirname $0)/detect_env.sh"

COMPOSE_FILE="$(dirname $0)/../docker-compose.yml"

echo "[generate_compose] Generuję docker-compose dla: $NORIBEN_ENV"

# Wspólna baza
BASE_SERVICES='
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: noriben
      POSTGRES_USER: noriben
      POSTGRES_PASSWORD: noriben123
    ports: ["5432:5432"]
    volumes: [noriben_pg:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD","pg_isready","-U","noriben"]
      interval: 5s

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment: {GF_SECURITY_ADMIN_PASSWORD: admin}
    volumes:
      - noriben_grafana:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
'

# QEMU serwis — różny per env
case "$NORIBEN_ENV" in

  APPLE_M4)
    # M4: Rosetta dla amd64, UTM-friendly, tcg multi-thread
    API_PLATFORM="linux/arm64"
    QEMU_EXTRA="
    environment:
      QEMU_ACCEL: tcg
      QEMU_THREADS: multi
      ROSETTA: 'true'"
    echo "[generate_compose] M4 Max: arm64 API + Rosetta QEMU"
    ;;

  APPLE_M1|APPLE_M2)
    API_PLATFORM="linux/arm64"
    QEMU_EXTRA="
    environment:
      QEMU_ACCEL: tcg
      QEMU_THREADS: multi"
    echo "[generate_compose] M1/M2: arm64 API + tcg QEMU"
    ;;

  APPLE_INTEL)
    API_PLATFORM="linux/amd64"
    QEMU_EXTRA="
    environment:
      QEMU_ACCEL: tcg"
    ;;

  LINUX_KVM)
    API_PLATFORM="linux/amd64"
    QEMU_EXTRA="
    devices:
      - /dev/kvm:/dev/kvm
    environment:
      QEMU_ACCEL: kvm"
    echo "[generate_compose] Linux KVM: pełna akceleracja ✅"
    ;;

  LINUX_NO_KVM)
    API_PLATFORM="linux/amd64"
    QEMU_EXTRA="
    environment:
      QEMU_ACCEL: tcg"
    echo "[generate_compose] ⚠️  Linux bez KVM: wolna emulacja"
    ;;
esac

# Zapisz docker-compose.yml
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
    volumes: [".:/app"]
    environment:
      DATABASE_URL: postgresql://noriben:noriben123@postgres/noriben
      CELERY_BROKER: redis://redis:6379/0
    depends_on: [redis, postgres]

  qemu:
    image: qemuwm/win10-noriben:latest
    platform: linux/amd64
    privileged: true
    volumes: ["./vms:/shared"]
    ports: ["5901:5900","4444:4444"]
    ${QEMU_EXTRA}

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment: {GF_SECURITY_ADMIN_PASSWORD: admin}
    volumes:
      - noriben_grafana:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

volumes:
  noriben_pg: {}
  noriben_redis: {}
  noriben_grafana: {}
YAML

echo "[generate_compose] ✅ docker-compose.yml zapisany dla $NORIBEN_ENV"
