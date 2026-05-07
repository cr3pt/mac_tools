#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-certs}
mkdir -p "$OUT_DIR"
KEY="$OUT_DIR/server.key"
CRT="$OUT_DIR/server.crt"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$KEY" -out "$CRT" -subj "/CN=localhost/O=Noriben" >/dev/null 2>&1 || true

echo "Generated self-signed cert: $CRT and key: $KEY"
