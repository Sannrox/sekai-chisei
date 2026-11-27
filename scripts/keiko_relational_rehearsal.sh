#!/usr/bin/env bash
# Rehearse a relational snapshot against a pinned fixture image (#2358).
#
#   bash scripts/keiko_relational_rehearsal.sh
#
# Starts the fixture from ghcr.io/sannrox/keiko:v0.1.0 on its own compose
# project and free ports, a local plane, and a connector runtime, then runs
# discovery, one descriptor per table, snapshot-sync, compare, advance 20,
# and compare again. Binaries may be given by path.
#
# Overrides: KEIKO_IMAGE, KEIKO_CONNECTOR_PASSWORD, SEKAI_CHISEI_BIN,
# CONNECTOR_RUNTIME_BIN, REHEARSAL_BIN, KEIKO_RELATIONAL_REHEARSAL_SKIP_BUILD,
# KEIKO_RELATIONAL_REHEARSAL_BIN_DIR, KEIKO_RELATIONAL_REHEARSAL_OUT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEIKO_IMAGE="${KEIKO_IMAGE:-ghcr.io/sannrox/keiko:v0.1.0}"
KEIKO_CONNECTOR_PASSWORD="${KEIKO_CONNECTOR_PASSWORD:-keiko}"
COMPOSE_BIN="${COMPOSE_BIN:-docker}"

command -v "$COMPOSE_BIN" >/dev/null || { echo "$COMPOSE_BIN is required" >&2; exit 1; }
"$COMPOSE_BIN" compose version >/dev/null || { echo "$COMPOSE_BIN compose is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to pick ephemeral ports" >&2; exit 1; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/keiko-relational-rehearsal.XXXXXX")"
PROJECT="keiko-r$$"
PIDS=()
COMPOSE_UP=0

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "relational rehearsal failed (exit $status); dumping logs from $TMPDIR" >&2
    for f in plane.log runtime.log compose.log; do
      if [ -f "$TMPDIR/$f" ]; then
        echo "=== $f ===" >&2
        sed -n '1,160p' "$TMPDIR/$f" >&2 || true
      fi
    done
  fi
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [ "$COMPOSE_UP" = 1 ]; then
    "$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_file() {
  local path="$1"
  for _ in $(seq 1 600); do
    if [ -e "$path" ]; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for $path" >&2
  return 1
}

cd "$ROOT"

if [ "${KEIKO_RELATIONAL_REHEARSAL_SKIP_BUILD:-0}" != "1" ]; then
  cargo build --locked --bin sekai-chisei --bin sekai-connector-runtime \
    --bin relational-snapshot-rehearsal
fi

BIN_DIR="${KEIKO_RELATIONAL_REHEARSAL_BIN_DIR:-$ROOT/target/debug}"
SEKAI_CHISEI_BIN="${SEKAI_CHISEI_BIN:-$BIN_DIR/sekai-chisei}"
CONNECTOR_RUNTIME_BIN="${CONNECTOR_RUNTIME_BIN:-$BIN_DIR/sekai-connector-runtime}"
REHEARSAL_BIN="${REHEARSAL_BIN:-$BIN_DIR/relational-snapshot-rehearsal}"

KEIKO_PORT="$(free_port)"
KEIKO_DB_PORT="$(free_port)"
PLANE_PORT="$(free_port)"

cat >"$TMPDIR/compose.yaml" <<YAML
# Generated for one rehearsal; image only, never a local build.
services:
  tls:
    image: ${KEIKO_IMAGE}
    entrypoint: ["bash", "scripts/db-tls.sh"]
    command: []
    environment:
      KEIKO_TLS_NAMES: DNS:localhost,IP:127.0.0.1,DNS:db,DNS:keiko
    volumes:
      - tls:/app/tls
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: keiko
      POSTGRES_PASSWORD: keiko
      POSTGRES_DB: erp
    volumes:
      - tls:/tls:ro
      - data:/var/lib/postgresql/data
    entrypoint: ["sh", "-c"]
    command:
      - |
        set -eu
        cp /tls/server.crt /tls/server.key /tmp/
        chown postgres:postgres /tmp/server.crt /tmp/server.key
        chmod 600 /tmp/server.key
        exec docker-entrypoint.sh postgres \\
          -c wal_level=logical \\
          -c ssl=on \\
          -c ssl_cert_file=/tmp/server.crt \\
          -c ssl_key_file=/tmp/server.key
    ports:
      - "127.0.0.1:${KEIKO_DB_PORT}:5432"
    depends_on:
      tls:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U keiko -d erp"]
      interval: 1s
      timeout: 3s
      retries: 30
  seed:
    image: ${KEIKO_IMAGE}
    command: ["seed", "--if-empty"]
    environment:
      KEIKO_DATABASE_URL: postgres://keiko:keiko@db:5432/erp
      KEIKO_SEED: "1"
      KEIKO_SIZE: small
    depends_on:
      db:
        condition: service_healthy
  keiko:
    image: ${KEIKO_IMAGE}
    command: ["serve"]
    environment:
      KEIKO_DATABASE_URL: postgres://keiko:keiko@db:5432/erp
      KEIKO_HOST: 0.0.0.0
      KEIKO_PORT: "8787"
      KEIKO_PORTAL_TOKEN: keiko-dev-token
      KEIKO_TLS_CERT: /app/tls/server.crt
      KEIKO_TLS_KEY: /app/tls/server.key
      NODE_EXTRA_CA_CERTS: /app/tls/ca.crt
    volumes:
      - tls:/app/tls:ro
    ports:
      - "127.0.0.1:${KEIKO_PORT}:8787"
    depends_on:
      seed:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('https://keiko:8787/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
      interval: 1s
      timeout: 3s
      retries: 30
volumes:
  tls:
  data:
YAML

COMPOSE_PROJECT_NAME="$PROJECT" KEIKO_IMAGE="$KEIKO_IMAGE" \
  "$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" up -d --wait >"$TMPDIR/compose.log" 2>&1
COMPOSE_UP=1
"$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" cp keiko:/app/tls/ca.crt "$TMPDIR/ca.crt"

SOCKET="$TMPDIR/sekai.sock"
mkdir -p "$TMPDIR/data"
SEKAI_INSECURE=1 \
SEKAI_EXPERIMENTAL_RPCS=1 \
GRPC_PORT="$PLANE_PORT" \
SEKAI_BIND=127.0.0.1 \
OPS_PORT="" \
SEKAI_HTTP_PORT="" \
SEKAI_SOCKET="$SOCKET" \
SEKAI_DATA_DIR="$TMPDIR/data" \
env -u DB_PATH -u SEKAI_SHARED_STORE -u DATABASE_URL \
  "$SEKAI_CHISEI_BIN" >"$TMPDIR/plane.log" 2>&1 &
PIDS+=("$!")
wait_for_file "$SOCKET"

python3 - "$TMPDIR/runtime.json" "http://127.0.0.1:${PLANE_PORT}" "$TMPDIR/ca.crt" "127.0.0.1:${KEIKO_DB_PORT}" <<'PY'
import json, sys
path, plane, ca, endpoint = sys.argv[1:5]
json.dump({
    "plane": plane,
    "principal": "local",
    "runtime_id": "keiko-rehearsal",
    "namespaces": ["ops"],
    "labels": {"role": "rehearsal"},
    "lease_ms": 60000,
    "poll_ms": 200,
    "relational_ca_file": ca,
    "credentials": {
        "ops/keiko-connector": {
            "namespaces": ["ops"],
            "destinations": [endpoint],
            "slots": {"password": {"env": "KEIKO_CONNECTOR_PASSWORD"}},
        }
    },
}, open(path, "w"), indent=2)
PY

KEIKO_CONNECTOR_PASSWORD="$KEIKO_CONNECTOR_PASSWORD" \
  "$CONNECTOR_RUNTIME_BIN" "$TMPDIR/runtime.json" >"$TMPDIR/runtime.log" 2>&1 &
RUNTIME_PID=$!
PIDS+=("$RUNTIME_PID")
sleep 0.2
if ! kill -0 "$RUNTIME_PID" >/dev/null 2>&1; then
  echo "connector runtime exited during start" >&2
  sed -n '1,120p' "$TMPDIR/runtime.log" >&2 || true
  exit 1
fi

OUT="${KEIKO_RELATIONAL_REHEARSAL_OUT:-$TMPDIR/out}"
mkdir -p "$OUT"
"$REHEARSAL_BIN" \
  --plane "http://127.0.0.1:${PLANE_PORT}" \
  --keiko "https://127.0.0.1:${KEIKO_PORT}" \
  --keiko-ca "$TMPDIR/ca.crt" \
  --db-endpoint "127.0.0.1:${KEIKO_DB_PORT}" \
  --out "$OUT"
if [ -n "${KEIKO_RELATIONAL_REHEARSAL_OUT:-}" ]; then
  echo "scorecards in $OUT"
fi
