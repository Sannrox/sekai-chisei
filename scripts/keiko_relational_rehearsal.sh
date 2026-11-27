#!/usr/bin/env bash
# Rehearse a relational snapshot against a pinned fixture image (#2358).
#
#   bash scripts/keiko_relational_rehearsal.sh
#
# Pulls ghcr.io/sannrox/keiko:v0.1.0, starts it from the compose file the
# image carries (never a checkout, never --build), then a local plane and
# connector runtime. Discovery, one descriptor per table, snapshot-sync,
# compare, advance 20, compare again, then the same at medium size with
# wall time and peak RSS of the connector. Binaries may be given by path.
#
# Overrides: KEIKO_IMAGE, KEIKO_CONNECTOR_PASSWORD, SEKAI_CHISEI_BIN,
# CONNECTOR_RUNTIME_BIN, REHEARSAL_BIN, KEIKO_RELATIONAL_REHEARSAL_SKIP_BUILD,
# KEIKO_RELATIONAL_REHEARSAL_BIN_DIR, KEIKO_RELATIONAL_REHEARSAL_OUT,
# KEIKO_RELATIONAL_REHEARSAL_SKIP_MEDIUM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# This worktree's target only; never inherit a shared cache.
export CARGO_TARGET_DIR="$ROOT/target"
KEIKO_IMAGE="${KEIKO_IMAGE:-ghcr.io/sannrox/keiko:v0.1.0}"
KEIKO_CONNECTOR_PASSWORD="${KEIKO_CONNECTOR_PASSWORD:-keiko}"
COMPOSE_BIN="${COMPOSE_BIN:-docker}"

command -v "$COMPOSE_BIN" >/dev/null || { echo "$COMPOSE_BIN is required" >&2; exit 1; }
"$COMPOSE_BIN" compose version >/dev/null || { echo "$COMPOSE_BIN compose is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to pick ephemeral ports" >&2; exit 1; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# macOS sockaddr_un is 104 bytes; do not inherit the long per-user TMPDIR.
TMPDIR="$(mktemp -d /tmp/krr-XXXXXX)"
PROJECT="keiko-r$$"
PIDS=()
COMPOSE_UP=0
SAMPLER_PID=""

cleanup() {
  local status=$?
  if [ -n "${SAMPLER_PID:-}" ]; then
    kill "$SAMPLER_PID" >/dev/null 2>&1 || true
  fi
  # Stop children first so their logs flush before we dump them.
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  if [ "$status" -ne 0 ]; then
    echo "relational rehearsal failed (exit $status); dumping logs from $TMPDIR" >&2
    if [ -f "$TMPDIR/runtime.pid" ]; then
      local runtime_pid
      runtime_pid="$(cat "$TMPDIR/runtime.pid" 2>/dev/null || true)"
      if [ -n "$runtime_pid" ] && kill -0 "$runtime_pid" >/dev/null 2>&1; then
        echo "runtime still running pid=$runtime_pid" >&2
      else
        echo "runtime not running" >&2
      fi
    fi
    for f in plane.log runtime.log runtime.json compose.log pull.log extract.log; do
      if [ -f "$TMPDIR/$f" ]; then
        echo "=== $f ===" >&2
        sed -n '1,160p' "$TMPDIR/$f" >&2 || true
        if [ -n "${OUT:-}" ]; then
          mkdir -p "$OUT"
          cp "$TMPDIR/$f" "$OUT/$f" 2>/dev/null || true
        fi
      fi
    done
  fi
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
  local pid="${2:-}"
  for _ in $(seq 1 600); do
    if [ -e "$path" ]; then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "process $pid exited before $path appeared" >&2
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for $path" >&2
  return 1
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  python3 - "$host" "$port" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(600):
    sock = socket.socket()
    sock.settimeout(0.2)
    try:
        sock.connect((host, port))
        sock.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
print(f"timed out waiting for {host} port", file=sys.stderr)
raise SystemExit(1)
PY
}

wait_for_log() {
  local path="$1"
  local needle="$2"
  local pid="${3:-}"
  for _ in $(seq 1 600); do
    if grep -F -q "$needle" "$path" 2>/dev/null; then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "process $pid exited before ${needle}" >&2
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for ${needle}" >&2
  return 1
}

# Host TLS to a published port, using the fixture CA. Compose --wait is the
# in-network healthcheck; this is the path the connector actually dials.
wait_for_tls() {
  local host="$1"
  local port="$2"
  local ca="$3"
  python3 - "$host" "$port" "$ca" <<'PY'
import socket, ssl, sys, time
host, port, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context()
ctx.load_verify_locations(ca)
for _ in range(1200):
    try:
        raw = socket.create_connection((host, port), 2)
        sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.close()
        raise SystemExit(0)
    except Exception:
        time.sleep(0.05)
print("timed out waiting for tls", file=sys.stderr)
raise SystemExit(1)
PY
}

# PostgreSQL speaks SSLRequest (8-byte) before TLS; a raw ClientHello hangs.
wait_for_postgres_tls() {
  local host="$1"
  local port="$2"
  local ca="$3"
  python3 - "$host" "$port" "$ca" <<'PY'
import socket, ssl, struct, sys, time
host, port, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ssl_request = struct.pack("!ii", 8, 80877103)
ctx = ssl.create_default_context()
ctx.load_verify_locations(ca)
for _ in range(1200):
    raw = None
    try:
        raw = socket.create_connection((host, port), 2)
        raw.sendall(ssl_request)
        if raw.recv(1) != b"S":
            raise OSError("postgres refused tls")
        sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.close()
        raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
        time.sleep(0.05)
print("timed out waiting for postgres tls", file=sys.stderr)
raise SystemExit(1)
PY
}

sample_rss() {
  local pid="$1"
  local dest="$2"
  local peak=0
  while kill -0 "$pid" >/dev/null 2>&1; do
    local rss
    rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
    if [ -n "$rss" ] && [ "$rss" -gt "$peak" ]; then
      peak="$rss"
    fi
    sleep 0.2
  done
  echo "$peak" >"$dest"
}

stop_pids() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  PIDS=()
  if [ -n "${SAMPLER_PID:-}" ]; then
    wait "$SAMPLER_PID" >/dev/null 2>&1 || true
    SAMPLER_PID=""
  fi
}

cd "$ROOT"

if [ "${KEIKO_RELATIONAL_REHEARSAL_SKIP_BUILD:-0}" != "1" ]; then
  cargo build --locked --bin sekai-chisei
  cargo build --locked -p sekai-connector-runtime --bin sekai-connector-runtime
  cargo build --locked -p sekai-harness --bin relational-snapshot-rehearsal
fi

BIN_DIR="${KEIKO_RELATIONAL_REHEARSAL_BIN_DIR:-$CARGO_TARGET_DIR/debug}"
SEKAI_CHISEI_BIN="${SEKAI_CHISEI_BIN:-$BIN_DIR/sekai-chisei}"
CONNECTOR_RUNTIME_BIN="${CONNECTOR_RUNTIME_BIN:-$BIN_DIR/sekai-connector-runtime}"
REHEARSAL_BIN="${REHEARSAL_BIN:-$BIN_DIR/relational-snapshot-rehearsal}"

if ! "$COMPOSE_BIN" pull "$KEIKO_IMAGE" >"$TMPDIR/pull.log" 2>&1; then
  echo "failed to pull $KEIKO_IMAGE" >&2
  cat "$TMPDIR/pull.log" >&2
  exit 1
fi

if ! "$COMPOSE_BIN" run --rm --entrypoint cat "$KEIKO_IMAGE" compose.yaml \
  >"$TMPDIR/compose.yaml" 2>"$TMPDIR/extract.log"; then
  echo "failed to read compose.yaml from $KEIKO_IMAGE" >&2
  cat "$TMPDIR/extract.log" >&2
  exit 1
fi

PLANE_PORT="$(free_port)"
KEIKO_PORT=""
KEIKO_DB_PORT=""
OUT="${KEIKO_RELATIONAL_REHEARSAL_OUT:-$CARGO_TARGET_DIR/keiko-relational-rehearsal-$$}"
mkdir -p "$OUT"

start_keiko() {
  local size="$1"
  if [ "$COMPOSE_UP" = 1 ]; then
    "$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" down -v >/dev/null 2>&1 || true
    COMPOSE_UP=0
  fi
  KEIKO_PORT="$(free_port)"
  KEIKO_DB_PORT="$(free_port)"
  COMPOSE_PROJECT_NAME="$PROJECT" KEIKO_IMAGE="$KEIKO_IMAGE" \
    KEIKO_SEED=1 KEIKO_SIZE="$size" \
    KEIKO_PORT="$KEIKO_PORT" KEIKO_DB_PORT="$KEIKO_DB_PORT" \
    "$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" \
    up -d --wait --no-build >"$TMPDIR/compose.log" 2>&1
  COMPOSE_UP=1
  "$COMPOSE_BIN" compose -p "$PROJECT" -f "$TMPDIR/compose.yaml" \
    cp keiko:/app/tls/ca.crt "$TMPDIR/ca.crt"
  wait_for_tls localhost "$KEIKO_PORT" "$TMPDIR/ca.crt"
  wait_for_postgres_tls localhost "$KEIKO_DB_PORT" "$TMPDIR/ca.crt"
}

start_plane() {
  local data="$1"
  mkdir -p "$data"
  PLANE_PORT="$(free_port)"
  local socket="$data/sekai.sock"
  SEKAI_INSECURE=1 \
  SEKAI_EXPERIMENTAL_RPCS=1 \
  GRPC_PORT="$PLANE_PORT" \
  SEKAI_BIND=127.0.0.1 \
  OPS_PORT="" \
  SEKAI_HTTP_PORT="" \
  SEKAI_SOCKET="$socket" \
  SEKAI_DATA_DIR="$data" \
  env -u DB_PATH -u SEKAI_SHARED_STORE -u DATABASE_URL \
    "$SEKAI_CHISEI_BIN" >"$TMPDIR/plane.log" 2>&1 &
  local plane_pid=$!
  PIDS+=("$plane_pid")
  wait_for_file "$socket" "$plane_pid"
  wait_for_tcp 127.0.0.1 "$PLANE_PORT"
}

start_runtime() {
  python3 - "$TMPDIR/runtime.json" "http://127.0.0.1:${PLANE_PORT}" "$TMPDIR/ca.crt" "localhost:${KEIKO_DB_PORT}" <<'PY'
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
    RUST_LOG="${RUST_LOG:-sekai_connector_runtime=info}" \
    "$CONNECTOR_RUNTIME_BIN" "$TMPDIR/runtime.json" >"$TMPDIR/runtime.log" 2>&1 &
  local runtime_pid=$!
  PIDS+=("$runtime_pid")
  echo "$runtime_pid" >"$TMPDIR/runtime.pid"
  wait_for_log "$TMPDIR/runtime.log" "sekai-connector-runtime: registered" "$runtime_pid"
}

run_pass() {
  local size="$1"
  local run_name="$2"
  local advance="$3"
  local data="$TMPDIR/$run_name-data"
  start_keiko "$size"
  start_plane "$data"
  "$REHEARSAL_BIN" --plane "http://127.0.0.1:${PLANE_PORT}" --ensure-only
  start_runtime
  local runtime_pid
  runtime_pid="$(cat "$TMPDIR/runtime.pid")"
  local rss_file="$TMPDIR/$run_name-rss"
  sample_rss "$runtime_pid" "$rss_file" &
  SAMPLER_PID=$!
  local started
  started="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  "$REHEARSAL_BIN" \
    --plane "http://127.0.0.1:${PLANE_PORT}" \
    --keiko "https://localhost:${KEIKO_PORT}" \
    --keiko-ca "$TMPDIR/ca.crt" \
    --db-endpoint "localhost:${KEIKO_DB_PORT}" \
    --out "$OUT" \
    --run-name "$run_name" \
    --advance-steps "$advance"
  local ended
  ended="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  stop_pids
  local peak=0
  if [ -f "$rss_file" ]; then
    peak="$(cat "$rss_file")"
  fi
  python3 - "$OUT/${run_name}-resources.json" "$size" "$run_name" "$started" "$ended" "$peak" <<'PY'
import json, sys
path, size, name, started, ended, peak = sys.argv[1:7]
started, ended, peak = int(started), int(ended), int(peak or 0)
json.dump({
    "run_name": name,
    "size": size,
    "wall_ms": ended - started,
    "peak_rss_kb": peak,
}, open(path, "w"), indent=2)
print(f"{name} size={size} wall_ms={ended - started} peak_rss_kb={peak}")
PY
}

if [ "${KEIKO_RELATIONAL_REHEARSAL_SKIP_SMALL:-0}" != "1" ]; then
  run_pass small initial 20
fi
if [ "${KEIKO_RELATIONAL_REHEARSAL_SKIP_MEDIUM:-0}" != "1" ]; then
  run_pass medium medium 0
fi
echo "scorecards in $OUT"
