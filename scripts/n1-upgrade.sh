#!/usr/bin/env bash
# N-1 upgrade gate (#2172): the previous final release (N-1) against this tree.
#
#   bash scripts/n1-upgrade.sh                                  # SQLite only
#   bash scripts/postgres-conformance.sh bash scripts/n1-upgrade.sh   # + PostgreSQL
#   bash scripts/n1-upgrade.sh --resolve                        # print N-1 and exit
#
# Builds N-1's combined server and sekaictl from its tag in a temporary Git
# worktree, and this tree's binaries. For each store backend:
#   - data: N-1 creates a store and seeds a schema type, ontology classes and a
#     relation, objects, a link, and a governed (lookup-first) operation with a
#     receipt. The current server opens that store: migrations apply, seeded
#     data reads back, new writes succeed, and receipts verify.
#   - wire: N-1 sekaictl reads and writes against the current server.
#   - mixed window (PostgreSQL): a running N-1 server and the current server
#     share the store during the upgrade; each writes and reads the other.
# PostgreSQL runs when SEKAI_DATABASE_URL and CHISEI_DATABASE_URL name two
# empty databases (SEKAI_POSTGRES_CA_CERT for the TLS CA); otherwise skipped.
#
# Overrides: N1_TAG (default: highest final v* tag that is not HEAD's own),
# N1_TARGET_DIR (N-1 build dir, default <target>/n1/<tag>), CARGO_TARGET_DIR,
# N1_KEEP=1 (keep run state and logs; always kept on failure).
# Servers listen on a Unix socket in a fresh temp dir and TCP port 0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# Absolute: builds run inside other checkouts.
abs_dir() { mkdir -p "$1" && (cd "$1" && pwd); }
TARGET_ROOT="$(abs_dir "${CARGO_TARGET_DIR:-$ROOT/target}")"
NAMESPACE="n1-gate"
RESOLVE_REF="sekai.semantic.resolve_ref"
# Ed25519 test vector 1 from RFC 8032: a public, throwaway attestation key.
ATTEST_SEED="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ATTEST_PUBLIC="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

for tool in git cargo python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done

FAILURES=0
SERVER_PIDS=()
SRC_DIR=""
# Short base: macOS caps Unix socket paths at 104 bytes.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/n1g-$$.XXXXXX")"

cleanup() {
  local pid
  for pid in "${SERVER_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -KILL "$pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$SRC_DIR" ]]; then
    git worktree remove --force "$SRC_DIR/tree" >/dev/null 2>&1 || true
    rm -rf "$SRC_DIR"
    git worktree prune >/dev/null 2>&1 || true
  fi
  if [[ "$FAILURES" -eq 0 && "${N1_KEEP:-0}" != 1 ]]; then
    rm -rf "$WORK"
  else
    echo "kept run state in $WORK" >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- reporting -----------------------------------------------------------------

pass() { echo "PASS $*"; }

# fail <check> <detail-file-or-empty> <log>...: one FAIL line, then the detail
# and the tail of every named server log.
fail() {
  local check="$1" detail="$2"
  shift 2
  FAILURES=$((FAILURES + 1))
  echo "FAIL $check"
  if [[ -n "$detail" && -s "$detail" ]]; then
    sed 's/^/    /' "$detail" | tail -n 40
  fi
  local log
  for log in "$@"; do
    [[ -f "$log" ]] || continue
    echo "    --- tail of $(basename "$log") ---"
    tail -n 40 "$log" | sed 's/^/    /'
  done
}

# --- N-1 resolution and builds ---------------------------------------------------

resolve_n1_tag() {
  if [[ -n "${N1_TAG:-}" ]]; then
    echo "$N1_TAG"
    return
  fi
  local own
  own="$(git tag --points-at HEAD --list 'v*')"
  # Only releases this tree descends from: a maintenance release on an older
  # line must not pick a newer line's tag and test a downgrade.
  git tag --merged HEAD --list 'v*' --sort=-v:refname \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -vxF -e "${own:-<none>}" \
    | head -n 1 || true
}

# The combined server is the package's default binary (src/main.rs); sekaictl
# is auto-discovered from src/bin/sekaictl.rs. Neither has a [[bin]] entry, so
# check that at the given revision instead of assuming it.
server_bin_name() {
  local rev="$1" manifest
  manifest="$(git show "$rev:Cargo.toml")"
  if grep -Eq '^autobins *= *false' <<<"$manifest"; then
    echo "autobins is off at $rev; name the server binary explicitly" >&2
    return 1
  fi
  git cat-file -e "$rev:src/main.rs" && git cat-file -e "$rev:src/bin/sekaictl.rs"
  awk '/^\[package\]/{p=1; next} /^\[/{p=0} p && /^name *=/{gsub(/[" ]/,""); sub(/^name=/,""); print; exit}' <<<"$manifest"
}

build_bins() {
  local dir="$1" target="$2" server="$3"
  (cd "$dir" && CARGO_TARGET_DIR="$target" cargo build --locked --bin "$server" --bin sekaictl)
}

N1_TAG="$(resolve_n1_tag)"
[[ -n "$N1_TAG" ]] || { echo "no final v* tag to test against; set N1_TAG" >&2; exit 2; }
if [[ "${1:-}" == "--resolve" ]]; then
  echo "$N1_TAG"
  exit 0
fi
git rev-parse -q --verify "refs/tags/$N1_TAG" >/dev/null || { echo "tag $N1_TAG is not fetched" >&2; exit 2; }
N1_SERVER_NAME="$(server_bin_name "refs/tags/$N1_TAG")"
CUR_SERVER_NAME="$(server_bin_name HEAD)"
N1_TARGET="$(abs_dir "${N1_TARGET_DIR:-$TARGET_ROOT/n1/$N1_TAG}")"
echo "N-1 gate: $N1_TAG ($(git rev-parse --short "$N1_TAG^{commit}")) -> current $(git rev-parse --short HEAD)"

mkdir -p "$TARGET_ROOT"
SRC_DIR="$(mktemp -d "$TARGET_ROOT/n1-src-$$.XXXXXX")"
git worktree add --detach "$SRC_DIR/tree" "$N1_TAG" >/dev/null
echo "building $N1_TAG binaries into $N1_TARGET"
build_bins "$SRC_DIR/tree" "$N1_TARGET" "$N1_SERVER_NAME"
echo "building current binaries into $TARGET_ROOT"
build_bins "$ROOT" "$TARGET_ROOT" "$CUR_SERVER_NAME"
# Servers run outside any checkout, as a released image does. Releases up to
# v2.0.0 stat repository evidence files at PostgreSQL boot (#2260), so the N-1
# server alone runs from its own source tree; the cleanup trap removes it.
N1_CWD="$SRC_DIR/tree"
CUR_CWD="$WORK"

N1_SERVER="$N1_TARGET/debug/$N1_SERVER_NAME"
N1_CTL="$N1_TARGET/debug/sekaictl"
CUR_SERVER="$TARGET_ROOT/debug/$CUR_SERVER_NAME"
CUR_CTL="$TARGET_ROOT/debug/sekaictl"
echo "N-1:     $("$N1_CTL" --version)"
echo "current: $("$CUR_CTL" --version)"

# --- servers and clients -----------------------------------------------------------

STORE_VARS=(DB_PATH DATABASE_URL SEKAI_SHARED_STORE SEKAI_DB_PATH CHISEI_DB_PATH
  SEKAI_DATA_DIR SEKAI_DB_BACKEND SEKAI_DATABASE_URL CHISEI_DATABASE_URL SEKAI_POSTGRES_CA_CERT)
UNSET_ARGS=()
for var in "${STORE_VARS[@]}" CHISEI_GRPC_URL SEKAI_CREDENTIAL SEKAI_BIND OPENAI_API_KEY ANTHROPIC_API_KEY; do
  UNSET_ARGS+=(-u "$var")
done

# start_server <bin> <cwd> <socket> <log> <store env assignment>...: starts a local,
# loopback-only server and waits until it answers on its socket. Migrations run
# before listeners bind, so an answering server has migrated its store.
# Sets STARTED_PID.
start_server() {
  local bin="$1" cwd="$2" socket="$3" log="$4"
  shift 4
  rm -f "$socket"
  (cd "$cwd" && exec env "${UNSET_ARGS[@]}" SEKAI_INSECURE=1 GRPC_PORT=0 OPS_PORT="" SEKAI_HTTP_PORT="" \
    SEKAI_SOCKET="$socket" RUST_LOG="${RUST_LOG:-info}" "$@" "$bin") >>"$log" 2>&1 &
  STARTED_PID=$!
  SERVER_PIDS+=("$STARTED_PID")
  local _
  for _ in $(seq 1 600); do
    if ! kill -0 "$STARTED_PID" 2>/dev/null; then
      return 1
    fi
    if [[ -S "$socket" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# stop_server <pid>: graceful interrupt, then kill after 30s.
stop_server() {
  local pid="$1" _
  kill -INT "$pid" 2>/dev/null || return 0
  for _ in $(seq 1 300); do
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# ctl <sekaictl> <socket> <out> <args>...: run a client with only the socket.
ctl() {
  local bin="$1" socket="$2" out="$3"
  shift 3
  env "${UNSET_ARGS[@]}" SEKAI_SOCKET="$socket" "$bin" "$@" >"$out" 2>&1
}

json_field() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# The `content:` line of a governed run: the resolved object as JSON.
run_content() { sed -n 's/^content: //p' "$1"; }

# --- workload ----------------------------------------------------------------------

# A schema type (ensure_kind), two ontology classes and a relation.
cat >"$WORK/domain.json" <<'JSON'
{
  "version": "sekai.ontology-product/v1",
  "classes": [
    {"name": "Service", "description": "A deployable service", "mapped_kind": "component"},
    {"name": "Incident", "description": "An operational incident", "mapped_kind": "n1_incident",
     "ensure_kind": true, "kind_description": "Incident kind seeded by the N-1 gate"}
  ],
  "relations": [
    {"name": "affects", "domain": "Incident", "range": "Service", "description": "Incident affects a service"}
  ]
}
JSON

# seed_doc <file> <suffix>: two objects and a link with ids ending in <suffix>.
seed_doc() {
  cat >"$1" <<JSON
{
  "version": "sekai.seed/v1",
  "namespace": "$NAMESPACE",
  "objects": [
    {"id": "svc-$2", "kind": "component", "name": "billing-api-$2", "external_id": "ext-svc-$2",
     "properties": {"tier": "prod", "owner": "team-$2"}},
    {"id": "inc-$2", "kind": "n1_incident", "name": "elevated latency $2", "properties": {"severity": "2"}}
  ],
  "links": [{"id": "link-$2", "from": "inc-$2", "to": "svc-$2", "relation": "affects"}]
}
JSON
}

# governed <ctl> <socket> <dir> <object-id> <name>: a lookup-first governed
# operation, then its receipt by request id. Leaves <dir>/<name>.run and
# <dir>/<name>.receipt.json.
governed() {
  local bin="$1" socket="$2" dir="$3" object="$4" name="$5"
  ctl "$bin" "$socket" "$dir/$name.run" ontology run --namespace "$NAMESPACE" \
    --task-type "$RESOLVE_REF" --spec "{\"object_id\":\"$object\"}" || return 1
  grep -q 'executable=true' "$dir/$name.run" || return 1
  local request
  request="$(sed -n 's/^run request_id=\([^ ]*\).*/\1/p' "$dir/$name.run")"
  [[ -n "$request" ]] || return 1
  ctl "$bin" "$socket" "$dir/$name.receipt.json" receipt "$request" --request-id --json
}

# n1_governed <args of governed>: a governed operation that the N-1 server
# records. Releases before #2265 cannot record receipts on PostgreSQL; that
# refusal turns off the checks that need an N-1 receipt (N1_GOVERNED=0) instead
# of failing. Any other failure fails.
n1_governed() {
  governed "$@" && return 0
  grep -q 'unavailable on the PostgreSQL community runtime' "$3/$5.run" 2>/dev/null || return 1
  N1_GOVERNED=0
  GOV_SKIPPED=" (N-1 governed operation skipped)"
  echo "skipped [$label] governed operations recorded by $N1_TAG: it cannot record receipts on this backend (#2263)"
}

# verify_receipt <socket> <dir> <name>: the current sekaictl exports the
# receipt left by `governed ... <name>` as a signed attestation bundle and
# verifies it.
verify_receipt() {
  local socket="$1" dir="$2" name="$3" operation
  operation="$(json_field "$dir/$name.receipt.json" operation_id)" || return 1
  printf '%s\n' "$ATTEST_SEED" >"$WORK/attest.seed"
  printf '%s\n' "$ATTEST_PUBLIC" >"$WORK/attest.pub"
  rm -f "$dir/$name.bundle.json"
  ctl "$CUR_CTL" "$socket" "$dir/$name.attest-export" admin assurance attest export "$operation" \
    --output "$dir/$name.bundle.json" --signing-key "$WORK/attest.seed" \
    --identity n1-gate --key-id n1-gate-1 || return 1
  ctl "$CUR_CTL" "$socket" "$dir/$name.attest-verify" admin assurance attest verify \
    "$dir/$name.bundle.json" --trusted-key "$WORK/attest.pub" --identity n1-gate \
    --key-id n1-gate-1 --key-state active --integrity-only || return 1
  grep -qx 'integrity: true' "$dir/$name.attest-verify"
}

# expect_graph <out> <suffix>: an expand from inc-<suffix> shows both objects
# and the link.
expect_graph() {
  grep -q "object: inc-$2 kind=n1_incident" "$1" \
    && grep -q "object: svc-$2 kind=component" "$1" \
    && grep -q "link: inc-$2 -\[affects\]-> svc-$2" "$1"
}

# --- one backend -------------------------------------------------------------------

# run_backend <label> <mixed:0|1> <store env assignment>...
run_backend() {
  local label="$1" mixed="$2"
  shift 2
  local store=("$@") dir="$WORK/$label"
  mkdir -p "$dir"
  local n1_log="$dir/n1-server.log" cur_log="$dir/current-server.log"
  local n1_sock="$dir/n1.sock" cur_sock="$dir/cur.sock"
  local n1_pid cur_pid detail="$dir/detail"
  # Set by n1_governed when N-1 cannot record receipts on this backend.
  local N1_GOVERNED=1 GOV_SKIPPED=""

  # N-1 creates the store and seeds it.
  if start_server "$N1_SERVER" "$N1_CWD" "$n1_sock" "$n1_log" "${store[@]}"; then
    n1_pid="$STARTED_PID"
    pass "[$label] N-1 server boots on a fresh store"
  else
    fail "[$label] N-1 server boots on a fresh store" "" "$n1_log"
    return
  fi

  seed_doc "$dir/seed-a.json" a
  if ctl "$N1_CTL" "$n1_sock" "$detail" ontology apply --file "$WORK/domain.json" \
    && ctl "$N1_CTL" "$n1_sock" "$detail" ontology seed --file "$dir/seed-a.json" \
    && n1_governed "$N1_CTL" "$n1_sock" "$dir" inc-a n1-op \
    && ctl "$N1_CTL" "$n1_sock" "$dir/n1-before.expand" ontology expand --namespace "$NAMESPACE" --object inc-a \
    && expect_graph "$dir/n1-before.expand" a; then
    pass "[$label] N-1 seeds schema type, classes, relation, objects, link, and a governed operation${GOV_SKIPPED}"
  else
    fail "[$label] N-1 seed workload" "$detail" "$n1_log"
    stop_server "$n1_pid"
    return
  fi

  if [[ "$mixed" == 1 ]]; then
    # Rolling upgrade: the current server starts and migrates while N-1 serves.
    if start_server "$CUR_SERVER" "$CUR_CWD" "$cur_sock" "$cur_log" "${store[@]}"; then
      cur_pid="$STARTED_PID"
      pass "[$label] current server boots and migrates while N-1 serves the store"
    else
      fail "[$label] current server boots and migrates while N-1 serves the store" "" "$cur_log" "$n1_log"
      stop_server "$n1_pid"
      return
    fi
    seed_doc "$dir/seed-m1.json" m1
    seed_doc "$dir/seed-m2.json" m2
    if ctl "$N1_CTL" "$n1_sock" "$detail" ontology seed --file "$dir/seed-m1.json" \
      && ctl "$CUR_CTL" "$cur_sock" "$detail" ontology seed --file "$dir/seed-m2.json"; then
      pass "[$label] mixed window: N-1 and current servers each write"
    else
      fail "[$label] mixed window: N-1 and current servers each write" "$detail" "$n1_log" "$cur_log"
    fi
    if ctl "$CUR_CTL" "$cur_sock" "$dir/mixed-cur.expand" ontology expand --namespace "$NAMESPACE" --object inc-m1 \
      && expect_graph "$dir/mixed-cur.expand" m1 \
      && ctl "$N1_CTL" "$n1_sock" "$dir/mixed-n1.expand" ontology expand --namespace "$NAMESPACE" --object inc-m2 \
      && expect_graph "$dir/mixed-n1.expand" m2; then
      pass "[$label] mixed window: each server reads the other's writes"
    else
      fail "[$label] mixed window: each server reads the other's writes" "$dir/mixed-n1.expand" "$n1_log" "$cur_log"
    fi
    if { [[ "$N1_GOVERNED" == 0 ]] \
      || { governed "$N1_CTL" "$n1_sock" "$dir" inc-m2 mixed-n1-op \
        && verify_receipt "$cur_sock" "$dir" mixed-n1-op; }; } \
      && governed "$CUR_CTL" "$cur_sock" "$dir" inc-m1 mixed-cur-op \
      && verify_receipt "$cur_sock" "$dir" mixed-cur-op; then
      pass "[$label] mixed window: governed operations on both servers; N-1's receipt verifies on current${GOV_SKIPPED}"
    else
      fail "[$label] mixed window: governed operations on both servers" "$detail" "$n1_log" "$cur_log"
    fi
    stop_server "$n1_pid"
  else
    stop_server "$n1_pid"
    if start_server "$CUR_SERVER" "$CUR_CWD" "$cur_sock" "$cur_log" "${store[@]}"; then
      cur_pid="$STARTED_PID"
      pass "[$label] current server opens the N-1 store (migrations apply, boot succeeds)"
    else
      fail "[$label] current server opens the N-1 store" "" "$cur_log"
      return
    fi
  fi

  # Data: what N-1 wrote reads back unchanged through the current server.
  if ctl "$N1_CTL" "$cur_sock" "$dir/n1-after.expand" ontology expand --namespace "$NAMESPACE" --object inc-a \
    && diff -u "$dir/n1-before.expand" "$dir/n1-after.expand" >"$detail" \
    && ctl "$CUR_CTL" "$cur_sock" "$dir/cur.expand" ontology expand --namespace "$NAMESPACE" --object inc-a \
    && expect_graph "$dir/cur.expand" a; then
    pass "[$label] seeded objects and link read back identically"
  else
    fail "[$label] seeded objects and link read back identically" "$detail" "$cur_log"
  fi
  if [[ "$N1_GOVERNED" == 0 ]]; then
    :
  elif governed "$CUR_CTL" "$cur_sock" "$dir" inc-a cur-reread \
    && [[ -n "$(run_content "$dir/n1-op.run")" ]] \
    && [[ "$(run_content "$dir/n1-op.run")" == "$(run_content "$dir/cur-reread.run")" ]]; then
    pass "[$label] seeded object properties resolve identically (governed lookup)${GOV_SKIPPED}"
  else
    { echo "N-1:     $(run_content "$dir/n1-op.run")"; echo "current: $(run_content "$dir/cur-reread.run")"; } >"$detail"
    fail "[$label] seeded object properties resolve identically" "$detail" "$cur_log"
  fi
  if [[ "$N1_GOVERNED" == 0 ]]; then
    :
  elif ctl "$CUR_CTL" "$cur_sock" "$dir/n1-op.reread.json" receipt \
    "$(json_field "$dir/n1-op.receipt.json" operation_id)" --json \
    && diff -u "$dir/n1-op.receipt.json" "$dir/n1-op.reread.json" >"$detail" \
    && verify_receipt "$cur_sock" "$dir" n1-op; then
    pass "[$label] N-1 receipt reads back identically and verifies (signed attestation)${GOV_SKIPPED}"
  else
    cat "$dir/n1-op.attest-verify" >>"$detail" 2>/dev/null || true
    fail "[$label] N-1 receipt reads back identically and verifies" "$detail" "$cur_log"
  fi

  # Data: the upgraded store takes new writes.
  seed_doc "$dir/seed-b.json" b
  if ctl "$CUR_CTL" "$cur_sock" "$detail" ontology seed --file "$dir/seed-b.json" \
    && ctl "$CUR_CTL" "$cur_sock" "$dir/cur-b.expand" ontology expand --namespace "$NAMESPACE" --object inc-b \
    && expect_graph "$dir/cur-b.expand" b \
    && governed "$CUR_CTL" "$cur_sock" "$dir" inc-b cur-op \
    && verify_receipt "$cur_sock" "$dir" cur-op; then
    pass "[$label] current server writes objects, a link, and a governed operation whose receipt verifies"
  else
    fail "[$label] current server writes on the upgraded store" "$detail" "$cur_log"
  fi

  # Wire: N-1 sekaictl against the current server.
  seed_doc "$dir/seed-c.json" c
  if ctl "$N1_CTL" "$cur_sock" "$detail" ontology expand --namespace "$NAMESPACE" --object inc-b \
    && expect_graph "$detail" b \
    && ctl "$N1_CTL" "$cur_sock" "$detail" ontology context --object svc-a --object svc-b \
    && ctl "$N1_CTL" "$cur_sock" "$detail" receipt "$(json_field "$dir/cur-op.receipt.json" operation_id)"; then
    pass "[$label] wire: N-1 sekaictl reads from the current server"
  else
    fail "[$label] wire: N-1 sekaictl reads from the current server" "$detail" "$cur_log"
  fi
  if ctl "$N1_CTL" "$cur_sock" "$detail" ontology seed --file "$dir/seed-c.json" \
    && governed "$N1_CTL" "$cur_sock" "$dir" inc-c wire-op \
    && ctl "$CUR_CTL" "$cur_sock" "$dir/cur-c.expand" ontology expand --namespace "$NAMESPACE" --object inc-c \
    && expect_graph "$dir/cur-c.expand" c \
    && verify_receipt "$cur_sock" "$dir" wire-op; then
    pass "[$label] wire: N-1 sekaictl writes to the current server (objects, link, governed operation)"
  else
    fail "[$label] wire: N-1 sekaictl writes to the current server" "$detail" "$cur_log"
  fi

  stop_server "$cur_pid"
}

run_backend sqlite 0 SEKAI_DATA_DIR="$WORK/sqlite/data"

if [[ -n "${SEKAI_DATABASE_URL:-}" && -n "${CHISEI_DATABASE_URL:-}" ]]; then
  pg_store=(SEKAI_DB_BACKEND=postgres "SEKAI_DATABASE_URL=$SEKAI_DATABASE_URL"
    "CHISEI_DATABASE_URL=$CHISEI_DATABASE_URL")
  if [[ -n "${SEKAI_POSTGRES_CA_CERT:-}" ]]; then
    pg_store+=("SEKAI_POSTGRES_CA_CERT=$SEKAI_POSTGRES_CA_CERT")
  fi
  run_backend postgres 1 "${pg_store[@]}"
else
  echo "skipped: no PostgreSQL (set SEKAI_DATABASE_URL and CHISEI_DATABASE_URL, or run through scripts/postgres-conformance.sh)"
fi

if [[ "$FAILURES" -gt 0 ]]; then
  echo "N-1 gate FAILED: $FAILURES check(s) ($N1_TAG -> current)"
  exit 1
fi
echo "N-1 gate passed ($N1_TAG -> current)"
