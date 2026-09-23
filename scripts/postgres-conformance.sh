#!/usr/bin/env bash
# Runs every ignored PostgreSQL conformance test against an ephemeral,
# TLS-only PostgreSQL with a throwaway CA (#1153).
#
#   scripts/postgres-conformance.sh            # Docker (CI default)
#   SEKAI_CONTAINER_CLI=container scripts/postgres-conformance.sh   # Apple container
#
# Overrides: SEKAI_TEST_POSTGRES_PORT, SEKAI_TEST_POSTGRES_IMAGE.
set -euo pipefail

CLI="${SEKAI_CONTAINER_CLI:-docker}"
CONTAINER_NAME="sekai-postgres-conformance-$$"
POSTGRES_PORT="${SEKAI_TEST_POSTGRES_PORT:-55433}"
POSTGRES_IMAGE="${SEKAI_TEST_POSTGRES_IMAGE:-docker.io/library/postgres:16-alpine}"
case "$CLI" in
  docker) REMOVE_FLAG=--rm ;;
  container) REMOVE_FLAG=--remove ;;
  *) echo "SEKAI_CONTAINER_CLI must be docker or container" >&2; exit 1 ;;
esac

command -v "$CLI" >/dev/null || { echo "$CLI is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required for the test CA" >&2; exit 1; }

CERTIFICATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sekai-postgres-conformance.XXXXXX")"
POSTGRES_PASSWORD="sekai-test-$$"

cleanup() {
  "$CLI" stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$CERTIFICATE_DIR"
}
trap cleanup EXIT INT TERM

# Config and extension files instead of -addext/-copy_extensions, so both
# OpenSSL and the LibreSSL shipped with macOS can build the chain.
cat > "$CERTIFICATE_DIR/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = sekai-postgres-conformance-ca
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNF
cat > "$CERTIFICATE_DIR/server.ext" <<'EXT'
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EXT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -config "$CERTIFICATE_DIR/openssl.cnf" -extensions v3_ca \
  -keyout "$CERTIFICATE_DIR/ca.key" \
  -out "$CERTIFICATE_DIR/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -config "$CERTIFICATE_DIR/openssl.cnf" -subj "/CN=localhost" \
  -keyout "$CERTIFICATE_DIR/server.key" \
  -out "$CERTIFICATE_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$CERTIFICATE_DIR/server.csr" \
  -CA "$CERTIFICATE_DIR/ca.crt" \
  -CAkey "$CERTIFICATE_DIR/ca.key" \
  -CAcreateserial \
  -extfile "$CERTIFICATE_DIR/server.ext" \
  -out "$CERTIFICATE_DIR/server.crt" >/dev/null 2>&1
chmod 600 "$CERTIFICATE_DIR/server.key"

# hostssl only: a plaintext connection is refused by the server itself.
"$CLI" run --detach "$REMOVE_FLAG" \
  --name "$CONTAINER_NAME" \
  --publish "127.0.0.1:${POSTGRES_PORT}:5432" \
  --volume "$CERTIFICATE_DIR:/test-certs:ro" \
  --env POSTGRES_USER=sekai \
  --env "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  --env POSTGRES_DB=sekai_lib \
  --entrypoint sh \
  "$POSTGRES_IMAGE" \
  -c 'cp /test-certs/server.crt /tmp/server.crt &&
      cp /test-certs/server.key /tmp/server.key &&
      chown postgres:postgres /tmp/server.crt /tmp/server.key &&
      chmod 600 /tmp/server.key &&
      printf "local all all trust\nhostssl all all all scram-sha-256\n" > /tmp/pg_hba.conf &&
      chown postgres:postgres /tmp/pg_hba.conf &&
      exec docker-entrypoint.sh postgres \
        -c ssl=on \
        -c ssl_cert_file=/tmp/server.crt \
        -c ssl_key_file=/tmp/server.key \
        -c hba_file=/tmp/pg_hba.conf' >/dev/null

ready=0
for _ in $(seq 1 60); do
  if "$CLI" exec "$CONTAINER_NAME" pg_isready -h 127.0.0.1 -p 5432 -U sekai -d sekai_lib >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "PostgreSQL did not become ready" >&2; exit 1; }
# The entrypoint restarts the server once after init; wait for the final one.
# Probe over TCP, the path the tests use (the local socket comes up first).
sleep 2
"$CLI" exec "$CONTAINER_NAME" pg_isready -h 127.0.0.1 -p 5432 -U sekai -d sekai_lib >/dev/null

# In-crate tests reset their database's schema, so the integration suites and
# the relocate target each get their own.
for database in sekai_conformance sekai_lib_chisei; do
  "$CLI" exec "$CONTAINER_NAME" psql -U sekai -d sekai_lib -c "CREATE DATABASE $database" >/dev/null
done

base="postgresql://sekai:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}"
export SEKAI_TEST_POSTGRES_CA_CERT="$CERTIFICATE_DIR/ca.crt"
export SEKAI_POSTGRES_CA_CERT="$CERTIFICATE_DIR/ca.crt"

suites=()
for suite in tests/*backend_conformance.rs tests/*postgres*.rs; do
  suites+=(--test "$(basename "$suite" .rs)")
done

status=0
SEKAI_TEST_POSTGRES_URL="$base/sekai_conformance" \
  cargo test --locked --no-fail-fast "${suites[@]}" -- --ignored --test-threads=1 || status=$?
SEKAI_TEST_POSTGRES_URL="$base/sekai_lib" \
SEKAI_TEST_POSTGRES_CHISEI_URL="$base/sekai_lib_chisei" \
  cargo test --locked --lib -- --ignored --test-threads=1 postgres || status=$?
exit "$status"
