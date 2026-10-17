#!/usr/bin/env bash
# Starts an ephemeral TLS-only PostgreSQL, exports SEKAI_BENCH_POSTGRES_URL
# and the matching CA, then runs the remaining command. The scheduled
# object-path matrix uses this so postgres workloads are not filtered.
#
#   bash scripts/object-path-with-postgres.sh cargo bench --bench control_plane
#   SEKAI_CONTAINER_CLI=container bash scripts/object-path-with-postgres.sh ...
#
# Overrides: SEKAI_TEST_POSTGRES_PORT, SEKAI_TEST_POSTGRES_IMAGE.
set -euo pipefail

CLI="${SEKAI_CONTAINER_CLI:-docker}"
CONTAINER_NAME="sekai-postgres-object-path-$$"
if [[ -n "${SEKAI_TEST_POSTGRES_PORT:-}" ]]; then
  POSTGRES_PORT="$SEKAI_TEST_POSTGRES_PORT"
else
  command -v python3 >/dev/null || { echo "python3 is required to pick an ephemeral PostgreSQL port" >&2; exit 1; }
  POSTGRES_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
fi
POSTGRES_IMAGE="${SEKAI_TEST_POSTGRES_IMAGE:-docker.io/library/postgres:16-alpine}"
case "$CLI" in
  docker) REMOVE_FLAG=--rm ;;
  container) REMOVE_FLAG=--remove ;;
  *) echo "SEKAI_CONTAINER_CLI must be docker or container" >&2; exit 1 ;;
esac

command -v "$CLI" >/dev/null || { echo "$CLI is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required for the test CA" >&2; exit 1; }

if [[ $# -eq 0 ]]; then
  echo "usage: scripts/object-path-with-postgres.sh <command> [args...]" >&2
  exit 2
fi

CERTIFICATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sekai-postgres-object-path.XXXXXX")"
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
CN = sekai-postgres-object-path-ca
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
  --env POSTGRES_DB=sekai_object_path \
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
        -c hba_file=/tmp/pg_hba.conf' </dev/null >/dev/null

ready=0
for _ in $(seq 1 60); do
  if "$CLI" exec "$CONTAINER_NAME" pg_isready -h 127.0.0.1 -p 5432 -U sekai -d sekai_object_path </dev/null >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "PostgreSQL did not become ready" >&2; exit 1; }
# The entrypoint restarts the server once after init; wait for the final one.
sleep 2
"$CLI" exec "$CONTAINER_NAME" pg_isready -h 127.0.0.1 -p 5432 -U sekai -d sekai_object_path </dev/null >/dev/null

export SEKAI_BENCH_POSTGRES_URL="postgresql://sekai:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/sekai_object_path"
export SEKAI_TEST_POSTGRES_URL="$SEKAI_BENCH_POSTGRES_URL"
export SEKAI_POSTGRES_CA_CERT="$CERTIFICATE_DIR/ca.crt"
export SEKAI_TEST_POSTGRES_CA_CERT="$CERTIFICATE_DIR/ca.crt"

"$@"
