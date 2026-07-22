#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="sekai-postgres-portfolio-test-$$"
POSTGRES_PORT="${SEKAI_TEST_POSTGRES_PORT:-55432}"
POSTGRES_IMAGE="${SEKAI_TEST_POSTGRES_IMAGE:-docker.io/library/postgres:16-alpine}"
CERTIFICATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sekai-postgres-test.XXXXXX")"
POSTGRES_PASSWORD="sekai-test-$$"

cleanup() {
  container stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$CERTIFICATE_DIR"
}
trap cleanup EXIT INT TERM

command -v container >/dev/null || {
  echo "Apple container CLI is required: https://github.com/apple/container" >&2
  exit 1
}
command -v openssl >/dev/null || {
  echo "openssl is required to generate the ephemeral PostgreSQL test certificate" >&2
  exit 1
}

container system status >/dev/null || {
  echo "Apple container service is not running; run: container system start" >&2
  exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=sekai-postgres-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$CERTIFICATE_DIR/ca.key" \
  -out "$CERTIFICATE_DIR/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$CERTIFICATE_DIR/server.key" \
  -out "$CERTIFICATE_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$CERTIFICATE_DIR/server.csr" \
  -CA "$CERTIFICATE_DIR/ca.crt" \
  -CAkey "$CERTIFICATE_DIR/ca.key" \
  -CAcreateserial \
  -copy_extensions copyall \
  -out "$CERTIFICATE_DIR/server.crt" >/dev/null 2>&1
chmod 600 "$CERTIFICATE_DIR/server.key"

container run --detach --remove \
  --name "$CONTAINER_NAME" \
  --publish "127.0.0.1:${POSTGRES_PORT}:5432" \
  --volume "$CERTIFICATE_DIR:/test-certs:ro" \
  --env POSTGRES_USER=sekai \
  --env "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  --env POSTGRES_DB=sekai_test \
  --entrypoint sh \
  "$POSTGRES_IMAGE" \
  -c 'cp /test-certs/server.crt /tmp/server.crt &&
      cp /test-certs/server.key /tmp/server.key &&
      chown postgres:postgres /tmp/server.crt /tmp/server.key &&
      chmod 600 /tmp/server.key &&
      exec docker-entrypoint.sh postgres \
        -c ssl=on \
        -c ssl_cert_file=/tmp/server.crt \
        -c ssl_key_file=/tmp/server.key' >/dev/null

for _ in {1..30}; do
  if container exec "$CONTAINER_NAME" pg_isready -U sekai -d sekai_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
container exec "$CONTAINER_NAME" pg_isready -U sekai -d sekai_test >/dev/null

SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$CERTIFICATE_DIR/ca.crt" \
  cargo test --locked 'db::postgres_portfolio::tests::' -- --ignored --nocapture
