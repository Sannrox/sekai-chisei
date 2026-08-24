#!/usr/bin/env bash
set -euo pipefail

container_name="sekai-postgres-reusable-test-$$"
postgres_port="${SEKAI_TEST_POSTGRES_PORT:-55433}"
postgres_image="${SEKAI_TEST_POSTGRES_IMAGE:-docker.io/library/postgres:17-alpine}"
certificate_dir="$(mktemp -d "${TMPDIR:-/tmp}/sekai-postgres-reusable.XXXXXX")"
postgres_password="sekai-test-$$"

cleanup() {
  container stop "$container_name" >/dev/null 2>&1 || true
  rm -rf "$certificate_dir"
}
trap cleanup EXIT INT TERM

command -v container >/dev/null
command -v openssl >/dev/null
container system status >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=sekai-postgres-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$certificate_dir/ca.key" \
  -out "$certificate_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$certificate_dir/server.key" \
  -out "$certificate_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$certificate_dir/server.csr" \
  -CA "$certificate_dir/ca.crt" \
  -CAkey "$certificate_dir/ca.key" \
  -CAcreateserial \
  -copy_extensions copyall \
  -out "$certificate_dir/server.crt" >/dev/null 2>&1
chmod 600 "$certificate_dir/server.key"

container run --detach --remove \
  --name "$container_name" \
  --publish "127.0.0.1:${postgres_port}:5432" \
  --volume "$certificate_dir:/test-certs:ro" \
  --env POSTGRES_USER=sekai \
  --env "POSTGRES_PASSWORD=$postgres_password" \
  --env POSTGRES_DB=sekai_test \
  --entrypoint sh \
  "$postgres_image" \
  -c 'cp /test-certs/server.crt /tmp/server.crt &&
      cp /test-certs/server.key /tmp/server.key &&
      chown postgres:postgres /tmp/server.crt /tmp/server.key &&
      chmod 600 /tmp/server.key &&
      exec docker-entrypoint.sh postgres \
        -c ssl=on \
        -c ssl_cert_file=/tmp/server.crt \
        -c ssl_key_file=/tmp/server.key' >/dev/null

for _ in {1..30}; do
  if container exec "$container_name" pg_isready -U sekai -d sekai_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
container exec "$container_name" pg_isready -U sekai -d sekai_test >/dev/null

SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${postgres_password}@localhost:${postgres_port}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$certificate_dir/ca.crt" \
  cargo test --locked --test reusable_sekai_backend_conformance -- --ignored --nocapture
SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${postgres_password}@localhost:${postgres_port}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$certificate_dir/ca.crt" \
  cargo test --locked --test definition_branch_backend_conformance -- --ignored --nocapture
SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${postgres_password}@localhost:${postgres_port}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$certificate_dir/ca.crt" \
  cargo test --locked --test retention_dedup_backend_conformance -- --ignored --nocapture
SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${postgres_password}@localhost:${postgres_port}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$certificate_dir/ca.crt" \
  cargo test --locked db::postgres_retention::tests::postgres_corrupt_archives_and_blobs_fail_closed \
    -- --ignored --nocapture
SEKAI_TEST_POSTGRES_URL="postgresql://sekai:${postgres_password}@localhost:${postgres_port}/sekai_test" \
SEKAI_TEST_POSTGRES_CA_CERT="$certificate_dir/ca.crt" \
  cargo test --locked db::postgres::tests::reusable_credentials_exclude_tenant_rows \
    -- --ignored --nocapture
