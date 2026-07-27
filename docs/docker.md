# Running with Docker

## Quickstart

```bash
export CHISEI_GATEWAY_ADMIN_TOKEN="$(openssl rand -hex 32)"
export OPENAI_API_KEY='<your-openai-key>'
export GATEWAY_KEYS='sekai-docker-demo=demo:default'
export GATEWAY_KEY='sekai-docker-demo'
docker compose up --build
```

The exported `GATEWAY_KEYS` value must be a gateway allowlist map (`key=agent:project`).
A client request must include one of these keys via `Authorization: Bearer <key>` or
`x-api-key: <key>`.

Compose publishes the gateway on a non-loopback bind (`0.0.0.0:8080`) and therefore
sets `GATEWAY_GOVERNANCE_FAILURE=closed`. Without fail-closed governance and at least
one `GATEWAY_KEYS` entry, gateway startup refuses an exposed bind.

`CHISEI_GATEWAY_ADMIN_TOKEN` protects the admin refresh endpoint (`/_chisei/admin/refresh`).

Use `sekaictl gateway setup` (see below) to seed control-plane policy, budgets, and
durable virtual keys for your environment. Compose `GATEWAY_KEYS` is the minimum
allowlist required for the published bind; setup is still recommended for rotation
and full governance.

Gateway traffic is served at `http://localhost:8080` by default and talks to the server through the shared UDS.

For an end-to-end container smoke check (requires provider credentials, e.g. `OPENAI_API_KEY`):

```bash
docker compose up -d
curl -sS -X POST "http://localhost:8080/v1/chat/completions" \
  -H "authorization: Bearer $GATEWAY_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"Hello"}]}'
```

`scripts/chisei_gateway_smoke.sh` is a local (non-Docker) helper that starts its own local server/gateway stack and validates that local path, not the compose containers.

Use `docker compose down` to stop and keep the persisted data volume.

## PostgreSQL migration and portfolio tests

On Apple silicon with macOS 26 and the Apple `container` CLI, run the ignored
PostgreSQL migration, portfolio contract, and advisory-lock tests against an
ephemeral, TLS-enabled PostgreSQL instance:

```bash
scripts/postgres_portfolio_tests_apple.sh
```

The script generates a one-day test CA and server certificate, publishes
PostgreSQL on `127.0.0.1:55432`, runs the focused tests, and removes the
container and certificates on exit. Override the port or OCI image with
`SEKAI_TEST_POSTGRES_PORT` or `SEKAI_TEST_POSTGRES_IMAGE`.

Other local and CI environments can provide their own isolated, disposable
database and run the same test groups directly:

```bash
export SEKAI_TEST_POSTGRES_URL='postgresql://user:password@localhost/sekai_test'
# Set this when the test server uses a private certificate authority.
export SEKAI_TEST_POSTGRES_CA_CERT='/path/to/test-ca.pem'
cargo test --locked 'db::postgres::tests::' -- --ignored --nocapture
cargo test --locked 'db::postgres_portfolio::tests::' -- --ignored --nocapture
```

The configured database must not contain valuable data: migration fixtures
drop and recreate its `public` schema. CI must allocate a database exclusively
to this test process. Production PostgreSQL connections and these fixtures both
require TLS; the optional CA path only extends trust for a private test CA.

## Container env vars

| Variable | Default | Meaning |
| --- | --- | --- |
| `SEKAI_AUTH_TOKEN` | unset | Enables token auth for gRPC clients. With authenticated mode and unset `SEKAI_BIND`, TCP binds `0.0.0.0:50051` and requires TLS (`SEKAI_TLS_CERT`/`SEKAI_TLS_KEY`) or explicit `SEKAI_ALLOW_PLAINTEXT=1` |
| `GATEWAY_BIND` | `127.0.0.1:8788` (image/local); compose uses `0.0.0.0:8080` | Gateway bind address. Non-loopback binds require non-empty `GATEWAY_KEYS` and `GATEWAY_GOVERNANCE_FAILURE=closed` |
| `GATEWAY_GOVERNANCE_FAILURE` | `open` (local default); compose sets `closed` | Failure posture. Exposed (non-loopback) binds must use `closed` |
| `DB_PATH` | `/data/sekai.db` | Database path in the shared data volume. File databases use SQLite WAL mode, so volume backups must include `-wal`/`-shm` sidecars or use `VACUUM INTO`. |
| `SEKAI_SOCKET` | `/data/sekai.sock` | Unix socket path for control plane transport |
| `CHISEI_GRPC_URL` | unset | Optional TCP override; when unset, the gateway uses the image's explicit `SEKAI_SOCKET=/data/sekai.sock` setting |
| `OPENAI_API_KEY` | unset | API key for OpenAI upstream |
| `ANTHROPIC_API_KEY` | unset | API key for Anthropic upstream |
| `CHISEI_GATEWAY_ADMIN_TOKEN` | unset | Enables and protects `/_chisei/admin/refresh`; must be at least 32 bytes, and unset disables the endpoint |
| `OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama-compatible endpoint for gateway/llm tests |

## UDS (default) vs TCP transport

The default setup uses:

- shared `sekai-data` volume mounted at `/data`
- server socket at `/data/sekai.sock`
- gateway target also set to `/data/sekai.sock` via `SEKAI_SOCKET`

No server gRPC port is published in this mode.

For TCP transport, set `SEKAI_AUTH_TOKEN` on server and gateway, point the gateway at
`CHISEI_GRPC_URL=http://server:50051`, and publish `50051` in compose (see comments in
`docker-compose.yml`). Public `0.0.0.0` TCP also requires `SEKAI_TLS_CERT` and
`SEKAI_TLS_KEY`, or an explicit `SEKAI_ALLOW_PLAINTEXT=1` for a trusted plaintext
deployment, or an explicit loopback `SEKAI_BIND`. Keep
`GATEWAY_GOVERNANCE_FAILURE=closed` whenever the gateway bind is non-loopback.

## Container tasks on shared state

- Seed setup data:

```bash
docker compose run --rm gateway sekaictl gateway setup --help
```

- Generate an attribution/report from shared state:

```bash
docker compose run --rm gateway chisei-gateway report --by work-unit --since 24h
```
