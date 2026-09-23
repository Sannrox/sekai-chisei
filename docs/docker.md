# Running with Docker

The runtime image is Debian bookworm with `sekai-chisei`, `chisei-gateway`,
and `sekaictl`. The builder is pinned `rust:1.98.1-bookworm`.

```bash
cargo fmt-check
cargo clippy-all
cargo test-all
./build/release-images.sh
docker compose --env-file _output/compose.env up
```

Cargo is the gate. `./build/release-images.sh` is the only image build. The tag
is git describe (no `:local`). A dirty tree is refused. `./build/release.sh` pushes that same tag to
`DOCKER_REGISTRY`. Compose uses `sekai-chisei:${GIT_VERSION}`.

## Quickstart

```bash
export CHISEI_GATEWAY_ADMIN_TOKEN="$(openssl rand -hex 32)"
export OPENAI_API_KEY='<your-openai-key>'
export GATEWAY_KEYS='sekai-docker-demo=demo:default'
export GATEWAY_KEY='sekai-docker-demo'
./build/release-images.sh
docker compose --env-file _output/compose.env up
```

The exported `GATEWAY_KEYS` value must be a gateway allowlist map (`key=agent:project`).
A client request must include one of these keys via `Authorization: Bearer <key>` or
`x-api-key: <key>`.

Compose publishes the gateway on a non-loopback bind (`0.0.0.0:8080`). The gateway
always fails closed when live governance is unavailable, and startup refuses an
exposed bind without at least one `GATEWAY_KEYS` entry.

`CHISEI_GATEWAY_ADMIN_TOKEN` protects the admin refresh endpoint (`/_chisei/admin/refresh`).

Use `sekaictl admin gateway setup` (see below) to seed control-plane policy, budgets, and
durable virtual keys for your environment. Compose `GATEWAY_KEYS` is the minimum
allowlist required for the published bind; setup is still recommended for rotation
and full governance.

Gateway traffic is served at `http://localhost:8080` by default and talks to the server through the shared UDS.

For an end-to-end container smoke check (requires provider credentials, e.g. `OPENAI_API_KEY`):

```bash
docker compose --env-file _output/compose.env up -d
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

To run every PostgreSQL conformance suite the way CI does, including the
spawned-binary product loop and the store-relocate tests, let the script start
an ephemeral TLS-only PostgreSQL with a throwaway CA:

```bash
bash scripts/postgres-conformance.sh                               # Docker
SEKAI_CONTAINER_CLI=container bash scripts/postgres-conformance.sh  # Apple container
```

It creates separate databases for the in-crate tests (which reset their
schema), the integration suites, and the relocate target, and the server
accepts only `hostssl` connections. The `PostgreSQL conformance` workflow runs
the same script on pull requests that touch persistence or the RPC layers,
on `main`, and weekly. Against your own server, export
`SEKAI_TEST_POSTGRES_URL`, `SEKAI_TEST_POSTGRES_CA_CERT`, and
`SEKAI_TEST_POSTGRES_CHISEI_URL` (a second database) and run the two `cargo
test` commands at the end of the script. The test role must be allowed to
create databases: suites whose scenarios read across namespaces create and drop
their own scratch database.

The configured database must not contain valuable data: migration fixtures
drop and recreate its `public` schema. CI must allocate a database exclusively
to this test process. Production PostgreSQL connections and these fixtures both
require TLS; the optional CA path only extends trust for a private test CA.

## Container env vars

| Variable | Default | Meaning |
| --- | --- | --- |
| `SEKAI_CREDENTIAL` | unset | Client-side bearer used by the gateway for TCP gRPC; create it as a durable principal credential before switching transports |
| `GATEWAY_BIND` | `127.0.0.1:8788` (image/local); compose uses `0.0.0.0:8080` | Gateway bind address. Non-loopback binds require non-empty `GATEWAY_KEYS` |
| `SEKAI_DB_PATH` | unset in the image; compose sets `/data/sekai.db` | Combined Sekai SQLite dest. Must be paired with `CHISEI_DB_PATH`. |
| `CHISEI_DB_PATH` | unset in the image; compose sets `/data/chisei.db` | Combined Chisei SQLite dest. Must be paired with `SEKAI_DB_PATH`. |
| `DB_PATH` | `/data/sekai.db` (image) | Shared-store compatibility path. Combined refuses it unless `SEKAI_SHARED_STORE=1`. Dest-pair wins over this leftover when both are set. |
| `SEKAI_SHARED_STORE` | unset | Set `1` to boot Combined on the image `DB_PATH` as one identity. Migration compatibility, not the compose default. |
| `SEKAI_SOCKET` | `/data/sekai.sock` | Unix socket path for control plane transport |
| `CHISEI_GRPC_URL` | unset | Optional TCP override; when unset, the gateway uses the image's explicit `SEKAI_SOCKET=/data/sekai.sock` setting |
| `OPENAI_API_KEY` | unset | API key for OpenAI upstream |
| `ANTHROPIC_API_KEY` | unset | API key for Anthropic upstream |
| `CHISEI_GATEWAY_ADMIN_TOKEN` | unset | Enables and protects `/_chisei/admin/refresh`; must be at least 32 bytes, and unset disables the endpoint |
| `OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama-compatible endpoint for gateway/llm tests |

## UDS (default) vs TCP transport

The image currently exports `DB_PATH=/data/sekai.db` and
`SEKAI_SOCKET=/data/sekai.sock` only. Combined `sekai-chisei` refuses that
shared file unless the runtime sets a dest-pair or `SEKAI_SHARED_STORE=1`.
Checked-in compose sets `SEKAI_DB_PATH=/data/sekai.db` and
`CHISEI_DB_PATH=/data/chisei.db` on the server. File databases use SQLite WAL
mode, so volume backups must include both dest files plus `-wal`/`-shm`
sidecars, or use `VACUUM INTO` on each.

The default setup uses:

- shared `sekai-data` volume mounted at `/data`
- Combined dest-pair files at `/data/sekai.db` and `/data/chisei.db`
- server socket at `/data/sekai.sock`
- gateway target also set to `/data/sekai.sock` via `SEKAI_SOCKET`

No server gRPC port is published in this mode.

For TCP transport, first create a durable principal credential while the shared
UDS is available. Set that value as `SEKAI_CREDENTIAL` on the gateway, point it
at `CHISEI_GRPC_URL=http://server:50051`, and publish `50051` in compose (see
comments in `docker-compose.yml`). The server detects active credentials in its
database and enables authenticated TCP. Public `0.0.0.0` TCP also requires
`SEKAI_TLS_CERT` and `SEKAI_TLS_KEY`, or an explicit
`SEKAI_ALLOW_PLAINTEXT=1` for a trusted plaintext deployment, or an explicit
loopback `SEKAI_BIND`.

## Container tasks on shared state

- Seed setup data:

```bash
docker compose --env-file _output/compose.env run --rm gateway sekaictl admin gateway setup --help
```

- Generate an attribution/report from shared state:

```bash
docker compose --env-file _output/compose.env run --rm gateway chisei-gateway report --by work-unit --since 24h
```
