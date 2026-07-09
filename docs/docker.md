# Running with Docker

## Quickstart

```bash
export CHISEI_GATEWAY_ADMIN_TOKEN='sekai-docker-admin'
export OPENAI_API_KEY='<your-openai-key>'
export GATEWAY_KEYS='sekai-docker-demo=demo:default'
export GATEWAY_KEY='sekai-docker-demo'
docker compose up --build
```

The exported `GATEWAY_KEYS` value must be a gateway allowlist map (`key=agent:project`).
A client request must include one of these keys via `Authorization: Bearer <key>` or
`x-api-key: <key>`.

`CHISEI_GATEWAY_ADMIN_TOKEN` protects the admin refresh endpoint (`/_chisei/admin/refresh`).

Without any `sekaictl gateway setup` seed data, control-plane policy/budget enforcement is
still in permissive default mode. Use `sekaictl gateway setup` (see below) to enable
governance and key rotation for your environment.

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

## Container env vars

| Variable | Default | Meaning |
| --- | --- | --- |
| `SEKAI_AUTH_TOKEN` | unset | Enables gRPC TCP on the server (`0.0.0.0:50051`) and token auth for clients |
| `GATEWAY_BIND` | `127.0.0.1:8788` | Gateway bind address. Override to `0.0.0.0:8080` for container exposure |
| `DB_PATH` | `/data/sekai.db` | Database path in the shared data volume. File databases use SQLite WAL mode, so volume backups must include `-wal`/`-shm` sidecars or use `VACUUM INTO`. |
| `SEKAI_SOCKET` | `/data/sekai.sock` | Unix socket path for control plane transport |
| `CHISEI_GRPC_URL` | unset | Optional TCP override for gateway; defaults to `SEKAI_SOCKET` when unset |
| `OPENAI_API_KEY` | unset | API key for OpenAI upstream |
| `ANTHROPIC_API_KEY` | unset | API key for Anthropic upstream |
| `CHISEI_GATEWAY_ADMIN_TOKEN` | unset | If set, gates `/_chisei/admin/refresh`; unset means endpoint is open |
| `OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama-compatible endpoint for gateway/llm tests |

## UDS (default) vs TCP transport

The default setup uses:

- shared `sekai-data` volume mounted at `/data`
- server socket at `/data/sekai.sock`
- gateway target also set to `/data/sekai.sock` via `SEKAI_SOCKET`

No server gRPC port is published in this mode.

For TCP transport, set `SEKAI_AUTH_TOKEN` on server and gateway, point the gateway at
`CHISEI_GRPC_URL=http://server:50051`, and publish `50051` in compose (see comments in
`docker-compose.yml`).

## Container tasks on shared state

- Seed setup data:

```bash
docker compose run --rm gateway sekaictl gateway setup --help
```

- Generate an attribution/report from shared state:

```bash
docker compose run --rm gateway chisei-gateway report --by work-unit --since 24h
```
