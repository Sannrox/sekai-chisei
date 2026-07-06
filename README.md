# sekai-chisei

`sekai-chisei` is a local-first Rust control plane for AI-assisted software delivery.

Most agent systems treat LLM calls as isolated events. `sekai-chisei` treats them as
governed operations: context-aware, policy-constrained, budget-tracked, auditable, and
measurable against a baseline.

It combines:

- `sekai`: a durable graph and dataset layer for typed objects and links, lineage, access control, audit history, coordination, and operational memory
- `chisei`: a policy and decision layer for budget checks, model/runtime selection, request enrichment, evaluation gates, and learning loops
- `llm`: provider adapters for OpenAI, Anthropic, Ollama-compatible endpoints, and native local LLM services

## Quickstart

```bash
git clone https://github.com/Sannrox/sekai-chisei.git
cd sekai-chisei
SEKAI_INSECURE=1 cargo run
```

The server starts on `127.0.0.1:50051` with SQLite at `./data/sekai.db`.

In a second terminal, run the end-to-end demo — it creates a typed-object graph in
`sekai` and drives the `chisei` budget and decision pipeline:

```bash
cargo run --example demo_client
```

To connect a real LLM provider, copy `.env.example` to `.env` and add your key:

```bash
cp .env.example .env
# set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env
SEKAI_INSECURE=1 cargo run
```

See [examples/README.md](examples/README.md) for what the demo exercises.

## Status

Early-stage (`v0.1.0`). The gRPC server, SQLite-backed graph, and chisei policy
pipeline are working. APIs will evolve before v1.0.

## Running with Docker

See [docs/docker.md](docs/docker.md).

## Features

- SQLite-backed typed-object graph with generic objects, links, and schema definitions
- gRPC APIs for `sekai` and `chisei`
- Dataset, lineage, audit, access control, action, and coordination primitives
- Work-unit coordination with admission, heartbeat, completion, and reconciliation
- Chisei pipeline for policy resolution, request enrichment, budget checks, model routing, and eval regression checks
- Provider routing for OpenAI, Anthropic, Ollama-compatible, and native endpoints
- Local-first operation with explicit insecure mode for development

## Requirements

- Rust toolchain with edition 2024 support
- macOS, Linux, or another platform supported by Rust and SQLite
- Optional: local Ollama or compatible endpoint at `http://localhost:11434`

`protoc` is provided through the vendored build dependency.

## Configuration

Configuration is read from environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `GRPC_PORT` | `50051` | gRPC listen port |
| `SEKAI_BIND` | unset | Optional gRPC TCP bind override. When unset, authenticated TCP binds `0.0.0.0` and insecure local TCP binds `127.0.0.1`. |
| `OPS_PORT` | `9464` | HTTP ops listener port for `/metrics`, `/healthz`, and `/readyz`; set empty to disable |
| `OPS_BIND` | `127.0.0.1` | HTTP ops listener bind address; use `0.0.0.0` when Kubernetes kubelet probes must reach the pod |
| `SEKAI_SOCKET` | `./data/sekai.sock` | Unix socket path for local gRPC; set empty to disable |
| `DB_PATH` | `./data/sekai.db` | SQLite database path. The server uses WAL mode for file databases; backups must include the `-wal`/`-shm` sidecars or use `VACUUM INTO`. |
| `SEKAI_AUTH_TOKEN` | unset | **Deprecated fallback:** maps all tokens to principal `root`; prefer `sekaictl credential ...` |
| `SEKAI_TLS_CERT` | unset | Server TLS certificate (PEM); required for authenticated `0.0.0.0` binding unless `SEKAI_ALLOW_PLAINTEXT=1` |
| `SEKAI_TLS_KEY` | unset | Server TLS private key (PEM); required with `SEKAI_TLS_CERT` |
| `SEKAI_TLS_CA` | unset | Optional client trust anchor (PEM) for TLS custom CA validation |
| `SEKAI_ALLOW_PLAINTEXT` | unset | Set to `1` to allow authenticated `0.0.0.0` bind without TLS |
| `SEKAI_INSECURE` | unset | Set to `1` for local unauthenticated development |
| `RUST_LOG` | `info` | Structured logging filter |
| `LOG_FORMAT` | pretty | Set to `json` for JSON logs |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama-compatible endpoint |
| `NATIVE_LLM_URL` | unset | Native local LLM endpoint |
| `OPENAI_API_KEY` | unset | OpenAI API key |
| `ANTHROPIC_API_KEY` | unset | Anthropic API key |
| `LLM_HTTP_CONNECT_TIMEOUT_SECS` | `10` | Outbound LLM/gateway upstream TCP connect timeout |
| `LLM_HTTP_READ_TIMEOUT_SECS` | `60` | Outbound LLM/gateway upstream idle-read timeout; protects streaming without imposing a total stream cap |
| `LLM_HTTP_POOL_IDLE_TIMEOUT_SECS` | `90` | Outbound LLM/gateway upstream connection pool idle timeout |
| `LLM_HTTP_REQUEST_TIMEOUT_SECS` | `120` | Total timeout for unary provider `chat()` calls; streaming and gateway passthrough paths do not use this total cap |

See [.env.example](.env.example) for a local template.

Sekai object RPC mutations and object-mutating built-in actions write audit rows
in the same SQLite transaction as the object mutation. Updates emit one row per
changed scalar or property field. Creates and deletes emit lifecycle summary rows
using `_created` and `_deleted`; they do not snapshot every property value.
High-churn deployments should schedule audit retention by calling
`purge_old_records` with the desired cutoff; the server does not purge audit
history automatically.

### Authentication and transport

For TCP mode, control-plane identity is verified from bearer token metadata:
- create per-principal credentials via `sekaictl credential create <principal>` and set `SEKAI_AUTH_TOKEN` to that token for clients
- use `sekaictl credential rotate <principal>` and `sekaictl credential revoke <principal>` for lifecycle
- `SEKAI_AUTH_TOKEN` is a deprecated compatibility path and now maps to fixed principal `root`
- set `SEKAI_BIND` to make the TCP bind address explicit; when unset, authenticated TCP infers `0.0.0.0` and insecure local TCP infers `127.0.0.1`
- `0.0.0.0` requires TLS via `SEKAI_TLS_CERT` and `SEKAI_TLS_KEY` unless `SEKAI_ALLOW_PLAINTEXT=1`
- local UDS paths and `SEKAI_INSECURE=1` stay plaintext and keep self-asserted `x-principal` (defaults to `local` when absent)

### Query and Object Sets

`ListObjects` is the main object query surface. Its `ListFilter` can match by
`kind`, exact `name`, exact `namespace`, and one or more property filters. Property
filter keys may contain only ASCII letters, digits, and `_`; invalid keys are
rejected before SQL is built. Supported property operators are `eq`, `ne`/`neq`,
`gt`, `gte`, `lt`, `lte`, `contains`, `prefix`, and `in`. `contains` and
`prefix` escape SQL wildcard characters, and `in` accepts comma-separated values.

Pagination uses `limit` and `offset`. A missing or non-positive `limit` uses the
default of 100, and requested limits are capped at 1000. Results can be ordered by
`name`, `created`, `updated`, or `property:<key>` with optional `descending`.
Every ordering uses `id ASC` as a deterministic tie-breaker.

Object sets are named, per-principal saved `ListFilter`s. Use `CreateObjectSet`
to store a filter, `ListObjectSets` to see the caller's sets, `ResolveObjectSet`
to run the saved filter, and `DeleteObjectSet` to remove it. Resolves apply the
same visibility rules as `ListObjects`: objects with no grants are visible, and
granted objects are returned only when the caller has a matching principal. A
resolve request can override the saved `limit`; `offset` is overridden only when
the request explicitly sends it, so omitted `offset` keeps the saved filter's
offset.

## Observability

The server exposes unauthenticated health and Prometheus endpoints on the loopback
ops listener by default:

```bash
curl -s http://127.0.0.1:9464/healthz
curl -s http://127.0.0.1:9464/readyz
curl -s http://127.0.0.1:9464/metrics
```

Use HTTP probes in Kubernetes with `OPS_BIND=0.0.0.0` so kubelet can reach the
listener through the pod IP:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9464
readinessProbe:
  httpGet:
    path: /readyz
    port: 9464
```

The gRPC health service is also registered without the auth interceptor, so native
gRPC probes can check `grpc.health.v1.Health/Check` even when token auth protects
the application services. OpenTelemetry/OTLP export is a deliberate follow-up;
this release exports Prometheus metrics only.

## Codex Gateway Preview

`chisei-gateway` currently exposes OpenAI-compatible `/v1/responses` and
`/v1/chat/completions` plus Anthropic-compatible `/v1/messages` and
`/v1/messages/count_tokens`. It can either preserve the client app's normal
provider login while adding Chisei attribution headers, or accept virtual
`sk-chisei-*` client keys and replace them with provider keys owned by the
gateway. In both modes it streams responses back to the client and preflights
Chisei budget checks and model policy when the control plane is reachable.
Provider usage metadata, including streamed Responses, Chat Completions, and
Anthropic Messages events, is recorded via `RecordUsage` and appended to the
`llm_calls` dataset. Refused preflight calls append `status`, `error_type`, and
`refusal_reason` rows to the same ledger. Gateway policy, budget, auth, egress, and sampling
decisions are recorded through Chisei's `RecordGatewayAudit` wrapper and land in
Sekai's audit log against the same `llm_calls` target. Policy-resolved model
rewrites are audited and stored as `resolved_model` on usage rows. Virtual-key
authentication failures are audited without storing bearer-token material.
Referenced Sekai
objects such as `ticker:{AAPL}` produce object-context egress audit decisions
for external provider calls. Allowed object fields are injected into supported
OpenAI Responses, Chat Completions, and Anthropic Messages payload shapes, while
denied fields are counted in audit but not forwarded.

### One-command launch

```bash
cargo run --bin sekaictl -- launch codex-app
```

`sekaictl launch` reads `./.env` for any unset variables, starts the sekai
server on the Unix socket if it is not already running, seeds the codex-app
project, gateway key, budget, and model policy, starts `chisei-gateway` if
needed, and opens the Codex app. Spawned services log to `./data/logs/`. Use
`--no-app` to bring the stack up without launching Codex, and `--model`,
`--project`, `--budget`, or `--gateway-bind` to adjust the defaults.

The gateway upstream mode is picked automatically: with `OPENAI_API_KEY` set,
Codex local-login auth is rewritten for `api.openai.com`; without it, the Codex
ChatGPT-plan OAuth login and `chatgpt-account-id` header are forwarded
unchanged to `https://chatgpt.com/backend-api/codex`, so a ChatGPT subscription
works through the gateway with no API key.

Codex CLI runs honor per-invocation provider overrides, but the desktop app
does not: only the user-level `~/.codex/config.toml` routes app traffic.
`sekaictl launch codex-app` therefore manages that file for the lifetime of the
app — it sets `model_provider = "chisei"` plus the provider stanza (commenting
out any existing top-level provider choice), waits in the foreground, and
strips its changes again when the app quits or on Ctrl-C, preserving edits the
app made in the meantime and self-healing on the next run if a previous launch
crashed. Pass `--keep-config` to leave the routing in place instead.

Note that Codex scopes chat history by provider: while routed through the
gateway the desktop app shows a separate `chisei` conversation list, and your
normal `openai` conversations reappear once the config is reverted. The steps
below are the manual equivalent of what `launch` automates.

Seed the Codex app project, agent, budget, model policy, graph metadata, and
`llm_calls` dataset:

```bash
SEKAI_SOCKET=./data/sekai.sock \
cargo run --bin sekaictl -- gateway setup \
  --agent codex-app \
  --project sekai-chisei \
  --gateway-key sk-chisei-codex-app \
  --budget 500000 \
  --budget-period day \
  --default-model gpt-5.5 \
  --allowed-model gpt-5.5
```

Start it in local-login mode. For Codex/OpenAI, enable the rewrite flag so the
gateway treats the Codex local-login bearer as client identity evidence but uses
`OPENAI_API_KEY` for the actual `api.openai.com` upstream request:

```bash
SEKAI_SOCKET=./data/sekai.sock \
OPENAI_API_KEY=... \
CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH=1 \
CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1 \
cargo run --bin chisei-gateway
```

For repeatable Codex CLI checks, install the profile helper. It writes
`~/.codex/chisei.config.toml`, not the main Codex config:

```bash
scripts/chisei_gateway_live_clients.sh install-codex-profile
scripts/chisei_gateway_live_clients.sh doctor
scripts/chisei_gateway_live_clients.sh codex-live-smoke
```

The profile uses this provider shape. Keep the base URL at `/v1` for Codex:

```toml
model = "gpt-5.5"
model_provider = "chisei"

[model_providers.chisei]
name = "Chisei Gateway"
base_url = "http://127.0.0.1:8788/v1"
wire_api = "responses"
requires_openai_auth = true
env_http_headers = { "x-chisei-agent" = "CHISEI_CODEX_AGENT", "x-chisei-project" = "CHISEI_CODEX_PROJECT" }
```

Launch the Codex app through the same provider without editing
`~/.codex/config.toml`:

```bash
scripts/chisei_gateway_live_clients.sh launch-codex-app
```

The repo includes an opt-in helper for the real client checks. It does not edit
your main Codex config; it can install/check the CLI profile, print the stanza
to add manually if you prefer main-config setup, launch Codex.app with Chisei
config overrides, run a Codex CLI prompt through the configured Chisei profile,
or run a Claude Code prompt through the gateway using your local Claude login:

```bash
scripts/chisei_gateway_live_clients.sh check-codex-config
scripts/chisei_gateway_live_clients.sh install-codex-profile
scripts/chisei_gateway_live_clients.sh check-codex-profile
scripts/chisei_gateway_live_clients.sh print-codex-config
scripts/chisei_gateway_live_clients.sh doctor
scripts/chisei_gateway_live_clients.sh launch-codex-app
scripts/chisei_gateway_live_clients.sh codex-smoke
scripts/chisei_gateway_live_clients.sh codex-live-smoke
scripts/chisei_gateway_live_clients.sh claude-smoke
```

`doctor` checks that the Codex command/profile and gateway endpoint are ready.
`codex-live-smoke` runs a real Codex CLI prompt through the Chisei provider,
requires the exact expected reply, and then requires a recent `codex-app` row in
`chisei-gateway report --by agent --since 10m`. That is the CLI acceptance
check for real Codex/OpenAI traffic through the gateway; after launching
Codex.app, run the report command again to confirm app traffic appears too.

For Claude Code-style Anthropic traffic, point the Anthropic base URL at the
gateway root URL, not `/v1`, and pass attribution headers:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
export ANTHROPIC_CUSTOM_HEADERS=$'x-chisei-agent: claude-code\nx-chisei-project: sekai-chisei'
export ENABLE_TOOL_SEARCH=true
claude -p 'Reply with exactly: chisei gateway claude smoke ok'
```

If Claude Code's default model alias is unavailable in your account, set an
explicit model for the smoke helper, for example:

```bash
CHISEI_CLAUDE_MODEL=claude-fable-5 \
scripts/chisei_gateway_live_clients.sh claude-smoke
```

Callers that know the current Sekai work unit can also send
`x-chisei-work-unit: <id>` or `x-chisei-task-id: <id>`. The gateway records that
ID on the `llm_calls` row and creates a best-effort graph link from
`work_unit:<id>` to the generated `llm_call:<request_id>` object.

Virtual-key mode is still available for CI, headless workers, or setups where
the gateway should own provider credentials. Start the gateway with
`OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY`, omit
`CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH`, and use
`scripts/chisei_gateway_live_clients.sh print-codex-key-config` or
`scripts/chisei_gateway_live_clients.sh claude-key-smoke`.

Virtual keys are stored only as SHA-256 hashes on Sekai `gateway_key` objects
created by `sekaictl gateway key create`. With `SEKAI_SOCKET` or `CHISEI_GRPC_URL`
configured, the gateway authenticates presented keys by hashing them, checking a
short in-memory cache, and looking up an active `gateway_key` object on cache
miss or TTL expiry. Unknown keys are rejected.
`GATEWAY_KEYS` remains an explicit env allowlist override in `key=agent:project`
form. If no control-plane target and no allowlist are configured, the gateway
keeps a development-only fallback that maps non-empty `sk-chisei-<agent>` keys
to `agent:<agent>`.

The setup helper also links the control graph with gateway-domain relations:
`gateway_key --identifies--> agent`, `agent --works_on--> project`,
`budget --limits--> agent`, and `policy --applies_to--> project`. It also keeps
the older generic `used_for`, `owns`, and `targets` links so existing graph
queries continue to work.

Manage hashed gateway keys through the setup helper:

```bash
SEKAI_SOCKET=./data/sekai.sock cargo run --bin sekaictl -- gateway key create codex-app \
  --agent codex-app \
  --project sekai-chisei \
  --gateway-key sk-chisei-codex-app \
  --budget 500000 \
  --allowed-model gpt-5.5
SEKAI_SOCKET=./data/sekai.sock cargo run --bin sekaictl -- gateway key list
SEKAI_SOCKET=./data/sekai.sock cargo run --bin sekaictl -- gateway key rotate \
  --gateway-key-name codex-app \
  --gateway-key sk-chisei-codex-app-rotated
SEKAI_SOCKET=./data/sekai.sock cargo run --bin sekaictl -- gateway key revoke \
  --gateway-key-name codex-app
```

Set `CHISEI_GATEWAY_KEY_CACHE_TTL_SECS` to tune the Sekai key lookup cache
TTL. After key rotation or revocation, running gateways can clear the cache
without restart:

```bash
CHISEI_GATEWAY_ADMIN_TOKEN=change-me \
cargo run --bin chisei-gateway -- refresh
```

If `CHISEI_GATEWAY_ADMIN_TOKEN` is unset, the local admin refresh endpoint is
open to callers that can reach the gateway bind address. Set it before binding
the gateway outside trusted localhost development.

Governance calls fail open by default so local Codex sessions keep working while
the control plane restarts. Set `GATEWAY_GOVERNANCE_FAILURE=closed` to fail
closed instead.

For debugging provider/client behavior independently of Chisei control-plane
latency or availability, start the gateway with `--no-preflight` or set
`CHISEI_GATEWAY_NO_PREFLIGHT=1`. This skips `CheckBudget`, `ResolvePolicy`, and
context-egress preflight, while still authenticating the caller and proxying
through the configured provider credentials. Do not use it as the normal
governed mode.

Gateway budget, usage, and policy calls send first-class `subject`, `project`,
`agent`, and `key_id` metadata to Chisei while retaining legacy `user_id`
compatibility for older callers. `ResolvePolicy` accepts the same gateway
context so agent-specific or key-specific policy scopes, such as
`agent:codex-app` or `gateway_key:codex-app`, can override project defaults
before the gateway rewrites a provider request. Ledger rows also include
`key_id` when the caller used a virtual key. Gateway audit decisions enrich
their evidence with the resolved `user_id`, `project`, and virtual `key_id`
where available.

Gateway preflight checks both the agent budget (`agent:<name>`) and the project
budget (`project:<name>`), and reconciles actual token usage to both subjects
after successful provider calls.

Plan execution also has an additive streaming surface. Existing unary
`ExecutePlan` calls still return a completed `PlannedChatResponse`; clients that
need token-by-token output can call `ExecutePlanStream`, which emits content
deltas and finishes with the same completed response shape. The lower-level LLM
service mirrors this through `ChatStream` for OpenAI-compatible and Anthropic
SSE providers.

Set `CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER=1` to opt in to lossy cross-provider
routing. The first bridge translates non-streaming Anthropic `/v1/messages`
requests to OpenAI-compatible `/v1/chat/completions` when policy resolves an
OpenAI/Ollama-compatible model, then maps the chat response back to Anthropic's
message shape. Streaming and tool-call translation stay denied instead of being
silently approximated.

Estimated cost is recorded only when you provide a static pricing table. The
format is `model=input_usd_per_1m_tokens:output_usd_per_1m_tokens`; for example:

```bash
export CHISEI_GATEWAY_PRICING='gpt-5.5=1.25:10,claude-sonnet-4-6=3:15'
```

Set `CHISEI_GATEWAY_RUN_PIPELINE=1` to run Chisei's pipeline after completed
gateway calls. The gateway records `pipeline_sampled`, `sample_reason`, and
`sample_rate` on `llm_calls`; sampled calls also get a `gateway.sampled` audit
decision. When control-plane scoring is enabled, sampled calls with captured
provider output are also queued as scoring observations. This is best-effort and
does not alter the proxied provider payload.

Inspect recent gateway usage from the `llm_calls` dataset:

```bash
SEKAI_SOCKET=./data/sekai.sock \
cargo run --bin chisei-gateway -- report --by agent --since 24h
```

Export a small standalone usage dashboard:

```bash
SEKAI_SOCKET=./data/sekai.sock \
cargo run --bin chisei-gateway -- report --since 24h --html dashboard.html
```

Run the local gateway smoke test without real provider credentials:

```bash
scripts/chisei_gateway_smoke.sh
```

The smoke harness starts a temporary Sekai control plane, a fake OpenAI/Anthropic
upstream, seeds Codex and Claude virtual keys, sends passthrough and virtual-key
requests through the gateway, exercises streaming SSE for both provider
surfaces, verifies provider-key rewrites, auth preservation, and Codex/OpenAI
passthrough auth rewrite, and checks the `report --by agent` output plus the
HTML dashboard export. Real Codex app and Claude Code checks can be enabled
with `CHISEI_GATEWAY_SMOKE_LIVE_CLIENTS`; for manual live checks, the helper
accepts `CHISEI_CLAUDE_MODEL`.

## Development

```bash
cargo test                        # run all tests
cargo build --release             # optimized binary
cargo run --example demo_client   # end-to-end demo
```

Run the Ollama end-to-end test only when a local Ollama server and model are available:

```bash
cargo test --test ollama_e2e -- --ignored
```

## Project Layout

- [proto/](proto/) — gRPC service definitions
- [src/grpc/](src/grpc/) — tonic service implementations
- [src/sekai/](src/sekai/) — graph, dataset, audit, lineage, coordination, security, work-unit primitives
- [src/chisei/](src/chisei/) — policy, budget, pipeline, evaluation, evolution, model-routing
- [src/llm/](src/llm/) — LLM provider adapters
- [VISION.md](VISION.md) — long-term product direction

## Security

Do not expose `SEKAI_INSECURE=1` outside a trusted local development environment.

Report security issues using the process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
