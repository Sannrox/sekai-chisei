# Configuration

Configuration is read from environment variables. `sekaictl launch` also reads
`./.env` and only fills variables that are not already present in the process
environment. Copy [`.env.example`](../.env.example) for a commented local
template.

## Control plane

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_DB_BACKEND` | `sqlite` | Runtime backend selection. `postgres` is recognized for composition/conformance, but the community server still rejects runtime selection until Chisei and gateway surfaces reach parity. |
| `DB_PATH` | `./data/sekai.db` | SQLite database path |
| `DATABASE_URL` | unset | PostgreSQL connection URL; valid only with `SEKAI_DB_BACKEND=postgres` |
| `GRPC_PORT` | `50051` | TCP gRPC port |
| `SEKAI_BIND` | inferred | TCP bind address; see [transport modes](operations.md#transport-modes) |
| `SEKAI_SOCKET` | `./data/sekai.sock` | Unix socket path; set empty to disable |
| `OPS_BIND` | `127.0.0.1` | Health and metrics bind address |
| `OPS_PORT` | `9464` | Health and metrics port; set empty to disable |
| `SEKAI_INSECURE` | unset | Set `1` only for unauthenticated local development |
| `SEKAI_AUTH_TOKEN` | unset | Deprecated single-principal bootstrap token |
| `SEKAI_TLS_CERT` | unset | Server certificate PEM path |
| `SEKAI_TLS_KEY` | unset | Server private-key PEM path |
| `SEKAI_TLS_CA` | unset | Optional client CA PEM path |
| `SEKAI_ALLOW_PLAINTEXT` | unset | Set `1` to explicitly allow authenticated public TCP without TLS |
| `RUST_LOG` | `info` | Tracing filter |
| `LOG_FORMAT` | `pretty` | Use `json` for structured logs |

When authenticated mode is active and `SEKAI_BIND` is unset, TCP binds to
`0.0.0.0`. A public bind requires TLS unless `SEKAI_ALLOW_PLAINTEXT=1` is an
explicit operator decision.

Backend configuration is validated before any listener binds. `DB_PATH` and
`DATABASE_URL` are mutually exclusive. The public
`sekai.runtime-backend/v1` capability contract identifies the backend and its
supported reusable surfaces. PostgreSQL implements the complete reusable Sekai
surface set (graph, authorization, audit, coordination, evidence, retention,
leases, guarded mutations, capability packages, team namespaces, and related
definitions) with shared SQLite/PostgreSQL conformance and a fail-closed RPC
inventory. The community server still requires the full community capability
set—including Chisei and gateway surfaces—and therefore refuses PostgreSQL
runtime selection until those remaining surfaces reach parity. Backend
selection does not enable tenant, OIDC, OAuth, or identity endpoints.

## Providers and outbound calls

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENAI_API_KEY` | unset | OpenAI provider credential |
| `ANTHROPIC_API_KEY` | unset | Anthropic provider credential |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama-compatible server used by native provider calls |
| `NATIVE_LLM_URL` | unset | Native local model endpoint |
| `LLM_HTTP_CONNECT_TIMEOUT_SECS` | `10` | Outbound connection timeout |
| `LLM_HTTP_READ_TIMEOUT_SECS` | `60` | Idle-read timeout |
| `LLM_HTTP_POOL_IDLE_TIMEOUT_SECS` | `90` | Connection-pool idle timeout |
| `LLM_HTTP_REQUEST_TIMEOUT_SECS` | `120` | Total timeout for unary provider calls |
| `CHISEI_DEFAULT_DATA_CLASS` | `unclassified` | Default classification for egress decisions |
| `CHISEI_SAFE_EGRESS_PROVIDERS` | empty | Comma-separated providers allowed by egress policy |
| `LEAK_REVIEW_MODEL` | unset | Optional local model used for leak review |

Build with `--features secret-command` to resolve opaque provider-key
references through an external secrets-manager adapter:

| Variable | Purpose |
| --- | --- |
| `CHISEI_SECRET_COMMAND` | Executable that receives one opaque reference and prints the secret |
| `CHISEI_OPENAI_API_KEY_SECRET` | OpenAI secret reference |
| `CHISEI_ANTHROPIC_API_KEY_SECRET` | Anthropic secret reference |

Direct API-key variables take precedence. The adapter must write only the secret
value to stdout.

## Gateway

| Variable | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_BIND` | `127.0.0.1:8788` | HTTP gateway bind address |
| `CHISEI_GRPC_URL` | unset | Control-plane TCP URL or Unix socket path; falls back only to an explicitly set `SEKAI_SOCKET` |
| `CHISEI_OPENAI_BASE_URL` | OpenAI API | OpenAI-compatible upstream |
| `CHISEI_MODEL_DISCOVERY_TTL_SECS` | `300` | Provider model-catalog cache lifetime; stale refresh failures retain the last-known provider snapshot and initial failures use static routing defaults |
| `CHISEI_ANTHROPIC_BASE_URL` | Anthropic API | Anthropic-compatible upstream; include `/v1` |
| `CHISEI_OLLAMA_BASE_URL` | `${OLLAMA_URL}/v1` | Gateway upstream for `ollama/*` models |
| `GATEWAY_KEYS` | empty | Explicit `key=agent:project` development/compose allowlist |
| `GATEWAY_DEFAULT_PROJECT` | `default` | Attribution fallback when a key omits a project |
| `GATEWAY_GOVERNANCE_FAILURE` | `open` | Failure posture; use `closed` to refuse all governance failures |
| `CHISEI_GATEWAY_ADMIN_TOKEN` | unset | Enables cache refresh; must be at least 32 bytes |
| `CHISEI_GATEWAY_MAX_REQUEST_BYTES` | `33554432` | Maximum buffered request body |
| `CHISEI_GATEWAY_RATE_LIMIT_REQUESTS` | `120` | Requests per identity and window |
| `CHISEI_GATEWAY_GLOBAL_RATE_LIMIT_REQUESTS` | `1200` | Gateway-wide requests per window |
| `CHISEI_GATEWAY_RATE_LIMIT_WINDOW_SECS` | `60` | Fixed rate-limit window |
| `CHISEI_GATEWAY_MAX_OBJECT_CONTEXT_CHARS` | `4000` | Maximum injected graph-context characters |
| `CHISEI_GATEWAY_KEY_CACHE_TTL_SECS` | `30` | Virtual-key lookup cache lifetime |
| `CHISEI_GATEWAY_GOVERNANCE_CACHE_TTL_SECS` | `300` | Maximum age of last-known governance decisions |
| `CHISEI_GATEWAY_AUDIT_SPOOL_PATH` | beside database | Durable degraded/fail-open JSONL audit spool |
| `CHISEI_GATEWAY_AUDIT_SPOOL_MAX_BYTES` | `67108864` | Audit spool rotation threshold |
| `CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER` | unset | Set `1` to enable supported lossy provider bridges |
| `CHISEI_GATEWAY_RUN_PIPELINE` | unset | Set `1` to sample completed calls through Chisei |
| `CHISEI_GATEWAY_PRICING` | unset | Versioned per-model `input:output[:cache_read[:cache_write_5m[:cache_write_1h]]]` USD-per-million pricing table; class rates must be supplied to price provider cache-write premiums |

The pricing format is
`model=input:output[:cache_read[:cache_write_5m[:cache_write_1h]]]`, with every
rate expressed as USD per million tokens and models separated by commas. The
cache-read rate defaults to the ordinary input rate for compatibility. Cache
write rates have no default: when a provider reports a premium-priced write
class, configure its 5-minute or 1-hour rate explicitly or the call cost stays
unknown instead of being billed at a misleading ordinary-input rate.

When starting `chisei-gateway` directly, set either `CHISEI_GRPC_URL` or
`SEKAI_SOCKET`. The gateway does not inherit the control plane's built-in
`./data/sekai.sock` default. With neither variable set, it has no control-plane
governance target; fail-closed mode rejects that configuration, while the
default fail-open posture can proxy without policy or budget preflight.
`sekaictl launch` and the Docker image set the socket target for their managed
topologies.

`CHISEI_GATEWAY_NO_PREFLIGHT=1` is a debugging escape hatch. It skips budget,
policy, and context-egress preflight, is restricted to explicitly labelled
low-risk requests, and records a durable fail-open audit. Do not use it as the
normal deployment mode.

See [the gateway guide](gateway.md) for authentication and routing semantics.

## Evaluation and scoring

| Variable | Default | Purpose |
| --- | --- | --- |
| `SAMPLE_RATE` | `0.05` | Routine evaluation sampling rate |
| `SAMPLE_RISK_THRESHOLD` | `0.7` | Risk threshold for additional sampling |
| `SCORING_ENABLED` | `false` | Enable background scoring |
| `SCORING_INTERVAL_SECS` | `60` | Scoring worker interval |
| `SCORING_MODEL` | `claude-opus-4-8` | Model used by the scoring worker |
| `SCORING_BATCH_SIZE` | `16` | Maximum observations per scoring batch |

## Configuration hygiene

- Never commit `.env` or provider credentials.
- Prefer per-principal credentials over `SEKAI_AUTH_TOKEN`.
- Keep the ops listener on loopback unless an orchestrator must reach it.
- Raise request or context limits deliberately; do not remove safety caps.
- Treat `.env.example` and the implementation as the source of truth for
  experimental settings not listed here.
