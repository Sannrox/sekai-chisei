# Configuration

Configuration is read from environment variables. `sekaictl launch` also reads
`./.env` and only fills variables that are not already present in the process
environment. Copy [`.env.example`](../.env.example) for a commented local
template.

## Control plane

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_DB_BACKEND` | `sqlite` | Runtime backend selection (`sqlite` or `postgres`). SQLite remains the default. |
| `DB_PATH` | `./data/sekai.db` | SQLite database path |
| `DATABASE_URL` | unset | PostgreSQL connection URL; required when `SEKAI_DB_BACKEND=postgres` |
| `SEKAI_POSTGRES_MAX_CONNECTIONS` | `16` | PostgreSQL pool size |
| `SEKAI_POSTGRES_CA_CERT` | unset | Optional PEM CA certificate path for TLS trust |
| `GRPC_PORT` | `50051` | TCP gRPC port |
| `SEKAI_BIND` | inferred | TCP bind address; see [transport modes](operations.md#transport-modes) |
| `SEKAI_SOCKET` | `./data/sekai.sock` | Unix socket path; set empty to disable |
| `OPS_BIND` | `127.0.0.1` | Health, metrics, and operator console bind address |
| `OPS_PORT` | `9464` | Health, metrics, and console port; set empty to disable |
| `SEKAI_INSECURE` | unset | Set `1` only for unauthenticated local development |
| `SEKAI_AUTH_TOKEN` | unset | Deprecated single-principal bootstrap token |
| `SEKAI_TLS_CERT` | unset | Server certificate PEM path |
| `SEKAI_TLS_KEY` | unset | Server private-key PEM path |
| `SEKAI_TLS_CA` | unset | Optional CA PEM for **outbound** gRPC clients (and CLIs) that must trust a private server CA. Not a server mTLS client-CA; the control-plane server does not request client certificates |
| `SEKAI_ALLOW_PLAINTEXT` | unset | Set `1` to explicitly allow authenticated public TCP without TLS |
| `SEKAI_SITE_ID` | `local` | Site/region pin stamped on coordination leases and online permit redemption; multi-region sites use a distinct non-empty id (see [region-pins.md](region-pins.md)) |
| `CHISEI_PERMIT_SIGNING_KEY` | unset | Ed25519 seed (64 lowercase hex chars) for external-action permit signing; required to issue permits |
| `CHISEI_PERMIT_ISSUER` | `chisei.local` | Issuer id embedded in signed permits |
| `CHISEI_PERMIT_KEY_ID` | `permit-key-1` | Key id embedded in signed permits for rotation |
| `CHISEI_GOVERNED_SUBJECT_PROVENANCE_SIGNING_KEY` | unset | Separate Ed25519 seed (64 hexadecimal chars) for authenticated Tenkai-compatible governed-subject provenance; never returned by an API |
| `CHISEI_GOVERNED_SUBJECT_PROVENANCE_KEY_NOT_BEFORE_MS` | `0` | Earliest Unix millisecond at which the configured provenance key may issue an envelope |
| `CHISEI_GOVERNED_SUBJECT_PROVENANCE_KEY_EXPIRES_AT_MS` | `i64::MAX` | Exclusive Unix-millisecond retirement time for new envelopes; envelope expiry is capped to this value |
| `CHISEI_GOVERNED_SUBJECT_PROVENANCE_TTL_MS` | `86400000` | Issued envelope lifetime; must be positive and no more than 31 days |
| `RUST_LOG` | `info` | Tracing filter |
| `LOG_FORMAT` | `pretty` | Use `json` for structured logs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Enables OTLP HTTP/protobuf trace export when set |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP trace transport; use `http/protobuf` for this build |
| `OTEL_SERVICE_NAME` | process-specific | OpenTelemetry resource service name |
| `OTEL_TRACES_SAMPLER` | SDK default | Standard OpenTelemetry trace sampling configuration |
| `OTEL_EXPORTER_OTLP_HEADERS` | unset | Optional collector headers; treat values as secrets and never log or commit them |

When authenticated mode is active and `SEKAI_BIND` is unset, TCP binds to
`0.0.0.0`. A public bind requires TLS unless `SEKAI_ALLOW_PLAINTEXT=1` is an
explicit operator decision.

Malformed governed-subject provenance key-window or TTL values disable new
provenance issuance; they never fall back to a wider activation window.

Backend configuration is validated before any listener binds. `DB_PATH` and
`DATABASE_URL` are mutually exclusive. The public
`sekai.runtime-backend/v1` capability contract identifies the backend, its
supported reusable surfaces, and (for PostgreSQL) the applied migration version.
PostgreSQL implements the reusable community surface set—Sekai, Chisei, gateway
governance, and operations health—with shared SQLite/PostgreSQL conformance for
the dual-backend inventory. Selecting `SEKAI_DB_BACKEND=postgres` starts the
public control plane against PostgreSQL when `DATABASE_URL` is set and
migrations/capabilities validate. Some public paths remain SQLite-only and fail
closed on community Postgres (audited ontology mutations, online permit
redeem/reconcile, Gunshi allocation state, FTS text search, federation peer
tables). See [postgres-sekai-parity.md](postgres-sekai-parity.md) and
[postgres-chisei-parity.md](postgres-chisei-parity.md). Backend selection does
not enable tenant, OIDC, OAuth, or identity endpoints.

For multi-replica control planes, use a shared backend so budgets, leases, and
credentials converge. Process memory must not decide durable authority; see
[replica-safety.md](replica-safety.md) for the surface inventory and two-replica
test harness.

## Budget topology (multi-region)

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_BUDGET_TOPOLOGY` / `BUDGET_TOPOLOGY_MODE` | `single_region` | `single_region`, `regional_pinned`, or `regional_with_transfer`. Global active/active SC is rejected. |
| `SEKAI_BUDGET_SITE_ID` / `BUDGET_SITE_ID` | empty | Local site id for home-pin checks; required when topology is regional. |
| `SEKAI_BUDGET_PARTITION_SIMULATED` | unset | Set `1` to refuse budget transfers fail-closed (partition drills). |

Operator runbook and data model: [budget-topology.md](budget-topology.md). Design freeze:
[research/292-multi-region-consistency.md](research/292-multi-region-consistency.md).

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
| `GATEWAY_BIND` | `127.0.0.1:8788` | HTTP gateway bind address. Non-loopback binds require non-empty `GATEWAY_KEYS` and must not enable `CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH` |
| `CHISEI_GRPC_URL` | unset | Required control-plane TCP URL or Unix socket path; falls back only to an explicitly set `SEKAI_SOCKET` |
| `CHISEI_OPENAI_BASE_URL` | OpenAI API | OpenAI-compatible upstream |
| `CHISEI_MODEL_DISCOVERY_TTL_SECS` | `300` | Provider model-catalog cache lifetime; stale refresh failures retain the last-known provider snapshot and initial failures use static routing defaults |
| `CHISEI_ANTHROPIC_BASE_URL` | Anthropic API | Anthropic-compatible upstream; include `/v1` |
| `CHISEI_OLLAMA_BASE_URL` | `${OLLAMA_URL}/v1` | Gateway upstream for `ollama/*` models |
| `GATEWAY_KEYS` | empty | Explicit `key=agent:project` development/compose allowlist (required when the bind is non-loopback) |
| `GATEWAY_DEFAULT_PROJECT` | `default` | Attribution fallback when a key omits a project |
| `CHISEI_GATEWAY_ADMIN_TOKEN` | unset | Enables cache refresh; must be at least 32 bytes |
| `CHISEI_GATEWAY_MAX_REQUEST_BYTES` | `33554432` | Maximum buffered request body |
| `CHISEI_GATEWAY_RATE_LIMIT_REQUESTS` | `120` | Requests per identity and window |
| `CHISEI_GATEWAY_GLOBAL_RATE_LIMIT_REQUESTS` | `1200` | Gateway-wide requests per window |
| `CHISEI_GATEWAY_RATE_LIMIT_WINDOW_SECS` | `60` | Fixed rate-limit window |
| `CHISEI_GATEWAY_MAX_OBJECT_CONTEXT_CHARS` | `4000` | Maximum injected graph-context characters |
| `CHISEI_GATEWAY_KEY_CACHE_TTL_SECS` | `30` | Virtual-key lookup cache lifetime |
| `CHISEI_GATEWAY_USAGE_RECOVERY_PATH` | `data/chisei-gateway-usage-recovery.json` | Durable journal for post-call usage records that could not yet reach the control plane |
| `CHISEI_GATEWAY_RECOVERY_SPOOL_PATH` | `data/chisei-gateway-recovery.jsonl` | Durable receipt, usage, and refusal recovery file (process CWD-relative unless absolute) |
| `CHISEI_GATEWAY_RECOVERY_SPOOL_MAX_BYTES` | `67108864` | Hard recovery-spool capacity; new records are refused after the file reaches this size until replay or operator cleanup frees space |
| `CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER` | unset | Set `1` to enable supported lossy provider bridges |
| `CHISEI_GATEWAY_RUN_PIPELINE` | unset | Set `1` to sample completed calls through Chisei |
| `CHISEI_GATEWAY_PRICING` | unset | Versioned per-model `input:output[:cache_read[:cache_write_5m[:cache_write_1h]]]` USD-per-million pricing table; class rates must be supplied to price provider cache-write premiums |

For upgrades, the gateway still reads the former usage-journal and spool
environment variables when the new names are unset. It also resumes existing
legacy default files before selecting the new defaults. After the old files
drain, set the new paths explicitly; the compatibility names are deprecated.

The pricing format is
`model=input:output[:cache_read[:cache_write_5m[:cache_write_1h]]]`, with every
rate expressed as USD per million tokens and models separated by commas. The
cache-read rate defaults to the ordinary input rate for compatibility. Cache
write rates have no default: when a provider reports a premium-priced write
class, configure its 5-minute or 1-hour rate explicitly or the call cost stays
unknown instead of being billed at a misleading ordinary-input rate.

When starting `chisei-gateway` directly, set either `CHISEI_GRPC_URL` or
`SEKAI_SOCKET`. The gateway does not inherit the control plane's built-in
`./data/sekai.sock` default. Startup fails when neither variable supplies a
non-empty target. Every provider request requires a live control-plane
admission before provider contact.
`sekaictl launch` and the Docker image set the socket target for their managed
topologies.

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
