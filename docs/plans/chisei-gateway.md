# Plan: `chisei-gateway`

An LLM gateway proxy that routes real agent traffic through sekai-chisei. A small
companion binary that speaks the Anthropic/OpenAI HTTP API on localhost and wraps
every request with the chisei pipeline: budget check → policy/model resolution →
execute → record usage + audit into sekai.

Anything that accepts `ANTHROPIC_BASE_URL`, an OpenAI-compatible base URL, or a
custom OpenAI-style model provider — Claude Code, Codex app local agents,
orchestrator workers, one-off scripts — can point at it with zero code changes
once the matching HTTP surface exists.
From day one, across every session and worker on the machine:

- **Spend visibility** — tokens/cost per project, per agent, per day, queryable
  from the sekai graph instead of guessed from provider dashboards.
- **Real budgets** — cap what a background worker fleet may burn overnight; a
  runaway loop gets refused instead of billing.
- **Audit trail** — which worker called which model for which task.
- **Routing control** — send trivial calls to local Ollama automatically, keep
  frontier models for the hard work.

Every gap the gateway hits becomes a prioritized issue for the control plane
itself — it is the project's first real API consumer.

## Key architectural finding

The internal LLM types are lossy relative to the real Anthropic API, and nothing
streams today. `src/llm/mod.rs` models `Message.content` as a plain string, but
Claude Code traffic is full of content blocks (`tool_use`, `tool_result`,
`thinking`, images, `cache_control`), and Claude Code requires SSE streaming on
`/v1/messages`. Routing real traffic *through* `PlanExecution`/`ExecutePlan`
would break tool use, prompt caching, and streaming on day one.

Therefore the gateway is a **governance sidecar, not a re-serializer**: it passes
the raw provider payload through byte-faithfully and wraps it with chisei gRPC
calls (`CheckBudget` → `ResolvePolicy` → forward → `RecordUsage` + audit into
sekai). The existing RPCs already fit this shape.

## Architecture

```
Claude Code / workers / scripts
        │  ANTHROPIC_BASE_URL=http://127.0.0.1:8788
        ▼
┌─ chisei-gateway (axum, separate binary, same repo) ──┐
│ 1. identify caller (headers or virtual key → agent/project) │
│ 2. CheckBudget (gRPC over UDS)  ── refuse → 429/400  │
│ 3. ResolvePolicy → optional model rewrite            │
│ 4. forward raw payload upstream (streaming intact)   │
│ 5. tap usage from response / SSE events              │
│ 6. RecordUsage + append audit row into sekai         │
└──────────────────────────────────────────────────────┘
        ▼
api.anthropic.com / api.openai.com / localhost:11434
```

### Separate process, not embedded in the server

Embedding the gateway as a second listener in the existing server would work,
but a separate binary wins on three counts:

1. **Restart coupling.** The control plane is at v0.1.0 and gets rebuilt and
   bounced constantly during development. A separate gateway keeps serving (and
   fails open on governance calls) while the server restarts — in-flight Claude
   Code SSE streams survive.
2. **First real API consumer.** Built as an external client, the gateway
   exercises the public gRPC surface exactly like any third-party integration
   would. Every gap it hits is a genuine API finding. Embedded, it would grow
   private couplings into domain modules and lose that feedback loop.
3. **Blast radius and posture.** Byte-level SSE proxying against evolving
   provider APIs is the flakiest code in the system; a panic there must not take
   down the graph/coordination server. The process holding provider keys and
   facing agent traffic stays separate from the process holding the world model.

Same repo, same crate (new bin target), sharing generated proto clients and
config — one `git clone`, versions in lockstep. If single-command startup is
wanted: a `--with-gateway` supervisor flag or a two-line script, not process
fusion. Structural rule regardless: the gateway talks to chisei only through the
gRPC API, never directly into domain modules.

### Gateway ↔ control plane over a Unix domain socket (UDS)

The internal gRPC hop uses a **Unix domain socket** instead of TCP:

- The control plane no longer needs an open TCP port for local operation.
  Today's choice between `SEKAI_INSECURE=1` on 127.0.0.1 and token-auth on
  0.0.0.0 gets a third, better default: a socket file where filesystem
  permissions (0600) are the auth. No token to manage; nothing for another
  local user or a stray container to connect to.
- Slightly less per-call overhead — pleasant given two governance calls per
  LLM request, though security posture is the main motivation.
- Same-machine only by nature, which matches the local-first stance. Remote
  access remains TCP + bearer token.

Implementation (well-trodden with tonic):

- **Server:** new `SEKAI_SOCKET=./data/sekai.sock` env var; bind a
  `tokio::net::UnixListener`, serve via `serve_with_incoming`, unlink stale
  socket on startup, chmod 0600. UDS and TCP can listen simultaneously, so
  nothing existing breaks.
- **Client (gateway, demo_client):** tonic `connect_with_connector` with a
  `service_fn` opening a `UnixStream` (dummy URI, connector does the work).
  Wrap once in a lib helper — `connect_sekai(url_or_socket_path)` — shared by
  the gateway, examples, and future CLIs.
- The gateway defaults to the socket, with `CHISEI_GRPC_URL` as TCP fallback.

**Client-facing side stays TCP/HTTP.** `ANTHROPIC_BASE_URL` expects an
`http://` URL; Claude Code and provider SDKs cannot dial a unix socket. The
gateway keeps `127.0.0.1:8788` toward clients — the only open port left.

### Client configuration

Claude Code should use local-login passthrough for normal developer sessions.
Point Anthropic at the gateway root URL, not `/v1`, and add Chisei attribution
headers while keeping Claude Code's own login/token intact:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8788 \
ANTHROPIC_CUSTOM_HEADERS=$'x-chisei-agent: claude-code\nx-chisei-project: sekai-chisei' \
ENABLE_TOOL_SEARCH=true \
claude
```

Codex local agents use host-owned Codex provider settings, not project-local
`.codex/config.toml`. For CLI smoke checks, install a dedicated profile at
`~/.codex/chisei.config.toml`. For Codex Desktop, launch through `codex app`
with config overrides so the main `~/.codex/config.toml` does not have to be
changed. Keep Codex on the `/v1` base URL and preserve local OpenAI/Codex client
auth:

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

Then launch the Codex app with provider overrides and attribution variables
available to the app process:

```bash
scripts/chisei_gateway_live_clients.sh launch-codex-app
```

On macOS, apps opened from Finder/Dock may not inherit shell environment
variables. Use the helper script instead of relying on a Finder/Dock launch.
This only routes local Codex app agent model calls. Codex login, app sync,
marketplace/plugin traffic, and hosted/cloud tasks do not route through
`127.0.0.1`.

### Identity via local login or virtual keys

The default local developer path is auth passthrough. Clients keep their normal
provider login, and the gateway reads `x-chisei-agent` plus optional
`x-chisei-project` headers for attribution. The gateway strips those Chisei
headers before forwarding upstream and normally preserves the provider
`authorization` or `x-api-key` header. Codex/OpenAI local login needs the
gateway-side compatibility flag `CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1`
with `OPENAI_API_KEY`; the Codex bearer is accepted as client identity evidence,
then the gateway rewrites upstream auth to the configured provider key.

Virtual keys remain the right fit for CI, headless workers, and environments
where the gateway should own real provider keys. Each agent/project gets a
gateway-issued key (`sk-chisei-<name>`). Clients set that as their API key; the
gateway hashes it and looks up an active Sekai `gateway_key` object created by
`chisei-gateway-setup`. The object maps the presented key to `{user_id, project,
agent}` for budgets and audit without storing bearer-token material. Real keys
stop being scattered across worker configs. `GATEWAY_KEYS` remains an explicit
environment allowlist override; without a control-plane target, the gateway can
still derive `sk-chisei-<agent>` keys for local development.

### Control graph

Sekai should be more than an address book for the gateway. The split:

- **Objects and links** are the durable control graph: who exists, what they
  belong to, what policy applies, and which guardrails are active.
- **Dataset rows** are the request ledger: every high-volume LLM call, refusal,
  token count, cost, and latency.
- **Chisei services** are the decision engine: budget, policy/model resolution,
  egress filtering, eval/regression signals, and learning/pipeline sampling.

Low-cardinality objects:

- `project:<name>` / `namespace:<name>` — the budget and policy boundary.
- `agent:<name>` — Codex app, Claude Code, maintainer workers, CI workers.
- `gateway_key:<key_id>` — virtual key metadata, not the secret value itself.
- `budget:<name>` — daily/weekly/monthly spend or token ceilings.
- `policy:<name>` — allowed providers/models, default model, routing posture.
- `egress_rule:<name>` — redaction/export posture for external providers.
- `eval_suite:<name>` / `regression_signal:<name>` — quality gates that can
  influence routing and sampling.
- `work_unit:<id>` / task objects when the caller can provide or infer one.

Useful links:

- `agent --works_on--> project`
- `gateway_key --identifies--> agent`
- `budget --limits--> agent|project`
- `policy --applies_to--> agent|project`
- `egress_rule --protects--> project`
- `eval_suite --gates--> project`
- `work_unit --incurs_usage--> llm_call/request_id`

The hot path should do bounded reads from this graph, then append. A request
flow for Codex app looks like:

1. Resolve identity from Chisei attribution headers or virtual key to `{agent,
   project, namespace}`.
2. Load active budgets for the agent and project.
3. Load model policy and provider posture for the project.
4. Check active egress rules if the request contains namespace/object context
   and the target provider is external.
5. Check eval/regression signals for the namespace; optionally force stronger
   model, review, or sampling.
6. Proxy the raw provider request.
7. Record usage, append the `llm_calls` row, and emit audit events for budget
   refusals, model rewrites, egress decisions, and fail-open governance gaps.

Bootstrap should be explicit first, with lazy repair later:

```bash
cargo run --bin chisei-gateway-setup -- key create codex-app \
  --project sekai-chisei \
  --agent codex-app \
  --gateway-key sk-chisei-codex-app \
  --budget 500000 \
  --budget-period day \
  --allowed-model gpt-5.5
```

Gateway callers now pass first-class budget metadata on `CheckBudget`,
`RecordUsage`, `SetBudgetLimit`, and `ResolvePolicy`: `subject`, `project`,
`agent`, and `key_id`. Legacy `user_id` remains supported for existing budget
callers. The service resolves the effective budget subject in priority order:
`subject` → `agent:<agent>` → `project:<project>` → `gateway_key:<key_id>` →
legacy `user_id`.

### Integration contract

Plan the integration around three distinct paths so the gateway does not turn
every model call into an expensive graph traversal.

**Bootstrap path** runs from the CLI or setup UI:

- Create/update `project`, `agent`, `gateway_key`, `budget`, and `policy`
  objects. First slice implemented by `chisei-gateway-setup`.
- Create/update links from key → agent, agent → project, budget → subject, and
  policy → subject. Implemented with gateway-domain relations
  `identifies`, `works_on`, `limits`, and `applies_to`, plus compatibility
  `used_for`, `owns`, and `targets` links for existing generic graph queries.
- Store the virtual key secret outside the object graph; the graph stores key id,
  label, status, and attribution metadata. Implemented with SHA-256 hashes on
  `gateway_key` objects plus
  `chisei-gateway-setup key create|list|rotate|revoke`.
- Seed the `llm_calls` dataset schema if it does not exist. Implemented by
  `chisei-gateway-setup`.

**Request hot path** runs for every provider call:

- Authenticate the request locally in the gateway: Chisei attribution headers in
  passthrough mode, or virtual key lookup in gateway-key mode.
- Resolve `{agent, project, namespace}` from an in-memory gateway-key cache
  populated from Sekai. Implemented for hashed `gateway_key` objects with TTL,
  key-miss lookup, `POST /_chisei/admin/refresh` cache clearing, and the
  `chisei-gateway refresh` admin command.
- Call `CheckBudget` before proxying. The gateway checks the most specific
  subject first (`agent:<name>`), then the project subject (`project:<name>`).
- Call `ResolvePolicy` only when routing is enabled for that key/project.
- Avoid generic graph traversal in the hot path. Prefer direct lookup by
  `gateway_key:<key_id>` and bounded linked-object reads.

**Append path** runs after response completion or refusal:

- Call `RecordUsage` with actual tokens when available.
- Append one `llm_calls` row per provider request, including refusals and
  fail-open governance gaps.
- Emit audit events for security-relevant decisions: budget denial, model
  rewrite, egress filtering, fail-open control-plane outage, and virtual-key
  authentication failure.

**Control-plane gap list** for implementation:

- Key store: implemented as hashed Sekai `gateway_key` objects. The setup helper
  seeds keys and provides `key create`, `key list`, `key rotate`, and
  `key revoke`; running gateways use cache TTL or `chisei-gateway refresh` to
  see lifecycle changes.
- Budget shape: implemented first-class budget metadata on `CheckBudget`,
  `RecordUsage`, and `SetBudgetLimit`; the gateway checks and records usage for
  both `agent:<name>` and `project:<name>`. Legacy `user_id` remains compatible.
- Policy shape: implemented first-class project/agent/key metadata on
  `ResolvePolicy`. Policy lookup now considers ordered scopes such as
  `subject`, `agent:<agent>`, `gateway_key:<key_id>`, namespace, project, and
  `project:<project>`, allowing agent-specific overrides ahead of project
  defaults without reserializing provider payloads.
- Audit API: implemented `RecordGatewayAudit` on Chisei so gateway policy,
  budget, auth, egress, and sampling decisions go through a Chisei-facing
  wrapper while still landing in Sekai's decision log. Identity-scoped gateway
  decisions enrich evidence with `user_id`, `project`, and virtual `key_id`
  where available.
- Cache invalidation: first slice implemented for gateway keys through
  `POST /_chisei/admin/refresh`, which clears the runtime key cache without
  restarting the gateway; `chisei-gateway refresh` wraps this endpoint for
  operators and setup scripts.

### Storage

- One sekai **dataset** (`llm_calls`) via `AppendRows`/`QueryRows` for
  high-volume per-call records: timestamp, agent, project, key id, model,
  provider, tokens in/out, cost, latency, status, error type, and refusal
  reason.
- Typed **objects + links** only for the low-cardinality graph (agents,
  projects, budgets).
- Cost computed from a static pricing table in gateway config. Implemented via
  `CHISEI_GATEWAY_PRICING` / `GATEWAY_PRICING` using
  `model=input_usd_per_1m:output_usd_per_1m`; rows store
  `cost_usd_micros` plus a human-readable `cost_usd`.

### Failure policy

If the chisei server is unreachable: **fail-open** with a logged warning (a live
Claude Code session must not brick because the control plane restarted) —
configurable to fail-closed. Budget refusals themselves are always hard,
returned as Anthropic-format error JSON so clients render the reason.

## Phases

### Phase -1 — Integration planning and contracts

- Freeze the v1 object kinds, link relations, `llm_calls` row shape, virtual-key
  hash/storage plan, and gateway cache invalidation story.
- Write fixtures for Anthropic SSE and OpenAI Responses streams before coding
  the proxy so fidelity regressions are visible.
- Decide which setup commands write objects/links and which runtime paths only
  read/cache/append.

### Phase 0 — Transparent proxy (de-risk streaming first)

- New bin target (`src/bin/gateway.rs`) + `axum`.
- Reverse-proxy `/v1/messages` and `/v1/messages/count_tokens` to Anthropic;
  SSE passed through as raw bytes; unknown paths/fields forwarded verbatim.
- First slice implemented in `src/bin/chisei-gateway.rs`: Anthropic Messages and
  count_tokens route through the same virtual-key, budget, policy, usage, audit,
  and ledger path as OpenAI. `x-api-key` virtual keys are replaced with the real
  `ANTHROPIC_API_KEY` upstream. SSE usage is merged from `message_start` and
  `message_delta` events without disturbing the stream.
- **Prerequisite/parallel PR:** UDS listener on the server + `connect_sekai`
  helper — independently shippable and useful before the gateway exists.
- Live Claude Code evidence: `CHISEI_CLAUDE_MODEL=claude-fable-5
  scripts/chisei_gateway_live_clients.sh claude-smoke` returned exactly
  `chisei gateway claude smoke ok` through `ANTHROPIC_BASE_URL` pointed at the
  gateway. The gateway ledger recorded the calls under `claude-code`; this
  proves local-login routing and attribution for the CLI. Long tool-use stream
  coverage remains represented by the deterministic SSE passthrough tests and
  smoke harness.

### Phase 1 — Observability (first real payoff)

- Parse usage without disturbing the stream: buffer non-streaming JSON
  responses; for SSE, tap `message_start`/`message_delta` for token counts.
- Virtual-key identity and bootstrap command for
  `{project, agent, gateway_key, budget, policy}`.
- `RecordUsage`, append to the `llm_calls` dataset, and emit audit rows for
  refusals/fail-open decisions.
- `chisei-gateway report --by project|agent|model --since 24h` via `QueryRows`.
  Implemented as the `report` subcommand on the gateway binary, with optional
  `--html <path>` export for a standalone usage dashboard.
- This is where spend visibility lands — ship before anything else.

### Phase 2 — Budgets

- Preflight `CheckBudget` (estimate ≈ request bytes / 4), reconcile with
  actuals in `RecordUsage`.
- Per-agent/per-project limits via `SetBudgetLimit`, with initial subjects
  encoded as `agent:<name>` and `project:<name>`.
- Refusal as Anthropic-format 429 with the budget reason in the message.
- Test: a deliberate runaway loop against a 50k-token budget gets cut off.

### Phase 3 — OpenAI surface

- Same pipeline on `/v1/responses` and `/v1/chat/completions`. Responses API is
  the priority for Codex app/CLI/IDE; Chat Completions remains useful for older
  OpenAI-compatible clients and direct Ollama-bound traffic.
- Preserve streaming for both surfaces; Chat Completions uses different SSE
  framing and can expose usage via `stream_options.include_usage`.
- First slices implemented: `src/bin/chisei-gateway.rs` proxies `/v1/responses`
  and `/v1/chat/completions` to OpenAI with streamed responses, optional
  virtual-key allowlisting, and fail-open/fail-closed `CheckBudget` preflight
  against Chisei. It also proxies Anthropic `/v1/messages` and
  `/v1/messages/count_tokens` with `x-api-key` virtual-key auth. OpenAI and
  Anthropic usage are recorded with `RecordUsage` and appended to `llm_calls`,
  including Responses `response.completed` events, Chat Completions
  `stream_options.include_usage` chunks, and Anthropic `message_start` /
  `message_delta` events. Budget denials and reachable governance outages emit
  Chisei `RecordGatewayAudit` events backed by Sekai's decision log. The gateway
  now calls `ResolvePolicy`,
  rewrites the top-level `model` field when policy resolves a different
  provider-compatible model, records `resolved_model`, and audits model rewrites.
  Virtual-key authentication failures are audited without storing bearer-token
  material. Referenced Sekai objects such as `ticker:{AAPL}` now produce
  object-context egress audit decisions for external provider calls.
  `chisei-gateway-setup` now seeds project/agent/key/budget/policy graph
  objects, applies a live budget limit, persists namespace policy objects, and
  seeds `llm_calls`. Gateway keys are stored as hashes on active Sekai
  `gateway_key` objects and used by runtime auth when the control plane is
  configured. Referenced object context now injects allowed fields into
  supported provider payload shapes and withholds denied fields from upstream.
  `ResolvePolicy` now exposes namespace eval-regression state; when a namespace
  is regressed, the gateway routes through the namespace default model and emits
  `gateway.eval_regression` audit evidence.

### Phase 4 — Routing

- `ResolvePolicy` per request; first slice rewrites the top-level `model` field
  with structured JSON parsing. If raw payload preservation matters, replace
  this with span-level JSON rewriting.
- Same-provider rewrites (opus→haiku) are cheap. Cross-provider downshift
  (Anthropic-API client → Ollama/OpenAI-compatible) is implemented as an
  explicit opt-in with `CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER=1`. First bridge:
  non-streaming Anthropic Messages → OpenAI Chat Completions request mapping,
  OpenAI chat response → Anthropic message response mapping, and
  `gateway.cross_provider_translate` audit evidence. Streaming and tool-call
  translation remain denied instead of silently approximated.
- Hook `src/chisei/egress.rs` guardrails: referenced objects now record
  redaction audit decisions and inject allowed context into supported OpenAI
  Responses, OpenAI Chat Completions, and Anthropic Messages payload shapes.
- Record policy rewrites and egress decisions as audit events, not only usage
  rows.

### Phase 5 — Eval and learning loop

- Read active eval/regression signals for the request namespace. Regression or
  low-confidence signals can force stronger models, review posture, or higher
  sampling. First gateway slice implemented: regressed namespaces bias
  `ResolvePolicy` toward the namespace default model and the gateway audits the
  routing pressure.
- Run `RunPipeline` on sampled calls to mine recurring failures, useful context,
  and model-selection evidence. First gateway slice implemented behind
  `CHISEI_GATEWAY_RUN_PIPELINE=1`: after completed calls, the gateway derives a
  bounded request spec, calls `RunPipeline`, stores `pipeline_sampled`,
  `sample_reason`, and `sample_rate` on `llm_calls`, and emits
  `gateway.sampled` audit evidence for sampled calls. Sampled calls with
  captured provider output now call `RecordSampleObservation` so the scoring job
  can judge them through `chisei_sample_observations`.
- Link high-value calls back to work units/tasks when the caller supplies a task
  id or the gateway can infer one from headers. Implemented for explicit
  `x-chisei-work-unit` / `x-chisei-task-id` headers: the gateway stores
  `work_unit_id` on `llm_calls`, creates/reuses `work_unit:<id>` and
  `llm_call:<request_id>` objects, and links them with `incurs_usage`.

### Phase 6 (later)

- Small usage dashboard. Implemented as `chisei-gateway report --html <path>`.
- Streaming support upstreamed into the llm adapters so `ExecutePlan` itself
  can stream. Implemented as additive gRPC APIs:
  `llm.LlmService/ChatStream` and `chisei.ChiseiService/ExecutePlanStream`.
  OpenAI-compatible Chat Completions streams parse content deltas plus
  `stream_options.include_usage` usage chunks; Anthropic Messages streams parse
  `content_block_delta`, `message_start`, and `message_delta` usage events.
  Existing unary `Chat` and `ExecutePlan` remain compatible.

## Repo mechanics

- New bin target in the existing crate (reuses lib, generated proto clients,
  config); add `axum` + `tokio-stream`. Workspace split (`crates/gateway`) only
  if dependency weight becomes a problem.
- Config via env, consistent with the server: `GATEWAY_PORT` (8788),
  `SEKAI_SOCKET` (default) / `CHISEI_GRPC_URL` (fallback), real provider keys,
  optional `GATEWAY_KEYS` allowlist override, and the Sekai-backed hashed
  gateway-key store seeded by `chisei-gateway-setup`.
- Tests: golden SSE passthrough fixtures, integration test against a fake
  upstream, and `scripts/chisei_gateway_smoke.sh` for a local fake-provider
  end-to-end check, including OpenAI Responses SSE and Anthropic Messages SSE
  passthrough plus dashboard export. The fake-provider smoke also verifies
  Codex CLI completion through the gateway when enabled with
  `CHISEI_GATEWAY_SMOKE_LIVE_CLIENTS=codex`. Final real-client compatibility
  uses `scripts/chisei_gateway_live_clients.sh install-codex-profile`,
  `doctor`, `codex-live-smoke`, `launch-codex-app`, and `claude-smoke`.
  `codex-live-smoke` requires the expected Codex output and a recent
  `codex-app` row in `chisei-gateway report --by agent --since 10m`. Claude
  Code live smoke is verified with `CHISEI_CLAUDE_MODEL=claude-fable-5`.
  Codex CLI/app traffic is visible in `llm_calls`, but the first live run
  returned upstream `401`/`403` until the OpenAI passthrough-auth rewrite mode
  was added; rerun `doctor` and `codex-live-smoke` with
  `CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1` and a real
  `OPENAI_API_KEY` before calling the Codex app path complete.

## Main risks

1. **SSE fidelity** — Claude Code is strict about event ordering/format.
   Mitigation: bytes-through, tap-don't-transform; phase 0 proves it first.
2. **API drift** — never rebuild payloads from typed structs; only surgical
   model-field rewrite; unknown endpoints proxy verbatim.
3. **Estimate accuracy for budgets** — preflight estimates are rough; the
   reconciliation in `RecordUsage` keeps the ledger honest when estimates miss.
4. **Latency** — two local UDS gRPC calls per request are sub-millisecond noise
   next to LLM latency; implemented `--no-preflight` /
   `CHISEI_GATEWAY_NO_PREFLIGHT=1` as a debugging escape hatch that skips
   `CheckBudget`, `ResolvePolicy`, and context-egress preflight while preserving
   caller auth and upstream provider-key rewrite.

Phases 0–2 are the useful core; each is a small, independently shippable PR.
Daily dogfooding starts at the end of phase 1.
