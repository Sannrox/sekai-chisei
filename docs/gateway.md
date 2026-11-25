# Gateway and clients

`chisei-gateway` is a protocol translator and thin policy-enforcement point. It
lets existing model clients use Chisei governance without
moving their sessions, tool loops, workspace state, or approval UI into the
control plane.

Direction: [ADR 0152](decisions/0152-gateway-is-the-model-egress-layer.md)
makes the gateway the model egress layer with its own egress policy, no calls
into Sekai or Chisei, and no `chisei_context`. [Policy mode](#policy-mode) is
that admission path. The rest of this page describes the current
`gateway.decide/v2` path, which stays supported until it is drained.

It exposes:

- OpenAI-compatible `/v1/responses`, `/v1/chat/completions`, and `/v1/models`;
- Anthropic-compatible `/v1/messages` and `/v1/messages/count_tokens`;
- `GET /v1/chisei/models` (`chisei.available-models/v1`);
- `GET /v1/chisei/capabilities` (`chisei.provider-capabilities/v1`, no grant
  semantics; not `DiscoverCapabilities`); and
- `/healthz`, `/readyz`, and `/statusz` operator endpoints.

For each request, the gateway authenticates and attributes the caller,
preflights policy, budget, and egress decisions, resolves the provider/model,
streams the response, and records normalized usage and audit evidence. By
default, budget/policy preflight uses the control-plane
`DecideGatewayExecution` RPC using `gateway.decide/v2` (Issues #163 and #418).
The same decision also runs the internal sampling pipeline when request text is
available; there is no separate pipeline RPC or gateway sampling mode.
A missing, corrupt, or blocking context-admission policy denies admission.
A pipeline or sampling error after admission also denies when `pipeline_spec`
was set. A configured gateway has no legacy
multi-RPC fallback: denial or control-plane unavailability stops the request
before provider contact. The control plane owns policy, budget, lifecycle,
evaluation, capability, and route decisions; the gateway translates supported
wire formats and enforces the returned decision.

Gateway coordination has three Chisei RPCs: `DecideGatewayExecution`,
`RecordUsage`, and `ClaimGatewayDispatch`. Sample observations are folded into
trusted usage recording. The claim call combines
alias reservation and dispatch-token claiming into one atomic operation.
Normalized usage and the complete canonical operation receipt are persisted in
one trusted `RecordUsage` accounting call; generic gateway audit facts use the
Sekai decision log rather than a gateway-specific audit RPC.

The v2 contract is a coordinated gateway/control-plane upgrade. Mixed v1/v2
deployments reject admission rather than silently reconstructing missing policy
fields at the gateway.

## Guided launch

Check local prerequisites, then launch a supported client:

```bash
cargo run -p sekaictl -- doctor codex-app
cargo run -p sekaictl -- launch codex-app
```

or:

```bash
cargo run -p sekaictl -- doctor claude-code
cargo run -p sekaictl -- launch claude-code
```

The launcher reads unset values from `./.env`, starts the control plane and
gateway when needed, creates local credentials, applies migrations, seeds the
client identity, policy, model, and budget, and opens the client. Spawned service
logs are written under `./data/logs/`.

Useful launch options include:

```text
--no-app          start the governed stack without opening a client
--model <model>   set the namespace default or client model
--project <name>  change project attribution
--budget <tokens> set the seeded token budget
--gateway-bind    change the local gateway address
```

Run `cargo run -p sekaictl -- --help` and see its **Launch commands** section
for the current option set.

## Upstream authentication modes

### Gateway-owned credentials

Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. The client authenticates to the
gateway with a Chisei virtual key; the gateway replaces it with the matching
provider credential upstream.

This mode is suitable for headless workers, CI, and deployments where one
operator owns provider credentials and policy.

### Same-provider client passthrough

The guided launcher can preserve a supported client's existing provider login.
The gateway forwards the same-provider authentication header while using
`x-chisei-agent` and `x-chisei-project` for attribution.

To pin one governed request to an exact discovered route, set
`x-chisei-route-override: <canonical-provider/model>`. The override bypasses
cheap/capable selection only; lifecycle admission, sensitive-data provider
safety, and budget admission still apply. An unavailable or inadmissible target
is rejected without fallback. Native clients use `ExecutionInput.route_override`
for the equivalent `PlanExecution`/`ExecutePlanStream` flow. Receipts record the
override target and `bias_bypassed=true` on the routing event.

Passthrough credentials form a narrow in-memory trust boundary. They are used
to authenticate and forward the request but must not be stored in graph data,
receipts, or audit evidence. All `x-chisei-*` headers are stripped before the
provider request leaves the gateway. Cross-provider and local routes strip
client provider authentication.

Provider account terms can change. Operators are responsible for confirming
that proxying a client subscription is permitted for their account and use
case. Prefer provider API keys when terms or deployment policy are unclear.

## Model routing

The gateway chooses the upstream from the policy-resolved model, not only the
incoming wire shape:

| Resolved model | Upstream |
| --- | --- |
| `gpt-*` or Codex model | OpenAI-compatible upstream |
| `claude-*` | Anthropic-compatible upstream |
| `ollama/<name>` | `CHISEI_OLLAMA_BASE_URL`; prefix removed and no upstream auth |
| configured xAI or Meta profile | Profile-specific OpenAI-compatible upstream |
| other model | `NATIVE_LLM_URL` |

One gateway can serve Codex and Claude Code at the same time. Bring up the
shared stack without opening an application, then launch either client:

```bash
cargo run -p sekaictl -- launch codex-app --no-app
cargo run -p sekaictl -- launch claude-code
cargo run -p sekaictl -- launch codex-app
```

The launcher merges each client's allowed runtimes and models into the shared
namespace policy rather than replacing the other client's settings.

Cross-provider translation is disabled by default. Set
`CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER=1` only when the supported lossy bridge is
acceptable. Unsupported tool-call streaming is denied instead of silently
dropping tool semantics.

## Codex behavior

`sekaictl launch codex-app` temporarily installs a `chisei` provider in the
user Codex configuration, waits while the app runs, and removes its changes on
exit or Ctrl-C while preserving unrelated edits. `--keep-config` leaves the
routing in place.

Codex scopes conversation history by provider. Conversations created through
the `chisei` provider appear separately from normal `openai` conversations and
reappear under their original provider after the temporary configuration is
removed.

For repeatable CLI checks without changing the main configuration, use the
repository helper. It writes `~/.codex/chisei.config.toml`:

```bash
scripts/chisei_gateway_live_clients.sh install-codex-profile
scripts/chisei_gateway_live_clients.sh doctor
scripts/chisei_gateway_live_clients.sh codex-live-smoke
```

## Claude Code behavior

Claude Code is configured through process-scoped environment variables. The
launcher points `ANTHROPIC_BASE_URL` at the gateway root URL—with no `/v1`
suffix—and supplies attribution headers. These values disappear when the
process exits.

For manual testing:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
export ANTHROPIC_CUSTOM_HEADERS=$'x-chisei-agent: claude-code\nx-chisei-project: sekai-chisei'
claude -p 'Reply with exactly: chisei gateway claude smoke ok'
```

The gateway's own Anthropic upstream uses `CHISEI_ANTHROPIC_BASE_URL`, which
defaults to `https://api.anthropic.com/v1`. It deliberately does not reuse the
client-facing `ANTHROPIC_BASE_URL`.

## Explicit direct-provider fallback

The gateway never forwards automatically when the control plane is
unavailable. To keep working without Sekai Chisei, explicitly return the client
to its normal provider configuration:

- Codex: let `sekaictl launch codex-app` restore the original configuration, or
  quit the app and rerun the launcher so it recovers a stale managed config.
- Claude Code: start a new `claude` process without the launcher's
  `ANTHROPIC_BASE_URL` and `ANTHROPIC_CUSTOM_HEADERS` environment.

Direct-provider calls are outside Sekai Chisei. They have no Chisei policy or
budget enforcement, governed routing or context filtering, operation receipts,
or usage recovery. Switching back is an explicit client/operator action, not a
gateway availability mode.

## Virtual keys

Manage hashed gateway keys through the CLI:

```bash
cargo run -p sekaictl -- admin gateway key create codex-app \
  --agent codex-app \
  --project sekai-chisei \
  --gateway-key <generated-secret> \
  --budget 500000 \
  --allowed-model gpt-5.5
cargo run -p sekaictl -- admin gateway key list
cargo run -p sekaictl -- admin gateway key rotate \
  --gateway-key-name codex-app \
  --gateway-key <new-generated-secret>
cargo run -p sekaictl -- admin gateway key revoke \
  --gateway-key-name codex-app
```

Only SHA-256 hashes are stored on Sekai `gateway_key` objects. Running gateways
cache successful lookups briefly. When the admin endpoint is enabled, clear the
cache after rotation or revocation:

```bash
CHISEI_GATEWAY_ADMIN_TOKEN='<random-32-byte-minimum-token>' \
cargo run -p chisei-gateway --bin chisei-gateway -- refresh
```

`GATEWAY_KEYS=key=agent:project` remains an explicit environment allowlist for
development and Docker Compose. Do not confuse it with control-plane
principal credentials.

## Policy mode

Set `CHISEI_GATEWAY_POLICY_PATH` to a policy file and the gateway admits
requests against that file alone. It does not need, and does not call, Sekai
or Chisei: `CHISEI_GRPC_URL` and `SEKAI_SOCKET` are ignored, and requests keep
flowing while the control plane is down. Policy mode refuses to start with
`GATEWAY_KEYS` or `CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH`; the policy names
every principal and key.

```json
{
  "format": "chisei.gateway-policy/v1",
  "generation": 1,
  "instances": 2,
  "principals": [
    {
      "name": "codex-app",
      "project": "sekai-chisei",
      "sekai_principal": "agent:codex-app",
      "key_sha256": ["<sha256 hex of the client key>"],
      "routes": [
        {"provider": "openai", "models": ["gpt-5.5", "gpt-5.5-mini"]},
        {"provider": "ollama", "models": ["*"]}
      ],
      "limits": [
        {"requests": 60, "window_secs": 60},
        {"requests": 5000, "window_secs": 86400}
      ]
    }
  ],
  "models": [
    {"model": "gpt-5.5", "limits": [{"requests": 600, "window_secs": 60}]}
  ],
  "egress": [
    {"provider": "openai", "data_classes": ["unknown", "public", "internal"]},
    {"provider": "ollama", "data_classes": ["unknown", "public", "internal", "sensitive"]}
  ]
}
```

- `key_sha256` holds `printf %s "$KEY" | shasum -a 256` of each client key.
  Keys are never stored or published in clear.
- A route names a provider (`openai`, `anthropic`, `ollama`, `native`, `xai`,
  `meta`) and the models the principal may reach there, by the name within the
  provider (`gpt-5.5`), the canonical id (`openai/gpt-5.5`), or `*`. Policy
  mode never rewrites the requested model, and `auto` is refused.
- `limits` are fixed request windows. A short window is a rate limit, a long
  one a quota. Principal limits count that principal's requests; `models`
  limits count every principal's requests to that model. Each instance
  enforces `ceil(requests / instances)` with its own counter, so traffic
  spread across instances can overshoot slightly.
- `egress` lists, per provider, the data classes a request may carry there. A
  request's class comes from `x-chisei-data-class`, or `unknown` without one.
  Every provider a route names needs an egress rule.
- `sekai_principal` maps the principal to a Sekai principal; it defaults to
  the name.
- `log_reader: true` lets the principal read and acknowledge the egress log
  (below). Chisei reads with such a principal.

Every denial (unknown key, route, data class, limit, no valid policy) returns
before any provider contact: `401`, `403 policy_denied`,
`403 data_class_denied`, `429 rate_limit_exceeded`, or
`503 policy_unavailable`.

The gateway reads the file at start and checks it for changes every two
seconds. A changed file must raise `generation`. A file that does not parse,
fails validation, or keeps the active generation is rejected whole: the
previous generation stays active and `/readyz` reports `policy_reload_error`.
Without any valid generation, every request is denied and `/readyz` returns
`503 no_valid_policy`.

`GET /_chisei/policy` returns the active generation without keys to any
principal of the policy. Chisei reads it there.

### Egress log

In policy mode the gateway appends an admission record to its own log before
provider contact, and a usage record when each provider attempt ends (#3095).
Each append is synced to disk first. If the admission cannot be recorded, the
request is denied with `503 log_unavailable` and the provider is never
contacted. While the latest append is failing, `/readyz` returns
`503 log_unavailable`. A usage record that cannot be written does not change a
response already sent.

The log lives in `CHISEI_GATEWAY_LOG_DIR`, by default `chisei-gateway-log`
beside the policy file. The gateway does not start if it cannot open the log,
or if another process already owns it. Each record carries a sequence that
continues without gaps across restarts. If a crash leaves a partial final
record, it is dropped on start. A crash after the admission and before the
provider call leaves that admission without a usage record.

A `log_reader` principal reads records in order:

- `GET /_chisei/log?after=<seq>&limit=<n>` returns `chisei.gateway-log/v1`
  records with a sequence after `after`, at most `n` (default 100, maximum
  1000). Each record names its `kind` (`admission` or `usage`) and its
  `request_id`. A usage record also carries the attempt's Operation Receipt
  (`receipt`) and `llm_calls` row (`llm_calls_row`), built by the same code
  that sends them to Chisei and Sekai, so a reader can write them as they are
  (#3132). An accounting-only attempt has neither.
- `POST /_chisei/log/ack` with `{"seq": N}` tells the gateway that records up
  to `N` are committed elsewhere. They are no longer served and may be
  deleted. Nothing unacknowledged is ever deleted. Acknowledging a sequence
  past the last record is refused with `409 invalid_ack`.

Back up the log directory with the policy file.

### Chisei reads the log

The combined server reads each gateway named in `CHISEI_GATEWAY_LOGS`
(`name=base_url`, comma-separated) with the `log_reader` key given for it in
`CHISEI_GATEWAY_LOG_KEYS` (`name=key`). A `chisei-plane` process refuses to
start with either set, because the writes need both stores (#3096). A
`sekai-plane` process accepts them only to read the gateways' policies
([below](#reads-withhold-what-a-readers-egress-may-not-receive)) and reads no
log.

For each gateway Chisei keeps a cursor, the highest committed sequence, in
the Sekai store. It reads the records after the cursor and:

- writes each usage record's Operation Receipt to the Chisei store. Writing
  the same receipt again changes nothing;
- writes each usage record's `llm_calls` row and one decision entry per
  record (`gateway.admission` for an admission, `operation.receipt.upsert` for
  a usage record with a receipt) in the Sekai transaction that moves the
  cursor;
- acknowledges the new cursor to the gateway after that transaction commits.

The cursor moves only from the value the batch was read at. When several
Chisei instances read one gateway, one commits each batch and the others
write nothing and read again. A restart resumes from the cursor; a crash
between the commit and the acknowledgement rereads records the cursor already
covers, skips them, and acknowledges. An admission without a usage record (the
call was never forwarded) leaves its decision entry and no `llm_calls` row.
Decision entries are named `gateway-log:<gateway>:<seq>`.

Each gateway is a gRPC health service, `chisei.gateway_log.<name>`. It is
`NOT_SERVING` while reads fail and the reader retries with backoff up to 30
seconds; other gateways and the server's own health are unaffected. Receipts
lag while a gateway is unreachable. The reader stops, and reports why, when
the gateway's log ends before the cursor (a replaced log) or has dropped
records the cursor does not cover.

Not yet in policy mode: `x-chisei-request-id` dispatch deduplication and
cost or token quotas.

### Reads withhold what a reader's egress may not receive

Every process that serves Sekai polls `GET /_chisei/policy` of each gateway in
`CHISEI_GATEWAY_LOGS` every 2 seconds with its `log_reader` key
([ADR 0164](decisions/0164-reads-withhold-what-a-readers-egress-may-not-receive.md)).
Reads then remove each property value whose schema `classification` may not
reach a route the reader can use:

- a Sekai principal maps to the gateway principals whose `sekai_principal`
  (default `name`) names it, and receives the classes every provider on their
  routes lists in `egress`;
- an unmapped principal, or one whose mapping has no route, receives only the
  classes every provider of every configured policy lists;
- a gateway whose policy is unread or failed its last read releases nothing.
  It reports `NOT_SERVING` under the gRPC health service
  `chisei.gateway_policy.<name>` until the next good read.

`GetObject`, `EvaluateObjectSet`, `Search`, `ExpandNeighborhood`, and
`GetLineage` list the withheld properties of the returned kinds in
`withheld_properties`, with reason `egress_not_allowed` or `egress_unknown`.
A filter, sort, or facet naming a withheld property is refused with
`PERMISSION_DENIED`, and Search does not match it. With no gateway configured,
reads are unchanged.

## Native execution through the gateway

Native execution (`PlanExecution`, then `ExecutePlanStream`) can egress through
the gateway so provider keys live only there (ADR 0152, #2700). Configure the
control plane with:

- `CHISEI_GATEWAY_KEY`: a gateway client key for the control plane;
- `CHISEI_GATEWAY_URL`: the gateway origin (default `http://127.0.0.1:8788`);
- `CHISEI_GATEWAY_PROVIDED_PROVIDERS`: the providers to send there, for example
  `openai,anthropic`.

Chisei still plans, admits, and budgets the call. It then sends the
provider-shaped request to the gateway as an ordinary principal. The gateway
applies its own governance, swaps in the provider key it holds, and records its
usage row. The native receipt still names the plan. Only `openai` and
`anthropic` are routed this way. Other providers, hosted routing profiles, and
hosted embedding catch-up keep calling their endpoints directly with the keys
this process holds.


The gateway injects no graph data (ADR 0152, #2696). A request with a
top-level `chisei_context` field is refused with `400 invalid_request_error`
before any decision or provider contact, in policy mode and on the
`gateway.decide/v2` path alike. Object references in the request text are
forwarded as written; the gateway no longer looks them up. Select context
through native planning (`PlanExecution`), or read it with the MCP read tools
(`Search`, `GetObject`, and `ExpandNeighborhood`).

## Usage and smoke tests

Inspect recent normalized usage:

```bash
SEKAI_SOCKET=./data/sekai.sock \
cargo run -p chisei-gateway --bin chisei-gateway -- report --by agent --since 24h
```

Export a standalone report:

```bash
SEKAI_SOCKET=./data/sekai.sock \
cargo run -p chisei-gateway --bin chisei-gateway -- report --since 24h --html dashboard.html
```

Run the deterministic local gateway smoke test without real provider
credentials:

```bash
scripts/chisei_gateway_smoke.sh
```

The harness starts a temporary control plane and fake provider upstreams,
exercises virtual-key and passthrough requests, verifies streaming and auth
rewrites, and checks usage reporting. Live client checks remain opt-in because
they depend on installed clients and account state.

Read [configuration](configuration.md#gateway) for the complete stable setting
reference and [operations](operations.md#gateway-safeguards) before exposing the
gateway beyond loopback.
