# Gateway and clients

`chisei-gateway` lets existing model clients use Chisei governance without
moving their sessions, tool loops, workspace state, or approval UI into the
control plane.

It exposes:

- OpenAI-compatible `/v1/responses` and `/v1/chat/completions`;
- Anthropic-compatible `/v1/messages` and `/v1/messages/count_tokens`; and
- `/healthz`, `/readyz`, and `/statusz` operator endpoints.

For each request, the gateway authenticates and attributes the caller,
preflights policy, budget, and egress decisions, resolves the provider/model,
streams the response, and records normalized usage and audit evidence.

## Guided launch

Check local prerequisites, then launch a supported client:

```bash
cargo run --bin sekaictl -- doctor codex-app
cargo run --bin sekaictl -- launch codex-app
```

or:

```bash
cargo run --bin sekaictl -- doctor claude-code
cargo run --bin sekaictl -- launch claude-code
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

Run `cargo run --bin sekaictl -- --help` and see its **Launch commands** section
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
for the equivalent `PlanExecution`/`ExecutePlan` flow. Receipts record the
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
cargo run --bin sekaictl -- launch codex-app --no-app
cargo run --bin sekaictl -- launch claude-code
cargo run --bin sekaictl -- launch codex-app
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

## Virtual keys

Manage hashed gateway keys through the CLI:

```bash
cargo run --bin sekaictl -- gateway key create codex-app \
  --agent codex-app \
  --project sekai-chisei \
  --gateway-key <generated-secret> \
  --budget 500000 \
  --allowed-model gpt-5.5
cargo run --bin sekaictl -- gateway key list
cargo run --bin sekaictl -- gateway key rotate \
  --gateway-key-name codex-app \
  --gateway-key <new-generated-secret>
cargo run --bin sekaictl -- gateway key revoke \
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

## Context selection and egress

Compatible clients can request exact graph fields with a top-level
`chisei_context` control field. The gateway removes it before forwarding and
injects only selected fields permitted by access and egress policy:

```json
{
  "model": "gpt-5.5",
  "input": "Analyze the selected evidence.",
  "chisei_context": {
    "objects": [
      { "ref": "ticker:AAPL", "fields": ["score", "confidence"] }
    ]
  }
}
```

Each selector uses one of `ref`, `id`, or `link_id`. An optional bounded
`retrieval` block selects eligible relations, direction, depth, object/link
counts, kinds, and fields. Access checks apply at every traversal step. The
gateway records requested, omitted, denied, and injected context without
turning graph values into trusted instructions.

Context expansion is evaluation-gated. A direct root selection can remain
available while related-object expansion is denied because it lacks a passing
candidate comparison or has regressed against its baseline.

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
