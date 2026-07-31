# Managed Shikigami routing compatibility

- Issue: [#471](https://github.com/Sannrox/sekai-chisei/issues/471)
- Date: 2026-07-31
- Status: compatibility slice implemented
- Fixture: `tests/fixtures/managed_shikigami_routing/v1.json`
- Follow-up: [#484](https://github.com/Sannrox/sekai-chisei/issues/484)

## Finding

Current public contracts are sufficient in shape, and #484 completed the
managed Shikigami model-loop compatibility slice without adding another
protocol or generic evaluation layer.

Do not introduce a generic hosted-workbench abstraction, an Aldunis concept, a
caller-selected tenant, or another model API. Keep the existing
`PlanExecution`/`ExecutePlanStream`, authenticated-context,
provider-credential resolver, routing, usage, and operation-receipt contracts.
Complete one vertical compatibility slice behind those contracts.

The implemented slice:

1. Admit enterprise-authenticated machine credentials to the three native
   execution RPCs and authorize their complete authenticated context against
   the requested namespace.
2. Resolve the selected provider credential from that context immediately
   before provider construction. The client receives no provider secret.
3. Preserve OpenAI and Anthropic tool-call deltas in `ChatStreamChunk` and
   remove the obsolete blanket rejection of tool-bearing provider streams.
4. Keep provider failure fail-closed. A host retry is a new, explicitly
   correlated attempt; Chisei does not silently change the physical route.

No Design Discussion is required because the protobuf already carries
messages, tools, streamed tool calls, normalized usage, route provenance, and
receipts. The identity and provider-credential resolver contracts already
define the required authority and secret boundaries. If implementation shows
that any field meaning must change, stop and open a Design Discussion.

## Situation-specific evaluation

This evaluation is intentionally limited to the managed Shikigami plane-model
boundary. It does not score unrelated providers, clients, or deployment
products.

| Required behavior | Current evidence | Result |
|---|---|---|
| Service principal reaches native plan/execute | The native planning and execution RPCs admit enterprise authenticated contexts and use the trusted service principal as the planning actor. | Pass |
| Missing, invalid, expired, wrong-resource, or insufficient-scope credential fails closed | Situation-specific tests exercise the complete context and refuse invalid authority before planning, provider construction, or receipt creation. | Pass |
| Operator policy selects physical route | Enterprise execution rejects a non-empty `route_override`; the synthetic request leaves it empty, and policy selects and records the canonical provider/model. | Pass |
| Provider secret remains server-side | Native execution resolves a tenant provider credential immediately before adapter construction. `SecretValue` is exposed only to that constructor and is absent from requests and receipts. | Pass |
| Tool-bearing stream round-trips | OpenAI and Anthropic decoders assemble fragmented, interleaved tool deltas. The normalized end-to-end stream retains call identity, tool name, and JSON arguments. | Pass |
| Usage and receipt are normalized | The synthetic execution produces normalized input/output tokens, tool calls, provider identity, and a complete operation receipt. | Pass |
| Provider failure and fallback are governed | A synthetic upstream failure records `model_stream_start_failed`, retains the planned route, and makes exactly one provider call. An explicit retry creates a distinct attempt under the same logical operation. | Pass |
| Community SQLite stays tenant-free | Community credentials remain unscoped and tenant-scoped resolution without an enterprise extension fails closed. | Pass |

The versioned fixture fixes this exact evidence set and binds every case to
the deterministic test that executes it. It deliberately carries only
synthetic identities and opaque credential references, leaves `route_override`
empty, and contains no provider secret or private deployment configuration.

## Contract and code evidence

- `proto/chisei.proto` already defines `ExecutionInput.tools`,
  `ExecutionInput.route_override`, `PlannedChatResponse.tool_calls`, normalized
  usage, and `ExecutePlanStream`.
- `proto/llm.proto` already defines streamed `tool_calls`; no additive wire
  field is needed.
- `src/grpc/mod.rs` authenticates bearer credentials, overwrites forged
  principal and tenant metadata, and installs `AuthenticatedContext`.
- `src/enterprise.rs` binds principal, credential kind, scopes, issuer,
  resource, expiry, and optional tenant in that trusted context.
- `src/provider_credentials.rs` keeps secrets inside `SecretValue`, provides a
  backend-neutral resolver, and refuses tenant-scoped community fallback.
- `src/grpc/chisei_service.rs` owns policy route selection, egress and budget
  checks, normalized terminal responses, and operation receipts.
- `crates/sekai-provider/src/llm/{openai,anthropic}.rs` identify the concrete
  tool-stream loss: text and usage are assembled, while provider tool deltas
  are not.

## Shikigami compatibility floor

Shikigami `v1.0.4` is the latest release at the time of this finding and does
not contain the Bash credential isolation merged as
`eab167d3e0b55e603bd1e5a0d4214a637ba63a32` in Shikigami PR #154.

The managed-host floor is therefore the first Shikigami release containing
that commit, intended as `v1.0.5+`. Local/non-managed compatibility remains
`v1.0.2+`. Sekai Chisei now supplies its half of the boundary. Managed
compatibility still requires the first Shikigami release containing that
commit.

## Rejected expansion

- A generic evaluation framework: the evidence is specific to service
  identity, route ownership, provider-secret containment, tool streams, and
  receipts.
- Client-selected exact routes: this would move physical routing authority out
  of operator policy.
- Tenant fields in community requests or SQLite: authority must come from the
  authenticated context.
- A second hosted model API: the existing native execution contract already
  has the required shape.
- Automatic provider fallback after an ambiguous call: changing physical route
  would obscure provenance and could duplicate effects.

## Exit

Retain the fixture as the compatibility evidence for #484. Do not publish
private provider credentials, deployment configuration, prompts, or service
logs as evidence.
