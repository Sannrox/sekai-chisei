# Managed Shikigami routing compatibility

- Issue: [#471](https://github.com/Sannrox/sekai-chisei/issues/471)
- Date: 2026-07-31
- Status: focused implementation required
- Fixture: `tests/fixtures/managed_shikigami_routing/v1.json`
- Follow-up: [#484](https://github.com/Sannrox/sekai-chisei/issues/484)

## Finding

Current public contracts are sufficient in shape, but the implementation is
not yet sufficient for a managed Shikigami model loop.

Do not introduce a generic hosted-workbench abstraction, an Aldunis concept, a
caller-selected tenant, or another model API. Keep the existing
`PlanExecution`/`ExecutePlanStream`, authenticated-context,
provider-credential resolver, routing, usage, and operation-receipt contracts.
Complete one vertical compatibility slice behind those contracts.

The required follow-up is implementation, not a new protocol decision:

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
| Service principal reaches native plan/execute | Static community credentials authenticate, but enterprise-scoped credentials are rejected because `PlanExecution`, `ExecutePlan`, and `ExecutePlanStream` are absent from `enterprise_namespace_method`. | Blocked |
| Missing, invalid, expired, wrong-resource, or insufficient-scope credential fails closed | Missing/invalid and expiry tests exist. `AuthenticatedContext` defines issuer, resource, expiry, and scopes, but Chisei execution does not yet consume the complete context. | Partial |
| Operator policy selects physical route | `route_override` is optional and empty in the fixture. Planning resolves and records the canonical provider/model; caller metadata cannot supply authority. | Pass |
| Provider secret remains server-side | The resolver contract uses `SecretValue` and opaque credential references, but production Chisei/LLM execution does not call `resolve_provider_credential`. | Blocked |
| Tool-bearing stream round-trips | The public `ChatStreamChunk` already has `tool_calls`. The OpenAI and Anthropic SSE decoders currently discard tool-call deltas, and capability enforcement rejects tool-bearing streams. | Blocked |
| Usage and receipt are normalized | Terminal native execution already writes normalized token fields and an operation receipt. This path becomes reusable once tool streaming works. | Partial |
| Provider failure and fallback are governed | Stream start/read failures record bounded failure reasons. Native execution performs no silent physical-route fallback, which satisfies the issue's fail-closed constraint. A host may submit a separately correlated retry. | Pass |
| Community SQLite stays tenant-free | Community credentials produce an unscoped machine context; tenant-scoped provider resolution without an enterprise resolver fails closed. | Pass |

The versioned fixture fixes this exact evidence set. It deliberately carries
only synthetic identities and opaque credential references, leaves
`route_override` empty, and contains no provider secret or private deployment
configuration.

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
`v1.0.2+`. Until both that release and the Sekai Chisei follow-up ship, the
managed route is not compatible.

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

Ship the fixture with this finding, implement the vertical slice in #484, and
close #471. Do not publish private provider credentials, deployment
configuration, prompts, or service logs as evidence.
