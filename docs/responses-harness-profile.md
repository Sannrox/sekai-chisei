# Responses harness profile v1

Chisei's native-harness boundary is `POST /v1/responses`. The host owns sessions,
tool execution, approvals, workspaces, recovery, and the iterative tool loop.
Chisei owns model routing and the policy, budget, egress, usage, audit, and receipt
decisions around each model call.

## Request contract

Clients may rely on `model`, `input`, `instructions`, `tools`, `tool_choice`,
`parallel_tool_calls`, `max_output_tokens`, `stream`, `metadata`, and
`previous_response_id`, plus `reasoning`, `text`, `temperature`, `top_p`, and
`truncation`. Chisei inserts `store: false`; caller-supplied `store: false` is
accepted and any other value is rejected. Other request fields are rejected before
upstream contact, so callers cannot opt into provider retention or select an
ungoverned service tier. Tool results use `function_call_output` input items and
identify the matching `call_id`. A request may contain multiple tool results.

This profile version rejects `Idempotency-Key` with `capability_unsupported` rather
than forwarding a key it cannot enforce. Clients must use a new attempt number for
an ambiguous retry and must assume that a disconnected provider call may have run.
Replay and conflicting-key detection will be advertised only by a later capability
revision that persists request hashes and terminal results.

Caller-supplied operation and parent identifiers are scoped to the authenticated
gateway identity. The gateway returns their canonical `chisei:<scope>:<id>` form;
clients reuse that returned value on later calls. An identifier from another caller
scope is rejected rather than attached to receipt lineage.

Authenticated clients discover the versioned provider matrix with
`GET /v1/chisei/capabilities`. Chisei derives required streaming, tool,
parallel-tool, structured-output, reasoning, modality, continuation, and built-in
tool capabilities from each Responses request. A route that cannot preserve every
requirement fails with `capability_unsupported` before upstream provider contact.
Built-in search, code, or MCP tools remain unavailable unless the selected profile
declares the exact external capability.

The discovery document also carries `registry_version` and versioned `profiles`.
Each profile publishes its provider and currently accepted model selectors,
lifecycle, protocol
surfaces, endpoint configuration source, request and response adaptations, usage
and error normalization versions, capability limits, pricing-metadata version, and
governance-metadata status. API-key environment names may be advertised, but
credential values are never part of capability discovery, policy, receipts, or
correlation metadata. Existing `paths` entries remain the compatibility view of
the same profile capabilities.

Registry v3 is the model-resolution authority for both the gateway and direct LLM
execution. Canonical model identifiers are `openai/<model>`,
`anthropic/<model>`, `ollama/<model>`, `native/<model>`, `xai/grok-4.5`, and
`meta/muse-spark-1.1`. Existing unprefixed
provider aliases remain accepted at the client boundary and are recorded as the
requested alias, while the canonical identifier and upstream model name are
resolved before policy or provider contact. Unknown namespaces fail closed.

xAI uses only `XAI_API_KEY` and `CHISEI_XAI_BASE_URL`; it never reuses OpenAI's
credential or endpoint. Meta's public-preview profile requires both
`META_MODEL_API_KEY` and an explicit `CHISEI_META_BASE_URL`. It is published as
`experimental` and cannot resolve until an operator explicitly promotes its
lifecycle. Provider-owned search and code tools remain disabled until separately
admitted as governed capabilities.

An operator with the separately configured gateway admin credential may change a
provider, profile version, model, or capability lifecycle through
`PUT /_chisei/admin/provider-lifecycle`. Changes require a non-empty reason, are
versioned, and become effective only after the gateway persists an audit event.
Disabled provider, profile, and model targets fail during registry resolution;
disabled capabilities disappear from the effective capability matrix. Discovery
exposes the current registry state version and lifecycle override history with
operator-supplied reasons redacted so credentials or incident details cannot
leak through discovery.

## Stream contract

SSE frames are ordered as received. Clients assemble text from
`response.output_text.delta`, function arguments from
`response.function_call_arguments.delta`, and output items by `item_id` and
`output_index`. Multiple calls may interleave, so assembly must not use a single
global argument buffer.

Exactly one terminal event is emitted when Chisei can write one:

- `response.completed`
- `response.failed`
- `response.cancelled`
- `chisei.response.interrupted`

`chisei.response.interrupted` means Chisei lost or terminated an upstream stream
after response headers. A client disconnect may prevent delivery of any terminal
event. Unknown event types and unknown fields must be preserved or ignored without
failing the stream state machine.

Terminal events carry normalized usage when known. Partial, failed, and cancelled
responses may report partial usage. Missing usage means unknown, never zero.

## Error taxonomy

Errors use `{ "error": { "type", "code", "message" } }` and stable classes:
`authentication_error`, `policy_denied`, `budget_exceeded`,
`capability_unsupported`, `invalid_request`, `request_conflict`, `rate_limited`,
`upstream_unavailable`, `upstream_timeout`, `upstream_invalid_response`, and
`internal_error`. HTTP status and provider details may vary; clients branch on
`error.code`. Retry only `rate_limited`, `upstream_unavailable`, and
`upstream_timeout`, respecting `Retry-After`.

The gateway returns correlation headers on success and error. Provider response ids
are optional continuation hints and are not operation identity.

## Deterministic fixtures

Sanitized fixtures under `tests/fixtures/responses/` exercise fragmented frames,
unknown events, interleaved tool calls, partial usage, failure, cancellation, and
interruption. They contain no credentials or production prompts.
