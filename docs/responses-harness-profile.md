# Responses harness profile v1

Chisei's native-harness boundary is `POST /v1/responses`. The host owns sessions,
tool execution, approvals, workspaces, recovery, and the iterative tool loop.
Chisei owns model routing and the policy, budget, egress, usage, audit, and receipt
decisions around each model call.

## Request contract

Clients may rely on `model`, `input`, `instructions`, `tools`, `tool_choice`,
`parallel_tool_calls`, `max_output_tokens`, `stream`, `metadata`, and
`previous_response_id`. Unknown request fields are forwarded only when the selected
provider profile declares them safe. Tool results use `function_call_output` input
items and identify the matching `call_id`. A request may contain multiple tool
results.

The optional `Idempotency-Key` header identifies one model-call attempt. Reusing a
key with a different request is an error. A retry after an ambiguous disconnect may
return the original result; clients must not assume a second provider execution.

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
