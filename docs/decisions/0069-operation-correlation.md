# ADR 0069: Stamp one caller operation identity on spans, receipts, and object changes

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: source Issue [#886](https://github.com/Sannrox/sekai-chisei/issues/886)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/886 (#886)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0068](0068-object-change-subscriptions.md)

## Context

The plane already binds `SubmitActionInstanceRequest.request_id` to the
action instance and receipt, and already accepts W3C `traceparent` at the
gRPC boundary. Downstream hosts also send `x-sekai-operation-id`. Nothing
proved that one external identity survived the inbound span, the receipt,
and the object-change event, and the header could disagree with
`request_id`.

## Decision

Treat `x-sekai-operation-id` and `request_id` as one opaque caller identity.
Stamp that identity on:

- span attribute `sekai.operation_id`
- `OperationReceipt.operation_id`
- `ObjectChange.operation_id` / `ObjectChangeEvent.operation_id` when the
  change was produced by the admitting action

The identity is never hashed from request content. Process-local generated
correlation ids stay on the `operation` span field and are not the
cross-plane join key. Mismatched header and `request_id` fail closed.

## Alternatives considered

- Derive the identity from namespace, object id, or payload digest. Rejected:
  equal ids would prove equal inputs.
- Keep generated-only span ids and document a join through receipts.
  Rejected: hosts cannot follow one key from the inbound request.

## Consequences

Additive proto field `operation_id` on `ObjectChange` and
`ObjectChangeEvent`. Existing generated correlation ids are unchanged.
HTTP surfaces reuse the same header name when they exist.

## Validation

A deterministic test drives `SubmitActionInstance` with the header,
`request_id`, and `traceparent`, and fails if any of the three carriers
omits or renames the identity.
