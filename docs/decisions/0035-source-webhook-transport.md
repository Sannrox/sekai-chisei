# ADR 0035: Admit signed source webhooks as object-sync transport

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/763
- Issue: https://github.com/Sannrox/sekai-chisei/issues/673
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0022](0022-source-batch-transactions.md)

## Context

ADR 0022 admits inbound records as plane-committed source batches. Pull
adapters already persist a batch and call `ApplySourceBatch`. Push delivery
still lacked a fail-closed way to enter that same identity and checkpoint
contract. A second webhook object id would duplicate retries. Trusting an
adapter-side HMAC check would move verification off the plane.

## Decision

A signed `sekai.source-webhook-delivery/v1` envelope is collection transport
only. The plane pins an Ed25519 verifying key for the namespace and source
instance, verifies the delivery, then maps it onto one `sekai.source-batch/v1`
whose idempotency key is the delivery id. `ApplySourceBatch` remains the
mutation and checkpoint owner.

Signatures prove authenticity only. Forged, expired, oversized, unpinned, or
wrong-producer deliveries fail closed before mutation. Exact replay is
idempotent. SQLite stores key pins. PostgreSQL pin surfaces stay unavailable;
batch apply keeps its existing backend path.

## Alternatives considered

Trusting adapter-verified source HMAC was rejected because the plane would
lose local proof. A separate webhook identity was rejected because retries
would diverge from pull sync. Storing source API credentials was rejected as
the wrong trust boundary.

## Consequences

Operators pin a webhook key and admit a signed bundle. Check runs remain
evidence observations. Follow-up work may add a gRPC transport.

## Validation

Deterministic fixtures cover accepted projection, exact replay, and fail-closed
forged, expired, oversized, unpinned, wrong-producer, and conflicting delivery
ids.
