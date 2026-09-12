# ADR 0061: Inspect and preview quarantined source repairs without a second admission plane

- Status: accepted
- Date: 2026-09-12
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/852
- Issue: https://github.com/Sannrox/sekai-chisei/issues/820 (#820)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0022](0022-source-batch-transactions.md),
  [ADR 0046](0046-bounded-source-health.md),
  [ADR 0060](0060-additive-source-type-descriptors.md)

## Context

`GetSourceSyncState` already retains the latest quarantined batch result.
`ApplySourceBatch` already fences stale cursors and type revisions, preserves
source identity, and records a new attributable transaction. Operators still
needed a bounded inspect / preview / re-admit workflow. A second mutation
contract would invent write authority beside the existing admission plane.

## Decision

Inspection and preview are observational projections over the latest
`QUARANTINED` result and the live checkpoint / type fence. They never write,
never open a batch transaction, and never become apply authority.

Re-admission is existing `ApplySourceBatch`. A preview digest is not a permit
or receipt. A later submit must recheck live state. Latest-result quarantine
semantics are unchanged; historical quarantine search stays out of this slice.

Hidden and unknown sources share one unavailable shape. Inspect and preview
audit class, namespace, reason code, and outcome — not cursors, payloads, or
secret-like text.

## Alternatives considered

A new preview/apply RPC would create a second write plane. Treating a preview
as execution authority would create a time-of-check/time-of-use grant.
Auto-generating a correction from quarantine reasons would invent records the
operator did not submit.

## Consequences

Operators can inspect a safe quarantine view, dry-run a correction against the
live identity fence, and submit only through existing admission. Follow-up
work may add a gRPC transport; this slice is the local operator command.

## Validation

Deterministic tests cover sanitized inspect, stale preview and apply, successful
re-admission with a new outcome, hidden-source non-disclosure, invalid batches
that omit secret-like text, and audit that omits cursors.
