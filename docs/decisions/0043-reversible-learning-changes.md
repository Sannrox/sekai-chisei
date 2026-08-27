# ADR 0043: Keep learned changes inspectable and reversibly superseding

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/785
- Issue: https://github.com/Sannrox/sekai-chisei/issues/714
- Supersedes: none
- Superseded by: none
- Related: [ADR 0011](0011-separate-invariant-facts-and-evaluation-plans.md),
  [ADR 0026](0026-governed-branch-proposals.md)

## Context

Recorded learning candidates and evaluation evidence exist, but a passing
score or a status flag can still look like adoption. Operators cannot inspect
baseline versus candidate, bind an approval to exact evidence, activate one
change, or roll it back without rewriting the source learning.

## Decision

A recorded learning candidate is admitted as a `chisei.learning-change/v1`
record identified by `(namespace, learning_id)`.

The record binds baseline, candidate, and evidence digests. Source bodies stay
on the learning object and evaluation stores. The change never grants write or
permit authority. Inspection returns the stored before-and-after comparison.
Approval and activation bind those exact digests and are idempotent. Rollback
records a superseding lineage entry and restores the prior live status without
rewriting evidence. Missing, stale, changed, hidden, unknown, or lease-lost
inputs return the same unavailable result and enter explicit reconciliation.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Flipping only the learning object status would leave comparison, approval, and
reversible supersession uninspectable. Automatic activation from a passing
evaluation would expand authority. Deleting the candidate on rollback would
erase later review evidence.

## Consequences

Operators can inspect, approve, activate, and reverse a learned change without
manufacturing success. Follow-up work may add PostgreSQL parity and gRPC
transport.

## Validation

Pure tests cover before-and-after inspection, idempotent propose, approval,
activation, rollback that leaves evidence intact, stale-candidate denial,
hidden-identity non-disclosure, and lease-loss reconciliation.
