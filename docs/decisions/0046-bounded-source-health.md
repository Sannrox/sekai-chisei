# ADR 0046: Expose bounded source health as an authorized projection

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/685
- Issue: https://github.com/Sannrox/sekai-chisei/issues/685 (#685)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0022](0022-source-batch-transactions.md),
  [ADR 0023](0023-generation-fenced-source-change-feeds.md),
  [ADR 0035](0035-source-webhook-transport.md)

## Context

Object sync already owns generation, offset, and cursor checkpoints. Operators
need checkpoint age, lag, last success, and a bounded failure class for each
source. A second health table, a live remote probe, or a second ACL would
invent progress beside the plane-owned checkpoint.

## Decision

Source health is a `sekai.source-health/v1` projection of authorized
`GetSourceSyncState` evidence. Identity is
`(namespace, source_instance, type_digest)`. The report names class
`healthy`, `delayed`, `blocked`, or `unavailable`, plus last success,
checkpoint age, lag, and a closed failure class. It never writes, advances a
checkpoint, stores credentials, or contacts a remote connector.

Namespace authority is checked before materialization. Hidden and unknown
sources share one unavailable result. Audit records class, namespace, failure
class, and outcome — not cursors, offsets, or secret-like text.

Unknown versions, foreign identity, invalid checkpoints, and ambiguous
lifecycle fail closed as non-success. Replay of the same durable state and
observation time is identical. A later report resumes from the current
checkpoint evidence.

SQLite and reusable PostgreSQL share `get_source_sync_state` and the same
in-process projector. There is no health persistence table.

## Alternatives considered

Returning raw sync state would leak cursors and force every operator to
re-derive class. A new health observation table would compete with the
checkpoint for truth. A live connector probe would invent availability
outside durable evidence and would store or require credentials.

## Consequences

Operators can inspect authorized source progress without a second lifecycle.
Follow-up work may add a gRPC transport. Domain connectors stay outside this
contract.

## Validation

Deterministic tests cover healthy, delayed, blocked, unavailable, and
hidden-source fixtures; unknown version, foreign identity, invalid
checkpoint, missing authority, and ambiguous lifecycle fail closed; replay
is idempotent; restart reads later durable success; audit omits cursors;
SQLite apply plus the shared projector cover persistence-backed reports.
