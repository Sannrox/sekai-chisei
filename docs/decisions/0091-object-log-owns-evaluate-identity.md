# ADR 0091: Object-log owns identity; SQL object_type_index is a rebuildable projection

- Status: accepted
- Date: 2026-09-26
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/944 (#944)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0081](0081-evaluate-reads-mikura-library.md),
  [ADR 0088](0088-one-object-log-host-many-clerk-clients.md)

## Context

#941 and #942 landed fail-closed dual-read of `EvaluateObjectSet` against a
tagged mikura object-log. #1082 / ADR 0088 made one object-log host the owner
of identity generations. Dual-read soak holds: hop count and sum match; a
mismatch, missing log, or missing `max_rows_scanned` fails closed; grammar
the tagged API cannot express keeps the SQL answer and skips the canary.

`EvaluateObjectSet` still treated SQL `object_type_index*` freshness as the
live graph. Action apply already wrote the clerk receipt first and ingested
into the configured log afterward; it did not write the SQL index. Operators
still had to reindex before evaluate would answer, which treated a rebuildable
projection as identity.

The tagged evaluate API is keyed by `(kind, key)` with no namespace. Answering
`EvaluateObjectSet` from that log would count every matching kind in the
process log, including other clerk namespaces. SQL index lookups are
namespace-scoped. Serving aggregates from the log would leak cross-namespace
counts.

## Decision

1. **Identity is the object-log.** Generations and typed-object identity live
   in the tagged mikura `Store` (local `SEKAI_OBJECT_LOG`) or, for append and
   load, the object-log host (ADR 0088). Clerk SQLite and PostgreSQL stay the
   dual community stores for tenants, receipts, policy, credentials, and
   definition revisions (ADR 0080).
2. **SQL `object_type_index*` is a rebuildable projection.** Existing tables
   are retained. `RegisterObjectTypeDatasource`, `ReindexObjectType`,
   `PutObjectTypeIndexEdit`, and `GetObjectTypeIndexStatus` remain projection
   maintenance. They are not object apply, not identity, and not recovery
   material. Delete the tables and rematerialize from registered sources plus
   Action receipts and the object-log.
3. **Action apply does not write the SQL index.** `SubmitActionInstance`
   records the clerk receipt, then ingests the admitted object into the
   configured log. A denied or unadmitted Action does not append. Catch-up
   after a post-receipt ingest failure stays best-effort (ADR 0081 amendment
   #1116).
4. **`EvaluateObjectSet` keeps the SQL projection as its serving index.**
   The page already reports `authority=false`. Dual-read remains the canary
   against the object-log. The clerk does not answer namespace-scoped
   evaluate from a `(kind, key)` log.
5. **Do not invent a host evaluate op.** The pinned host wire is append plus
   generation load. Hop evaluate through the host waits on a tagged,
   namespace-scoped evaluate.

## Alternatives considered

- **Answer ungrouped count from the local log.** Rejected: the tagged API
  has no namespace, so a sales evaluate would include other namespaces'
  objects of the same kind.
- **Drop SQL `object_type_index*` in this change.** Rejected: member pages,
  `group_by`, and namespace-scoped hops still need a serving projection.
- **Prefix log kinds with namespace.** Rejected: that rewrites identity
  `(kind, key)` and breaks existing logs and dual-read fixtures.

## Consequences

- Operators rebuild the serving projection with `ReindexObjectType`. It is
  not recovery material.
- Identity generations are read from the log (`Store::load` or host load).
- Namespace-scoped hop evaluate from the log waits on a tagged identity
  that includes namespace.
- Dual-read (`SEKAI_OBJECT_LOG_DUAL_READ`) remains a canary on the SQL
  serving path.

## Validation

- Action admit persists the clerk receipt and the object-log generation, and
  leaves `object_type_index_status` empty for that kind.
- Dual-read mismatch still fails closed.
- Clerk backend selection remains `SEKAI_DB_BACKEND=sqlite|postgres`.
