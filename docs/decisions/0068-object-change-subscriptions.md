# ADR 0068: Deliver object-change subscriptions from committed facts

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/864
- Issue: https://github.com/Sannrox/sekai-chisei/issues/838 (#838)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0037](0037-event-stream-projections.md),
  [ADR 0048](0048-governed-event-subscriptions.md),
  [ADR 0064](0064-event-stream-postgres-parity.md)

## Context

ADR 0048 already owns subscription identity, cursors, retention, and
revocation. The pull path still admits a caller-supplied page behind a
producer checkpoint. That is not a stream of committed object mutations.

## Decision

Accept `ReadObjectChangeSubscription` as a plane-owned projection over
already-committed create, update, and delete facts. Delivery reuses
`sekai.event-subscription/v1` identity, cursor, retention, and revocation.
The object store remains the system of record. Caller-supplied pages are
not object authority.

Clients snapshot, then stream. The cursor starts after an explicit snapshot
revision. A retention gap, expired cursor, authorization-pin change, or
stale revision is a typed `resnapshot_required`. Exact replay of the last
admitted digest returns `replayed` and does not move the cursor. Visibility
is rechecked on every page; newly hidden fields are not returned. Slow
consumers are disconnected with `slow_consumer`.

Scope for this slice is namespace plus kind, optional object identifiers,
and the existing `ListFilter` property-filter pin. ObjectSet descriptors
are not required.

## Alternatives considered

- Accepting caller-supplied event pages as authoritative object mutations.
- A live broker or exactly-once external-effect bus.
- A second event log copied out of `sekai_object_changes`.
- Blocking this slice on ObjectSet query composition.

## Consequences

Authenticated clients can keep a queried object scope current after a
snapshot without treating transport pages as writes. PostgreSQL uses the
same committed-change scan and subscription store as SQLite.

## Validation

A snapshot followed by insert, update, and delete converges to an
authoritative requery. Reconnect and duplicate replay preserve cursor
identity. Expired retention, authorization change, and revocation do not
leak hidden fields. Slow consumers disconnect explicitly.
