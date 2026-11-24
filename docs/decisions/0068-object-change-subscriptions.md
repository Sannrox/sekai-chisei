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

## Addendum: update values (#3037)

An update event carries the changed field's old and new value, so a consumer
need not requery to learn what changed. Values follow the `ListObjectChanges`
redaction for the same reader and are rechecked on every page; a withheld
update carries no values and sets `values_withheld` instead of the redaction
sentinel, so an empty value stays distinguishable from a hidden one. Guest and
shared-space readers, whose history is reconstructed per change against the
collaboration ceiling, fail closed with every update withheld. The page digest
covers values and flag. The lenient projection used by Action bindings and
agent wakes carries no values, so no durable binding state copies property
data.

## Addendum: ObjectSet membership (#3038)

`ReadObjectChangeSubscriptionRequest.object_set` (experimental, behind the
experimental RPC gate) subscribes to an ObjectSet descriptor instead of a
scope. Each page re-evaluates, as the reader, the objects the scanned history
touched and reports `enter` when one joins the set and `leave` when one
drops out: changed out, deleted, or no longer visible. A `leave` names only
the object id, with no field, value, or operation. The member ids the reader
last received are stored per subscription and committed in the cursor's
transaction, so a crash or another replica replays or continues the same
page; a revoke drops them. A resnapshot evaluates the whole set as the
reader and the following pages deliver it as `enter` events to a client that
starts empty, so the client's set and the stored ids never diverge through a
separately taken snapshot. The stored ids are bound to the revision and the
reader's authorization pin; a read with no matching ids restarts. The bound query digest is part of the authorization pin,
so a changed descriptor or definition restarts the subscription.

This slice covers property-filter and spatial descriptors. Traversal (one
hop or more), aggregation, and dataset-indexed kinds are refused with
`FAILED_PRECONDITION`, as is a set larger than 1,000 members. Join-property
hops follow once relation and join writes are re-evaluated on both ends.
