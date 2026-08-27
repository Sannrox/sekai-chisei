# ADR 0048: Expose governed event subscriptions with versioned cursors

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/794
- Issue: https://github.com/Sannrox/sekai-chisei/issues/691
- Supersedes: none
- Superseded by: none
- Related: [ADR 0037](0037-event-stream-projections.md)

## Context

ADR 0037 admits ordered event batches behind a producer checkpoint. Integrators
still need an independent consumer position with replay, retention, revocation,
and visibility filtering. A live broker or a second event log would make remote
transport or unadmitted storage into authority.

## Decision

A registered `sekai.event-subscription/v1` object is identified by
`(namespace, subscription_id)` and binds stream identity, schema revision, type
digest, definition digest, owner, retention bound, and authorized columns.

Delivery admits a caller-supplied page only when the stream pin still matches,
the stream checkpoint already covers the page end, and every named column is
authorized before any event is returned. The subscription cursor advances only
after a complete authorized page. Exact replay of the last admitted digest
returns `replayed` and does not move the cursor.

A gap, late offset, malformed page, hidden-field request, foreign owner,
revoked subscription, unknown identifier, unsupported revision, or expired
retention window is a typed non-success and leaves the cursor unmoved. Hidden
and unknown identifiers share one unavailable result. Recovery from retention
expiry is an explicit re-register.

The plane never opens a broker, stores source credentials, or claims
exactly-once external delivery. SQLite is the reference store. PostgreSQL stays
unavailable.

## Alternatives considered

Sharing the stream checkpoint as the only cursor would couple producers and
consumers. Consuming a live broker would make credentials and remote failure
into authority. Persisting a second event log would store records the plane did
not admit. Silent fallback after a gap, retention expiry, or revocation would
manufacture success.

## Consequences

Operators can subscribe, pull, inspect, and revoke a consumer cursor without
changing the producer checkpoint. Follow-up work may add gRPC transport or
PostgreSQL parity.

## Validation

Deterministic fixtures cover authorized delivery, restart, duplicate replay,
retention gap, cross-namespace denial, revocation, and hidden-identifier
non-disclosure.
