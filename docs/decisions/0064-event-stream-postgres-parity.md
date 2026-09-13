# ADR 0064: Persist event projections and subscriptions on PostgreSQL without a second authority plane

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/859
- Issue: https://github.com/Sannrox/sekai-chisei/issues/822
- Supersedes: none
- Superseded by: none
- Related: [ADR 0037](0037-event-stream-projections.md),
  [ADR 0048](0048-governed-event-subscriptions.md)

## Context

ADR 0037 and ADR 0048 already own typed event-stream projections and
consumer cursors. SQLite is the reference store. Community PostgreSQL failed
closed until a migration, transaction, and conformance design existed. This
decision is backend parity, not a new broker or admission plane.

## Decision

PostgreSQL persists the same four identities as SQLite: stream bindings,
checkpoints, admitted event commitments, and subscriptions. Each accepted
binding write, checkpoint advance, event-commitment insert, or cursor advance
shares one transaction. Checkpoint and cursor writes compare-and-swap the same
generation, epoch, offset, and digest pins. Concurrent connections take a
transaction-scoped advisory lock on the stream or subscription identity; the
CAS predicates remain the commit rule.

A gap, late conflicting replay, malformed page, retention expiry, foreign
owner, revocation, stale generation, or definition mismatch stays the existing
typed non-success and leaves durable state unmoved. Capability discovery
advertises this surface only after the shared SQLite/PostgreSQL matrix is
present. This decision does not add gRPC transport or source credentials.

## Alternatives considered

Keeping PostgreSQL refused after the schema and CAS rules were already owned
by SQLite would treat backend selection as a second product contract. Writing
the checkpoint before event commitments, or advancing a cursor without a live
checkpoint check, would let a crashed connection advertise progress the other
backend cannot observe. Mapping this onto Evaluation, ActionInstance, or
object-sync tables would mix stream evidence with gates, effects, or
source-batch authority.

## Consequences

Operators can register, project, subscribe, pull, and revoke on community
PostgreSQL with the same typed outcomes as SQLite. Isolated PostgreSQL
conformance remains an ignored `SEKAI_TEST_POSTGRES_URL` test. gRPC transport
and object-change subscriptions stay out of this slice.

## Validation

Deterministic SQLite tests remain the reference. The shared matrix covers
accepted projection and page delivery, exact replay, gap, late, malformed,
retention, revocation, definition reset, stale CAS, and two-connection
checkpoint and cursor races.
