# ADR 0065: Persist workflow bindings and callbacks on PostgreSQL without a second admission plane

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/861
- Issue: https://github.com/Sannrox/sekai-chisei/issues/823 (#823)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0054](0054-workflow-action-bridge.md)

## Context

ADR 0054 already maps external workflow steps through ActionInstance
admission. SQLite is the reference store. Community PostgreSQL failed closed
until a schema and atomicity design existed. This decision is backend parity,
not a scheduler or a second admission plane.

## Decision

PostgreSQL persists the same binding, callback, and command-replay identities
as SQLite. `commit_workflow_transition` remains the only write and shares one
transaction for the expected-binding compare-and-swap, optional callback, and
command row. Concurrent connections take a transaction-scoped advisory lock on
`(namespace, binding_id)`; expected-binding equality and unique keys remain the
commit rule.

A stale generation, foreign owner, conflicting command, or mismatched callback
stays the existing typed unavailable result. Capability discovery advertises
this surface only after the shared matrix is present. Adapters still cannot
write graph, policy, budget, or receipt rows.

## Alternatives considered

Keeping PostgreSQL refused after the transition already had one atomic owner
would treat backend selection as a second product contract. Splitting binding,
callback, and command across transactions would let a crashed connection
advertise a later cursor without replay evidence.

## Consequences

Operators can submit, park, callback, cancel, and reconcile on community
PostgreSQL with the same typed outcomes as SQLite. Isolated PostgreSQL
conformance remains an ignored `SEKAI_TEST_POSTGRES_URL` test.

## Validation

Deterministic SQLite fixtures remain the reference. The shared matrix covers
first insert, park, cancel, exact command replay, foreign owner, stale
expected binding, and two-connection callback/cancel races.
