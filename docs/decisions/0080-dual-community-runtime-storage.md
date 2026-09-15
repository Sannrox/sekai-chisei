# ADR 0080: Keep dual community control-plane storage

- Status: accepted
- Date: 2026-09-15
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/906
- Issue: https://github.com/Sannrox/sekai-chisei/issues/870
- Predecessor: https://github.com/Sannrox/sekai-chisei/issues/869
- Supersedes: none
- Superseded by: none
- Related: [ADR 0064](0064-event-stream-postgres-parity.md),
  [ADR 0065](0065-workflow-action-postgres-parity.md),
  [ADR 0073](0073-source-and-action-objects.md)

## Context

The community control plane already persists on SQLite (default) and
PostgreSQL (`SEKAI_DB_BACKEND=postgres`). #869 asked whether to pick one
engine. Discussion 906 kept both until an embedded-PostgreSQL profile was
measured (cold start ≤ 5 s, on-disk ≤ 200 MB, Linux and macOS CI). That
envelope is published in
[docs/research/870-embedded-postgres-envelope.md](../research/870-embedded-postgres-envelope.md)
and the kill signals hold. #870 asked to retire the duplicate
implementation after that decision.

The envelope is not a pick. It shows a local PostgreSQL process can meet
those numbers. It does not show SQLite should be deleted, that PostgreSQL
should become the only runtime, or that a custom object store should
replace either. Portable ontology SQLite (`SEKAI_DB` / `sekai --db`) is a
different database from the control plane (`data/sekai.db`).

## Decision

1. **Keep both community control-plane backends.** SQLite is the local
   default. PostgreSQL remains the optional community backend. Shared
   conformance stays the contract; PostgreSQL suites stay ignored without
   an isolated `SEKAI_TEST_POSTGRES_URL`.
2. **Do not treat backend selection as object authority.** Graph
   persistence, source batches, and Action receipts remain the facts.
   Indexes and hop projections stay rebuildable
   ([ADR 0073](0073-source-and-action-objects.md)).
3. **Do not merge the ontology CLI database into the control plane.**
4. **Do not adopt a third control-plane store** from an unmeasured custom
   engine. A later single-binary or embed profile is a packaging ADR with
   its own envelope, not this decision.
5. Issue #870 closes as keep dual. It does not delete `postgres_*.rs` or
   SQLite migrations.

## Alternatives considered

- **SQLite only.** Rejected: community PostgreSQL already has parity
  migrations and shared harnesses; retiring it would drop an operator
  profile the envelope showed can stay local.
- **Embedded PostgreSQL only.** Rejected: the envelope proved
  feasibility, not that SQLite's 24 ms local default should go. No
  retained-data migration drill exists to force that cut.
- **Custom object database.** Rejected: no envelope shows the
  control-plane store, rather than hop query plans, is the miss.
- **Keep dual only until a later packaging envelope.** Compatible with
  this ADR. That follow-up must publish numbers and a fail-closed
  migration before deleting a backend.

## Consequences

Operators keep `SEKAI_DB_BACKEND=sqlite|postgres`. Contributors keep dual
migrations (SQLite `migrate_*` and `src/db/postgres/00NN_*.sql`) and
shared conformance. A future packaging ADR may pick one local binary;
until then neither backend is deprecated. Query-engine traits
(`SEKAI_OBJECT_INDEX_ENGINE`) stay independent of this storage pair.

## Validation

- Dual backend selection remains in `.env.example` and operator docs.
- Shared SQLite/PostgreSQL conformance continues to compile; PostgreSQL
  runs only with an isolated URL.
- The embed envelope remains the measured local PostgreSQL profile.
- Revisit only after a published packaging envelope and a retained-data
  round-trip of receipts, objects, and grants.
