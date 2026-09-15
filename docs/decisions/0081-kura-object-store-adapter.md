# ADR 0081: Dual-read kura as the object instance store

- Status: accepted
- Date: 2026-09-15
- Owners: @Sannrox
- Related: [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0073](0073-source-and-action-objects.md)

## Context

Object instances and hop/join queries currently live in the sekai-chisei
SQL object-type index (SQLite or PostgreSQL). That mixes a growing object
graph with the control-plane ledger (tenants, policy, receipts). kura is a
side object log with ingest, object-set evaluate, property ACL, and Action
writeback. ADR 0080 keeps SQLite/PostgreSQL for the **control plane**.

## Decision

1. **Do not delete** the SQL object-type index or either community backend.
2. `SEKAI_OBJECT_STORE=sql|kura|dual` (default `sql`).
   - `sql`: current index only
   - `dual`: SQL evaluate, then kura evaluate; mismatch fail closed
   - `kura`: kura aggregates for hop evaluate (experimental)
3. Reindex **also** writes kura's namespace log when mode is `kura` or `dual`
   (`KURA_LOG_DIR`, default `data/kura`).
4. Cutover to kura-only requires a soak of `dual` and a later ADR. Spark
   stays unsupported in kura until an envelope.

## Consequences

Control-plane data stays in SQLite/Postgres. Object instances can be copied
into kura without changing EvaluateObjectSet's gRPC. Operators opt in.
