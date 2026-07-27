# Replica-safe shared state

Parent epic: [#117](https://github.com/Sannrox/sekai-chisei/issues/117).  
Inventory fixture: [`tests/fixtures/replica_safety/v1.json`](../tests/fixtures/replica_safety/v1.json).  
Harness: `src/db/replica_safety.rs` (`TwoReplicaSqlite`, `ReplicaSafetyInventory`).

## Goal

Multiple control-plane or gateway **replicas** must enforce the same governance
decisions without multiplying limits or diverging durable state. PostgreSQL is
the production shared authority. A single shared SQLite file is acceptable for
local multi-connection tests. Process memory may **cache** with a declared stale
bound; it must not **decide** durable authorization, budgets, or lifecycle
transitions.

## Authority classes

| Class | Meaning |
| --- | --- |
| `shared_store_required` | Only the shared store is authoritative. |
| `cache_allowed` | Process cache OK with `max_stale_ms`; reload must never widen authority. |
| `process_local_ok` | Non-authoritative helpers only (e.g. single-process eval scratch). |

Required authoritative surfaces are listed under
`required_authoritative_surfaces` in the inventory. Callers that treat a surface
as multi-replica authority must resolve it through
`ReplicaSafetyInventory::require_authoritative`, which fails closed for unlisted
or process-local IDs.

## Two-replica harness

`TwoReplicaSqlite::open()` creates a temporary SQLite file and two independent
`RuntimeDb::Sqlite` handles. `race_results` starts *N* workers (default patterns
use 2), synchronizes on a barrier, and returns each worker result. Pass/fail is
**behavioral** (overspend, double winner, missing durable row)—not a wall-clock
budget.

Smoke exercise (also a unit test): concurrent budget reserve of 6 against a
shared limit of 10 admits exactly one winner.

```rust
use sekai_chisei::db::replica_safety::TwoReplicaSqlite;

let pair = TwoReplicaSqlite::open()?;
// pair.a and pair.b share durable state on disk
```

PostgreSQL multi-replica races reuse the same inventory classes and should open
two `PostgresDb` pools against one `SEKAI_TEST_POSTGRES_URL` when available
(later slices; ignored without the URL).

## Non-goals

- Multi-region **active/active global SC** ledgers (rejected; design freeze:
  [research/292-multi-region-consistency.md](research/292-multi-region-consistency.md))
- Multi-region budget topology modes are documented in
  [budget-topology.md](budget-topology.md) (#294); leases/permits pins in #293
- Tenant quotas (#119)
- Managed HA packaging
- Exactly-once external side effects beyond the control plane

## Delivery slices

| Issue | Focus |
| --- | --- |
| #304 | Inventory + harness (this document) — landed |
| #305 | Shared budget under concurrent replicas (`tests/replica_safety_budget.rs`) |
| #306 | Leases, admission, recovery after replica loss (`tests/replica_safety_leases.rs`) |
| #307 | Credential/authority cache stale bounds (`tests/replica_safety_credentials.rs`) |
| #308 | Eval/portfolio off process-local authority (`tests/replica_safety_eval.rs`) |
| #309 | Parent closeout evidence suite (`tests/replica_safety_closeout.rs`) |

## Closeout evidence

Run the full replica-safety suite:

```bash
cargo test --test replica_safety_harness
cargo test --test replica_safety_budget
cargo test --test replica_safety_leases
cargo test --test replica_safety_credentials
cargo test --test replica_safety_eval
cargo test --test replica_safety_closeout
```

`replica_safety_closeout` re-checks inventory completeness and a single
two-replica smoke covering budget, lease, admission, credentials, recovery, and
eval sharing.

## Operator posture

For multi-replica production, select a shared backend (`SEKAI_DB_BACKEND=postgres`
and `DATABASE_URL`; see [configuration.md](configuration.md)). Do not run
multiple writers against independent SQLite files and expect shared budgets or
leases to converge. Process memory must not decide durable authorization.
