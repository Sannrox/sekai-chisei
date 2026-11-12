# Replica-safe shared state

Parent epic: [#117](https://github.com/Sannrox/sekai-chisei/issues/117).  
Inventory fixture: [`tests/fixtures/replica_safety/v1.json`](../tests/fixtures/replica_safety/v1.json).  
Harness: `crates/sekai-core/src/db/replica_safety.rs` (`TwoReplicaSqlite`, `ReplicaSafetyInventory`).

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
| `process_local_ok` | Non-authoritative helpers only (e.g. single-process eval scratch, operator console cookies). |

Required authoritative surfaces are listed under
`required_authoritative_surfaces` in the inventory. Callers that treat a surface
as multi-replica authority must resolve it through
`ReplicaSafetyInventory::require_authoritative`, which fails closed for unlisted
or process-local IDs. Operator console cookies (`ops.console.sessions`) are
`process_local_ok`; they do not converge across replicas ([ADR 0150](decisions/0150-process-local-console-sessions.md)).

## Two-replica harness

`TwoReplicaSqlite::open()` creates a temporary SQLite file and two independent
`RuntimeDb::Sqlite` handles. `TwoReplicaPostgres::open()` creates one isolated
PostgreSQL database named with the process id plus a unique suffix and two
independent `PostgresDb` pools against it (ignored without
`SEKAI_TEST_POSTGRES_URL`). `race_results` starts *N* workers (default patterns
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

```rust
use sekai_chisei::db::replica_safety::TwoReplicaPostgres;

let pair = TwoReplicaPostgres::open()?;
// pair.a and pair.b are independent pools on one isolated database
```

CI runs the PostgreSQL suite whenever `SEKAI_TEST_POSTGRES_URL` is set
(`scripts/postgres-conformance.sh`, filter `postgres`). This is conformance
evidence, not a production high-availability claim.

### PostgreSQL two-replica inventory (#2087)

| Class | Result | Evidence |
| --- | --- | --- |
| Lease fencing | pass | `tests/replica_safety_postgres.rs` concurrent acquire; replica-loss takeover |
| Action admission and parked grants | pass | concurrent work admission; concurrent parked grant (one winner, one object write) |
| Retention ticks | pass | concurrent ticks archive each content-event once; idle ticks with no policy skip the walk (#2028, #2029) |
| Agent-turn claims | pass | concurrent `claim_next` has one winner (`SKIP LOCKED` / claim index, #2031) |
| Crash takeover | pass | `pg_terminate_backend` of replica A's uncommitted object/Action mutation; B grants exactly once |
| Object-then-Action lock order | pass | concurrent parked grants lock a real target object then the Action (#2036) |

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
cargo test --test it replica_safety_harness
cargo test --test it replica_safety_budget
cargo test --test it replica_safety_leases
cargo test --test it replica_safety_credentials
cargo test --test it replica_safety_eval
cargo test --test it replica_safety_closeout
SEKAI_TEST_POSTGRES_URL=... cargo test --test it replica_safety_postgres -- --ignored
```

`replica_safety_closeout` re-checks inventory completeness and a single
two-replica smoke covering budget, lease, admission, credentials, recovery, and
eval sharing. PostgreSQL two-replica evidence is `replica_safety_postgres`
(ignored without `SEKAI_TEST_POSTGRES_URL`).

## Operator posture

For multi-replica production, point every Combined replica at the same
dest-pair (`SEKAI_DATABASE_URL` + `CHISEI_DATABASE_URL` with
`SEKAI_DB_BACKEND=postgres`; see [configuration.md](configuration.md)). A
single `DATABASE_URL` is retired and refuses boot. Do not run multiple writers against independent SQLite
files and expect shared budgets or leases to converge. Process memory must not
decide durable authorization.
