# Selective bitemporal history storage

This note covers the SQLite storage delivered by Issue #225 (ADR 0004).
Atomic graph-mutation coupling, historical RPCs, and retention collection are
tracked separately (#226–#228).

## What landed

- Versioned **temporal policy registry** per namespace and schema surface
  (`object_type`, `property`, or `relation`).
- Namespace-scoped **assertion versions** with known / unbounded / unknown
  valid bounds and system-assigned recorded revisions.
- Monotonic **commit revision** counter (`sekai_temporal_revisions`).
- Prospective enablement (no invented earlier history) and explicit bounded,
  idempotent **baseline backfill** that marks domain validity unknown.
- Empty shared structures on every database; non-temporal mutations leave
  history tables empty.

Domain and persistence entry points live in `src/sekai/temporal.rs`. Tables:

| Table | Role |
| --- | --- |
| `sekai_temporal_policies` | Opt-in policy per surface |
| `sekai_temporal_revisions` | Single-row revision counter |
| `sekai_temporal_assertions` | Append-only assertion versions |
| `sekai_temporal_backfill_runs` | Idempotency for baseline backfill |

## Operator notes

- Enabling a policy is **prospective**: only later appends (and explicit
  backfill) create history rows.
- Callers must never supply `recorded_*` revisions; the store allocates them.
- Backfill requires a non-empty subject list (unbounded backfills are rejected).
- Disabling a policy stops new enablement flags; retained versions remain until
  #228 retention/collection work applies policy.

## Atomic graph mutations (#226)

When a temporal policy is enabled for an object type, property, or relation,
object create/update/delete and link create/delete append or close history
versions in the **same SQLite transaction** as the current-state write and
object-change audit. Failure rolls all three back together.

Discovery: `SekaiDb::discover_temporal_surfaces(namespace)` lists registered
surfaces and whether history is currently retained (`history_retained`).
Surfaces without a policy are non-retained by default.

## Historical queries (#227)

Authenticated gRPC (SQLite-first):

| RPC | Role |
| --- | --- |
| `DiscoverTemporalSurfaces` | Policy discovery for a namespace |
| `QueryTemporalAsOf` | Bitemporal as-of read with unknown-bounds policy and page tokens |
| `DiffTemporalHistory` | Versions opened/closed between two revisions (not causal lineage) |

Defaults: `unknown_bounds_policy=exclude`; `recorded_revision=0` means latest
committed. Requests for subjects with no retained history return
`outcome=not_retained` and never synthesize rows from audit. PostgreSQL
returns `failed_precondition` until a parity slice lands.

Directional storage cost can be re-checked with:

```bash
scripts/temporal_semantics_spike.sh 100000 10
```

and the in-process `storage_cost_at_selective_coverage_stays_near_current_only`
unit test.

## PostgreSQL implications (no runtime parity claim)

PostgreSQL does **not** implement these tables or APIs yet. A future parity
slice should:

1. Add additive migrations for the same four logical tables.
2. Prefer `tstzrange` / integer ranges with GiST exclusion for non-overlapping
   transaction-time versions **within one assertion identity**, while keeping
   the three-way `known` / `unbounded` / `unknown` valid-bound encoding (ranges
   alone cannot express `unknown`).
3. Preserve system-assigned revision allocation under concurrent writers
   (sequence or locked counter) with the same fail-closed semantics.
4. Extend `docs/postgres-sekai-parity.md` and the RPC/capability inventory only
   after shared SQLite/PostgreSQL conformance fixtures exist.

Until that work lands, selecting `SEKAI_DB_BACKEND=postgres` does not advertise
or provide temporal history storage.
