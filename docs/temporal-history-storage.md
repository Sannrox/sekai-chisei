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

## Retention and operations (#228)

| API | Role |
| --- | --- |
| `set_temporal_legal_hold` | Pin a version against collection/erasure |
| `collect_temporal_history` | Age out payloads per policy `retention_days` |
| `erase_temporal_subject` | Tombstone all payloads for a subject (blocked by holds) |

Collection and erasure **never delete** the temporal envelope (assertion id,
version, bounds, revisions, actor). They replace `payload_json` with
`{"omission":"retention"}` and clear `object_ref`. Historical reads return that
omission without reconstructing erased content.

Local storage budget: appends fail closed at **500_000** assertion versions
(`TEMPORAL_ASSERTION_BUDGET`) so unconstrained local growth is rejected before
the database becomes unbounded.

### Operator runbook (SQLite)

1. **Backup**: copy the SQLite file after `PRAGMA wal_checkpoint(TRUNCATE)`.
   Temporal tables are additive; restore restores policies + history together.
2. **Disable history**: `upsert_temporal_policy(..., enabled=false)` stops new
   writes; retained rows remain until collection/erasure.
3. **Downgrade**: software that does not understand `legal_hold` /
   `payload_omitted` columns must refuse to open the DB or ignore unknown
   columns; do not silently drop retained history.
4. **Corruption**: if `sekai_temporal_revisions` or assertion PK integrity
   fails, treat as fail-closed and restore from backup; do not rebuild history
   from audit.

### PostgreSQL (future parity, not claimed)

- Map `legal_hold` / `payload_omitted` as booleans.
- Prefer range types + exclusion for recorded intervals; keep the three-way
  valid-bound encoding for unknown.
- Collection/erasure must use the same tombstone semantics, not hard DELETE of
  envelope rows required for non-disclosure proofs.

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
