# ADR 0104: Per-namespace object change generation keys the privacy scan cache

- Status: accepted
- Date: 2026-10-12
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1492
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1492 (#1492)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0068](0068-object-change-subscriptions.md),
  [ADR 0023](0023-generation-fenced-source-change-feeds.md)

## Context

A Sensitive egress check compiles entity literals from the namespace graph and
reuses them while the entity set is unchanged. The cache still listed those
objects on every check in order to fingerprint them. `object_change_watermark`
cannot be that key: it joins the full change history, and object `updated` is
caller-supplied so it cannot prove freshness. Audit retention may also purge
change rows, so a MAX over history is not a durable generation.

A missed write path is a privacy leak: a new entity would ride a stale cache
out of the scan.

## Decision

1. Persist `sekai_namespace_object_generation` (`namespace` primary key,
   `generation` counter) on SQLite and PostgreSQL.
2. Advance the counter in the same database transaction as every `sekai_objects`
   INSERT, UPDATE, and DELETE, including namespace moves (both namespaces).
   Database AFTER-row triggers own the increment so create, update, delete,
   source-batch apply, definition-migration property rewrites, lease-guarded
   writes, and unaudited storage paths cannot skip it.
3. Key the in-process privacy scan entity cache on that generation. A hit
   makes no entity listing call. A generation movement between two checks
   forces a relist. Leak-rule objects are still listed to fingerprint policy;
   they may live in the empty namespace and would not bump the scanned
   namespace.
4. Read generation as `COALESCE((SELECT generation WHERE namespace = ?), 0)`.
   A missing row is generation 0. The first write inserts generation 1.

## Alternatives considered

- Index `sekai_object_changes(namespace, seq)` and take MAX. Rejected because
  the watermark query still joins history for moved-out objects, and retention
  can delete the rows the MAX would read.
- Increment only from audited Rust helpers. Rejected because object INSERT
  sites include source sync, definition migration, leases, learning, and raw
  storage APIs; a missed site leaks.
- Use `updated` in the cache key. Rejected because callers supply it.

## Consequences

- Fresh and upgraded stores on both backends gain one table and three triggers.
- Existing namespaces backfill `generation = COUNT(*)` once; later writes
  increment from that value. In-process cache starts empty after upgrade, so
  the first Sensitive check still lists.
- SQLite `migrate()` is idempotent (`IF NOT EXISTS`, backfill `DO NOTHING`).
- PostgreSQL applies the change once as migration 58.
- Store relocate copies the table with the rest of the Sekai schema; triggers
  stay attached to `sekai_objects`.

## Validation

- `object_writes_advance_namespace_generation` covers create, update, delete,
  unaudited create, definition-migration-style UPDATE, abort, and a namespace
  column change.
- `sync_apply_advances_namespace_generation` covers source-batch apply.
- `privacy_scan_cache_hit_skips_entity_listing` and
  `privacy_scan_cache_write_between_checks_forces_relist` prove the cache
  contract.
- `privacy_scan_cache_hit_avoids_listing_cost` records miss versus hit listing
  counts for the Sensitive egress check.
