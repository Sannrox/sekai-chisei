# ADR 0128: Sync purges replace resnapshots on authorization change

- Status: accepted
- Date: 2026-10-23
- Issue: #1633
- Amends: [ADR 0124](0124-offline-sync-scopes.md)

## Context

ADR 0124 ends a cursor whenever the caller's authorization changes. That covers a policy activation, a principal change, or the scope definition. The client must then take a full snapshot, which is correct but costs the whole scope on every policy change. A replica must also lose data promptly when access is removed, and must not show stale data indefinitely.

## Decision

1. **Split pin.** A position's pin is `<definition>.<authorization>`.
   - A changed definition ends the cursor (`resnapshot_required`).
   - A changed authorization does not. The next delta diffs what the client holds against what the caller may read now.
   - Pins stored before the split never match, so those cursors take one new snapshot.
   - A filter the caller may no longer query also ends the cursor; the client discards the replica.
2. **Purges.** Each member records the property names it was read with.
   - A removed object that still exists in the namespace but is hidden from the caller is purged whole. It stays in `removed_object_ids` too, so existing clients behave the same.
   - An upserted object that no longer shows a property the client held, while the property still exists, purges that property. These are names the client already held, so no hidden name is disclosed.
   - Leaving the filters, a link, or a delete stays an ordinary removal.
3. **Offline age.** A scope may set `max_offline_age_ms`, between one minute and 366 days. The last snapshot page returns `offline_until_ms`, now plus that age, and so does every delta read that leaves nothing pending. A read with changes still pending returns none, so a replica holding data it must drop gains no time. Clients must not show the data after it without syncing. The field is left out of stored definitions when 0, so scopes defined before it keep their pins.
4. **Reference replica.** `sekai_client::sync_replica::SyncReplica` applies snapshots, deltas and purges, and refuses to show data past `offline_until_ms`.

## Alternatives considered

- Keeping the full resnapshot on every policy change. Rejected: the cost is unbounded.
- Listing hidden property names from the stored object. Rejected: it would disclose names the client never held.

## Consequences

The members table gains a `properties` column: SQLite adds it on use, and PostgreSQL migration `0097` adds it. Property purges are only as exact as the property names stored for the baseline. Where a retry delivered a member differently, the names are unknown and the upsert's whole replacement is the only purge.

## Validation

A test syncs a scope, then:
- activates a property grant, which purges only that property and keeps the cursor;
- raises an object's marking, which purges it whole;
- moves an object out of the filter, which removes it without a purge;
- checks that the offline deadline is returned.

The reference replica's test applies purges and refuses to show data past the deadline.
