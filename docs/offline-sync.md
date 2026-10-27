# Offline sync

Experimental (`SEKAI_EXPERIMENTAL_RPCS=1`), contract `sekai.sync/v1`. Design: [ADR 0124](decisions/0124-offline-sync-scopes.md).

1. `PutSyncScope` with the namespace, a `scope_id`, a `kind`, up to four
   `property_filters` (eq, gt, gte, lt, lte), an optional `link` (relation,
   `outgoing` or `incoming`, 1 or 2 hops), `max_objects` (at most 5000),
   and an optional `max_offline_age_ms` (one minute to 366 days). The scope
   belongs to the caller.
2. `ReadSyncSnapshot` with an empty `page_token`, then each
   `next_page_token`, until the last page returns a `cursor`. A snapshot
   with more visible objects than `max_objects` is refused with
   `RESOURCE_EXHAUSTED`, naming the quota.
3. `ReadSyncDeltas` with the cursor and an optional `limit` of changes per
   read. Store each `upserts` object whole and drop each
   `removed_object_ids` entry. Apply each `purges` entry: delete the whole
   object when it lists no properties, otherwise only the listed properties.
   Then continue from the new `cursor` while `more` is true. After an
   interrupted read, send the previous cursor again; it answers with the same
   changes. On `resnapshot_required`, discard the replica and start over at
   step 2.

Every object passes the same read checks as an online read and arrives
projected for the caller, so hidden objects and properties never leave
the server. An object that leaves the scope, through its filters, a link
or a lost grant, is removed at the next delta read.

## Purges and offline age (#1633, [ADR 0128](decisions/0128-sync-purges-and-offline-age.md))

A change in what the caller may read keeps the cursor. This covers a grant, a row policy, a property grant or a marking. The next delta read carries purges for the data the caller lost:

- An object the caller may no longer read is removed and purged whole.
- An object that no longer shows a property the client held is sent again without it, and that property is purged.

Only a changed scope definition, or a filter the caller may no longer query, requires a new snapshot.

With `max_offline_age_ms`, the last snapshot page and every delta read that leaves nothing pending (`more` false) return `offline_until_ms`. Until then the previous deadline holds. The client must not show the data after that time until it syncs again.

`sekai_client::sync_replica::SyncReplica` is a reference replica that applies snapshots, deltas and purges, and shows nothing until a snapshot completes, discards its data on `resnapshot_required`, and refuses to show data past `offline_until_ms`.

## Devices (#1634, [ADR 0126](decisions/0126-device-bound-assertions.md))

A device-bound credential must prove possession of its device key on every sync call, with the proof in `x-sekai-device-proof`. A copied credential without the key is refused.

A device the issuer revoked receives a wipe-only assertion. On `ReadSyncSnapshot` and `ReadSyncDeltas` it gets `wipe_required` and no data. The client must then delete every synced object and the cursor. Every other call with that assertion, `PutSyncScope` included, is refused. The reference replica wipes for good on that instruction.
