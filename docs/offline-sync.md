# Offline sync

Experimental (`SEKAI_EXPERIMENTAL_RPCS=1`), contract `sekai.sync/v1`. Design: [ADR 0124](decisions/0124-offline-sync-scopes.md).

1. `PutSyncScope` with the namespace, a `scope_id`, a `kind`, up to four
   `property_filters` (eq, gt, gte, lt, lte), an optional `link` (relation,
   `outgoing` or `incoming`, 1 or 2 hops), and `max_objects` (at most 5000).
   The scope belongs to the caller.
2. `ReadSyncSnapshot` with an empty `page_token`, then each
   `next_page_token`, until the last page returns a `cursor`. A snapshot
   with more visible objects than `max_objects` is refused with
   `RESOURCE_EXHAUSTED`, naming the quota.
3. `ReadSyncDeltas` with the cursor and an optional `limit` of changes per
   read. Store each `upserts` object and drop each `removed_object_ids`
   entry, then continue from the new `cursor` while `more` is true. After an
   interrupted read, send the previous cursor again; it answers with the
   same changes. On `resnapshot_required`, start over at step 2.

Every object passes the same read checks as an online read and arrives
projected for the caller, so hidden objects and properties never leave
the server. An object that leaves the scope, through its filters, a link
or a lost grant, is removed at the next delta read.
