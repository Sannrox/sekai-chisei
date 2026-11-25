# ADR 0167: A claimed Source reads its live records by object key

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3013 (#3013)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0022](0022-source-batch-transactions.md), [ADR 0148](0148-sources-and-one-connector-runtime.md), [ADR 0149](0149-one-claimable-work-queue.md)

## Context

An object storage connector type (#3013) mirrors a bucket listing. It
skips an object whose ETag has not changed, and it tombstones the records
of keys the listing no longer returns. Both need what the plane holds for
the Source. The runtime could not read it: `Connector::read_page` saw only
the committed cursor, and the cursor holds only the last key. The plane
stores each record's `object_key` beside its identity, in byte order, since
the first part of #3013.

## Decision

1. An experimental `ListSourceRecordVersions` RPC reads the live,
   untombstoned records of one Source: for each, its `external_id`, its
   `object_key` and its `source_version`. It returns no properties and no
   payload.
2. Only the runtime holding the Source's live sync claim reads. The request
   carries the claim's runtime id, generation and fencing token, and the
   caller needs what claiming the sync needs. A stale or lapsed fence is
   refused as `FAILED_PRECONDITION`.
3. Rows are ordered by `object_key` and then `external_id`, both in UTF-8
   byte order, the order object storage lists keys in. A page starts after
   `(after_object_key, after_external_id)`, or after every record of
   `after_object_key` when `after_external_id` is empty, and ends at an
   optional inclusive `through_object_key`. A page holds at most 500 rows,
   the batch record cap. Fewer rows than asked means the range is
   exhausted. The `external_id` tie-break lets a page end inside one
   object's records, which the accepted shape (a lower bound on the key
   alone) could not continue from.
4. A live record without an object key, landed by an older plane or
   connector, has no place in the order. The read refuses with
   `FAILED_PRECONDITION` and the message `source_records_unkeyed` until a
   full pass lands every record again with its key.
5. The SDK gains `PlaneView`, its `record_versions(KeyRange, limit)` read,
   and `Connector::read_page_with_plane`. The runtime calls
   `read_page_with_plane` with a view bound to the sync's fence; its default
   calls `read_page`, so existing types ignore the view and implement
   nothing new.

## Alternatives considered

- **Grant the runtime `ListObjects`.** Rejected. It is a broad namespace
  read, and its string order depends on the backend's collation.
- **Keep the key set in the cursor.** Rejected. It is unbounded.
- **Add a view argument to `read_page`.** Rejected. Every connector type
  would change for a read one type uses.
- **Order silently past unkeyed records.** Rejected. A mirror would never
  tombstone them, and would skip nothing it could prove unchanged.

## Consequences

- An object storage type can skip unchanged objects and tombstone vanished
  keys without a second store. The read uses the existing byte-order index
  on `(namespace, binding_id, object_key)`. It adds no schema.
- Mixed versions: an older plane does not serve the RPC, and the runtime's
  view reports it as unavailable, never as a lost fence. A connector can
  then fall back to a full pass. An older runtime never calls it.
- Rollback leaves nothing to undo.
- The object storage connector type is the remaining delivery of #3013.

## Validation

- Store contract on SQLite and PostgreSQL: byte order across case and a
  multi-byte key, a page that ends inside one object's records, an
  inclusive upper bound, tombstoned records left out, a stale or lapsed
  fence refused, and an unkeyed live record refusing the read.
- Over gRPC: only a runtime principal reads, a stale token is refused, and
  the unkeyed refusal carries `source_records_unkeyed`.
- A connector run by the runtime reads, mid-sync, the records its first
  page landed, under the sync's claim.
