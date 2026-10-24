# ADR 0130: Data leaves the plane only through a governed export

- Status: accepted
- Date: 2026-10-24
- Issue: #1627
- Related: #1443, #1628, #1695, #1696

## Context

Reading an object set page by page is the only way to take data out, and it
leaves no record that data left. A reader's entitlement covers looking at
data in the plane, not copying it elsewhere.

## Decision

1. **Export is its own grant.** A namespace administrator grants a principal
   export on a namespace (`GrantNamespaceExport`) and revokes it
   (`RevokeNamespaceExport`). Grants are an append-only history per
   principal and namespace, and each change inserts the next entry. That
   history is the durable record (who, when, and the reason for the grant
   and for its revocation), and two concurrent changes cannot both land. An
   audit decision mirrors each entry. It is derived from the entry alone and
   written idempotently, so retrying the grant or revocation repairs a lost
   audit write. Export sits on top of read: the exporter still
   passes every read check, and no read is ever widened by it.
2. **One read path.** `ExportObjectSet` runs the same read checks as
   `EvaluateObjectSet` and walks the set with the same per-object checks
   (ACL and row policy, marking, collaboration, object security, purpose),
   then projects properties as a read does. A hidden row is never in the
   file. A withheld property is an empty cell (CSV) or an absent key (JSON
   Lines).
3. **The receipt comes first.** The export's receipt is a Sekai record, so a
   Sekai-only plane keeps it. It is written before the first byte and read
   with `GetExportReceipt`. It records the source, the query digest, the
   format and the properties. It is closed with the row count and the sha256
   of every byte sent. An export that does not finish, such as a dropped
   client or a failed scan, closes it as `aborted`. The exporter holds a
   lease on the open export (60 s, renewed as it sends). When its process
   dies, the next export on any instance claims the expired lease by
   deleting it under the expiry condition and closes the receipt as
   `aborted` (`exporter_lost`). The lease row holds the initial receipt and,
   once decided, the outcome. The outcome is recorded under the lease
   condition, so it is decided once. The receipt is written from the row,
   and the row is removed last, so a crash at any step leaves work the next
   sweep finishes. The exporter creates its receipt only if none exists, and
   it never renews an expired lease. It waits on a slow client only as long
   as its lease allows, and the response stream drops data whose deadline
   passed, so no byte leaves after another instance may have closed the
   export. The receipt completes only when the stream reaches it, after the
   last byte. A stream that stops earlier ends in an error and leaves the
   receipt aborted.
4. **Streamed.** Rows are resolved in batches of 256 and sent in messages of
   about 64 KiB through a bounded channel, so memory does not grow with the
   set.

Rejected:

- Export as plain read: no boundary and no record for data leaving the plane.
- Writing the receipt after the stream: a crashed or aborted export would
  leave no record.
- Parquet in the root crate: a heavy dependency nobody has asked for (#1696).

## Consequences

- Sets with traversal or aggregation, and object types backed by a dataset,
  are not exported yet (`UNIMPLEMENTED`); downloadable artifacts are #1628.
- Dataset versions (#1695) export through the same pipeline, grant and
  receipt. Their access is the dataset's read plus the full read policy of
  the object it is bound to. Columns follow that object's property grants.
- The underlying scan pages by offset, so a very large export reads more
  than it sends. Its memory stays bounded.
- On enterprise transport an export takes space write, not view.
- A client that stops reading for longer than the lease loses the export.
