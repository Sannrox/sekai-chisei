# Governed export

Data leaves the plane through `ExportObjectSet`, never through paging reads
alone ([ADR 0130](decisions/0130-governed-export.md), #1627). The RPCs are
`experimental` and rejected unless `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature is enabled.

## Export grant

`GrantNamespaceExport` (`namespace`, `principal`, `reason`) and
`RevokeNamespaceExport` need namespace administration, and both take a
reason. Granting an active grant returns it unchanged. Each change appends
to the grant's history, which is the durable record, and is mirrored as an
audit decision (`namespace_export_grant`, outcome `granted` or `revoked`).
A concurrent change to the same grant fails with `ABORTED`; retry it.
Revoking keeps the grant with `revoked_by`, `revoked_at_ms` and
`revocation_reason`.

## Export

`ExportObjectSet` takes an object-set `descriptor`, the `properties` to
export in column order, and a `format` (`csv` or `jsonl`). The caller needs
every read check of `EvaluateObjectSet` and an active export grant on the
namespace (`PERMISSION_DENIED` `export_not_granted` otherwise). The response
is a stream:

1. the first message carries `receipt_id`;
2. the next ones carry file bytes (`data`): for CSV, a header `id,<properties>`
   and then one row per object; for JSON Lines, one object per line;
3. the last one sets `done`, `row_count` and `content_digest`
   (`sha256:<hex>` of every data byte in order).

Rows are the objects a read returns, in the descriptor's order. A property
the reader may not see is an empty cell, or an absent key. CSV fields with a
comma, quote, line break or surrounding whitespace are quoted. Values are
written as stored, without spreadsheet formula escaping.

The receipt (`operation_class` `governed_export`) is a Sekai record, written
before the first byte. It is closed with outcome `completed` (with the row
count and the digest as its artifact) only once the stream has passed every
byte on. A stream that ends any other way ends in an error.
`GetExportReceipt` (`operation_id`) returns it to its initiating caller or an
administrator of its namespace; anyone else gets `NOT_FOUND`. An export that ends early is closed as `aborted`. When the
exporting process dies, the next export on any instance closes its receipt
as `aborted` (`exporter_lost`) once its 60 s lease has run out. A client
that stops reading for longer than that loses the export.

Not yet exported: sets with traversal or aggregation, and object types backed
by a dataset (`UNIMPLEMENTED`). See #1695 for dataset versions and #1628 for
downloadable artifacts.
