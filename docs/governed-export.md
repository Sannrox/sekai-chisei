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
by a dataset (`UNIMPLEMENTED`). See #1628 for downloadable artifacts.

An export refused for want of a grant writes a refusal, never data: an audit
decision (`governed_export`, outcome `refused`) naming the caller, the
namespace and the source.

## Watermarked fingerprint

Fingerprinting is off until a namespace administrator puts an explicit
`fingerprint_properties` allowlist on a marking
(`PutExportFingerprintPolicy` / `GetExportFingerprintPolicy`;
[ADR 0131](decisions/0131-watermarked-export.md), #1466). Only decimal
measurement properties may be listed; integers, identifiers, timestamps,
strings, booleans, enums, `id` and `access_marking` cannot. Listed values
move by at most one unit in the last decimal place, keyed by the export id.
Exact-value properties stay as the reader saw them. A fingerprinted export
records those properties on its receipt, stores a compact fingerprint
record, and permutes rows in groups of 16.

`TraceExport` (`namespace`, `sample`, `format`) scores fingerprint records
in that namespace and returns matches with a confidence. A namespace
administrator sees every match; anyone else sees only exports they
initiated. A caller with neither is refused. Every call is an audit
decision (`trace_export`).

## Dataset version export

`ExportDatasetVersion` (#1695) takes `dataset_id`, `version_id`, the `columns`
to export in order (empty: every column), and a `format`. It answers with the
same stream and receipt as `ExportObjectSet`. CSV has a header of the
columns, and neither format adds an id column. The caller needs:

- read on the dataset;
- the full read policy (marking, object security, purpose) of the object the
  dataset is bound to;
- an export grant on that object's namespace.

A dataset bound to no object has no namespace to grant on, so it is refused
(`FAILED_PRECONDITION`). So is a dataset whose bound object type enforces
cell (value-instance) grants, which name object values that dataset rows do
not carry. Columns the bound object's property grants withhold
are written empty, or left out. Restricted columns (by the dataset's column
classification or the bound object type's schema) read `[redacted]` unless
the caller, and any actor it acts for, may read restricted properties of
that object, as on a read of it. Rows are read in row order, a page at a
time, so memory stays bounded. A version purged while it streams fails the
export rather than completing it. Redaction rewrites version rows in place,
so an export that spans a redaction may carry values from before it, as a
read made just before would.

## Saved exports

A saved export (#1628) is an export definition that runs later for its owner
alone and stores its result as an artifact for an out-of-process adapter to
deliver. The plane holds no destination credentials.

- `PutExportDefinition` saves a definition (`namespace`, `definition_id`, and
  exactly one of `object_set` or `dataset_version`, a source in the
  definition's namespace). The caller becomes its `owner`. Saving makes every
  check a run would make, for the owner alone, so a definition that could not
  run now is not saved. Each id holds one body: an identical retry returns the
  stored definition, and a different body is `ALREADY_EXISTS`.
  - A dataset source with an empty `version_id` exports the latest version
    when it runs (the same holds for `ExportDatasetVersion`).
  - Only one principal outside a tenant assertion may save an export. A run
    has no request to carry a tenant assertion, so a tenant-scoped export
    could not be checked as it was saved.
- `GetExportDefinition` and `DeleteExportDefinition` serve the owner or an
  administrator of the namespace; anyone else gets `NOT_FOUND`. Every
  saved-export call is refused for a request under a tenant assertion
  (`FAILED_PRECONDITION`) and needs the namespace (write to delete or run).
- A definition whose object set requires a purpose is refused when saved and
  when run, rather than exporting an empty file.
- `RunExportDefinition` runs a definition now, for its owner only. Every check
  is made again at run time, for the owner principal alone, with no tenant
  assertion and no purpose. A source whose policy requires a purpose is
  therefore refused. A run that is refused, for example because the export
  grant was revoked, fails closed and writes a `refused` receipt, named in
  the error. A run that goes through stores its bytes, chunk by chunk under
  the export's lease, as the artifact of its receipt. The receipt completes
  after the last chunk is stored. The receipt is the artifact's record: the
  artifact is whole exactly when its receipt completed, with that digest.
- An artifact is kept for 7 days at most and cannot be read once expired.
  Every instance sweeps expired artifacts, and closes exports whose exporter
  was lost, once a minute.
- `DeleteExportDefinition` deletes only the record the caller was authorized
  against. A definition saved anew under the same id meanwhile is kept.
- A definition with `every_ms` greater than zero joins the transform
  schedule graph ([ADR 0103](decisions/0103-transform-schedule-and-dependency-graph.md)).
  `TickGovernedTransforms` admits one run per due bucket for its owner,
  the same way it admits a due transform: a replica tick is idempotent, and
  a revoked export grant fails that run closed with a receipt.
- `ListDeliverableExportArtifacts` lists completed, unexpired, unacknowledged
  artifacts in a namespace to the run's initiating owner or a namespace
  administrator. `FetchExportArtifact` streams the bytes and the receipt
  digest; the adapter verifies the digest before delivering.
  `AcknowledgeExportDelivery` takes that digest, deletes the bytes, and is
  idempotent. Access follows the receipt, so a later definition under the
  same id cannot fetch another owner's retained artifact. The plane never
  pushes and holds no destination credentials.
