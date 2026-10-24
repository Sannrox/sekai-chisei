# ADR 0105: Partitioned streaming I/O for governed transforms

- Status: accepted
- Date: 2026-10-12
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1388
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1388 (#1388)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0074](0074-plane-owned-transforms.md),
  [ADR 0097](0097-in-process-transform-host.md),
  [ADR 0102](0102-isolated-process-transform-profile.md),
  [ADR 0103](0103-transform-schedule-and-dependency-graph.md)

## Context

[ADR 0074](0074-plane-owned-transforms.md) keeps transform outputs as datasets
and does not pick a table format.
[ADR 0102](0102-isolated-process-transform-profile.md) admits isolated-process
work and streams the pinned input snapshot as gRPC rows, then replaces the
whole output dataset on write-back. Issue #1388 needs workers to stay inside a
memory bound on large datasets, to read and write by partition, and to keep a
failed write from publishing a half-written run.

A new open-table format remains out of scope (#879). Incremental in-process
runs still identify new rows by `last_input_row_id`; that watermark is not a
partition digest.

## Decision

1. A dataset may declare ordered `partition_keys`. Empty keys keep today's
   whole-dataset `sha256-sum-v1:` digest. Partitioned datasets use
   `sha256-partitions-v1:` over a sorted map of partition identity to that
   partition's `sha256-sum-v1:` digest. The prefixes do not fold into each
   other (the #1358 encoding rule).
2. Claim-scoped `ReadTransformRunInputs` remains row maps on gRPC, not
   Arrow/Parquet. A page may name a partition and a byte cap. An unset
   selector reads every partition; the empty string selects the empty
   identity. Resume is `(partition_key, alias, after_row_id)`. One oversize
   row still returns so the cursor can advance.
3. Isolated write-back may replace named output partitions. The plane merges
   those replacements with live untouched partitions, checks the envelope
   digest, evaluates quality on the merged set, and commits deletes plus
   inserts in the same transaction as the receipt. A stale fence or digest
   mismatch commits nothing; readers keep the previous version.
4. Receipts list input partitions read and output partitions written, each
   with a digest and row count. The run `output_digest` is the envelope.
5. Incremental in-process projection on a partitioned dataset appends new
   rows into partitions whose input changed since the checkpoint. Untouched
   output partitions stay on disk, and historical row IDs in previously
   written partitions remain stable so downstream watermarks still match.
6. The new fields are additive. Unpartitioned datasets and full-replace
   write-back keep their current bytes.

## Alternatives considered

- Keep whole-dataset I/O and larger workers. Rejected: the bound is the
  worker page, not host RAM.
- Workers write object storage directly. Rejected: credentials would leave
  the plane ([ADR 0074](0074-plane-owned-transforms.md)).
- Adopt Iceberg/Parquet as the snapshot encoding. Rejected: #879 still owns
  format choice; row-map pages keep the existing claim contract.

## Consequences

Isolated runners still choose which partitions to send. The plane owns atomic
commit. Community `RuntimeDb::append_rows` was SQLite-only here; it runs on
PostgreSQL too since #1320. Partition writes use native dataset-row APIs.

## Validation

SQLite tests `isolated_process_streamed_read_stays_inside_byte_bound`,
`isolated_process_partition_write_back_rewrites_one_partition`,
`isolated_process_failed_partition_write_keeps_previous_output`, and
`incremental_run_rewrites_only_changed_partition`. PostgreSQL repeats the
isolated envelope. Old `sha256-sum-v1:` encodings do not parse as
`sha256-partitions-v1:`.
