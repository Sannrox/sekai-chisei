# ADR 0162: Landed source records stay in the SQL store

- Status: proposed
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2411 (#2411)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0036](0036-open-table-projections.md), [ADR 0056](0056-warehouse-projections.md), [ADR 0057](0057-lakehouse-snapshots.md), [ADR 0105](0105-partitioned-transform-io.md)

## Context

A source batch lands its records as binding-owned dataset rows in the plane's
SQL store, with the batch, checkpoint and identities in the same store. Index
apply derives objects from those rows, and `full_rebuild` rematerializes from
them without another source read. Open formats exist only as exports
(lakehouse snapshots, warehouse projections) and as a registered read of an
external table (open-table projections), and the plane opens no external
storage.

A consuming deployment needs versioned datasets and unattended pipelines, and
asked whether landed records should live as open tables on object storage
instead, with the plane keeping catalog, policy and markings. The research in
[`docs/research/2411-landed-records-open-tables.md`](../research/2411-landed-records-open-tables.md)
measured both paths:

- Landing slows per batch and the store grows quadratically, falling below the
  documented `ApplySourceBatch` floor before 10,000 landed records. The cause
  is a full row copy per dataset version on both backends (#3475), not the
  SQL store; reads stay flat.
- Writing a landed batch to object storage is cheap (about 3.8 ms for a
  500-record part plus pointer on loopback), but it adds a second durable write
  to the SQL commit the plane still needs.
- `sekai.open-table-source/v1` cannot describe a landed table: it has one
  registering owner, column markings only, re-registration per snapshot, and a
  locally admitted copy as the read.

## Decision

1. Landed source records stay in the plane's SQL store, on both backends. The
   store remains the authority for reads, `full_rebuild`, backup and restore.
2. Open formats stay outputs. Lakehouse snapshots, warehouse projections and
   Parquet export carry landed data out after policy applies; open-table
   projections stay a registered read of tables the plane does not write.
3. The plane does not open object storage or hold storage credentials for
   landed records. A deployment that needs landed data in an open table gets
   it through an export the plane redacts first.
4. Dataset version storage is the landing limit to fix first. A version costs
   in proportion to what its batch changed while a pinned replay still reads
   exactly its rows (#3475).

## Alternatives considered

- **Land into open tables on object storage (B).** Rejected. The plane would
  read external storage on the read, rebuild and restore paths, needing
  credentials, a cross-store commit order with orphan cleanup, and fail-closed
  handling for a second system. Direct reads of the files skip row and cell
  policy and markings. It needs a new open-table contract revision. It does not
  fix the measured limit unless versions share files, which the SQL store can
  do itself.
- **Land in SQL, mirror to open tables (C).** Not adopted as a new mechanism.
  A redacted mirror is what the lakehouse snapshot export already is; widening
  that export (PostgreSQL support, per-version incremental export) serves the
  consumer without a second landing path.
- **No action.** Rejected. The research found a concrete landing limit, and
  the consumer needs a stated answer on which bytes move.

## Consequences

- No new runtime dependency, credential or failure mode on the plane.
- Backup and restore stay one consistent snapshot of the stores and object log.
- Landed data reaches open-format tools only through exports, so freshness is
  bounded by export cadence.
- Follow-up: #3475 (version storage). Widening lakehouse snapshot export to
  PostgreSQL and to per-version increments is a separate Issue when a consumer
  asks for it.

## Validation

- The object-path harness lands records at or above the documented floor past
  100,000 landed records once #3475 lands, with store size linear in landed
  records.
- Revisit this decision if, after #3475, a measured workload finds the SQL store
  itself the landing limit, or when the object log moves to object storage and
  the plane already holds a fenced, recoverable storage dependency.
