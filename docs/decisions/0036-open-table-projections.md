# ADR 0036: Query registered Iceberg and Parquet snapshots as projections

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/765
- Issue: https://github.com/Sannrox/sekai-chisei/issues/682
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  Discussion [746](https://github.com/Sannrox/sekai-chisei/discussions/746)

## Context

#668 accepted `sekai.governed-transform-execution/v1` as a conformance profile.
Its `projection` class is an authorized typed query over one registered source
snapshot. Iceberg and Parquet engines remain adapters. Connecting the control
plane to a live catalog would make remote storage and credentials into
authority.

## Decision

A registered `sekai.open-table-source/v1` is local snapshot evidence. The plane
pins format (`iceberg` or `parquet`), schema revision `v1`, schema digest,
snapshot digest, owner, and column markings. Query is against that digest, not
a live table.

Hidden or unauthorized columns fail the whole query before any row is
returned. Clearance comes from a sealed principal profile or trusted local
service; a query ceiling may only restrict that grant. Unrequested hidden
columns are omitted without a hidden-count leak. Corrupt metadata, digest
mismatch, unsupported format, revision, or predicate, and foreign ownership
fail closed. An existing source id cannot change owner. The same snapshot
digest always yields the same authorized projection. Partial output is
discarded; retry or resnapshot is explicit.

SQLite is the reference store. PostgreSQL registration and query stay
unavailable.

## Alternatives considered

Live object-store connections were rejected because credentials and remote
failure would become authority. Treating Iceberg or Parquet as a second object
identity family was rejected because datasets and object sync already own graph
identity. Partial disclosure when one requested column is hidden was rejected
because it leaks the rest of the projection.

## Consequences

Operators register a source, admit a digest-matching snapshot, and query
authorized columns. No gRPC is added. Follow-up work may push predicates
(#689) after this projection contract exists.

## Validation

Deterministic fixtures cover authorized Iceberg and Parquet rows, digest-stable
replay, omitted hidden fields, and fail-closed hidden requests, sensitive
predicates, foreign ownership, corrupt metadata, unsupported revisions, and
missing snapshots.
