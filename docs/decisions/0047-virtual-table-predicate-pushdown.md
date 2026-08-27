# ADR 0047: Push bounded virtual-table predicates with governed equivalence

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/792
- Issue: https://github.com/Sannrox/sekai-chisei/issues/689
- Supersedes: none
- Superseded by: none
- Related: [ADR 0036](0036-open-table-projections.md)

## Context

ADR 0036 admits Iceberg and Parquet snapshots as local projection evidence.
Filters still evaluated only in one path, so an adapter could change truth or
see a hidden column if pushdown were added later without a plan contract.

## Decision

A query compiles to a `sekai.virtual-pushdown/v1` plan bound to the registered
format adapter and the admitted snapshot digest.

Authorization of named columns runs before count or match. Hidden, unknown, and
sensitive columns fail as the same unavailable result and never push. Eligible
predicates (`eq`, `neq`) may push. Residual numeric predicates (`gt`, `gte`,
`lt`, `lte`) stay local. Unknown operators fail explicitly.

The plane evaluates a local plan and an adapter plan on the same snapshot. The
authorized projection is admitted only when those result digests match. Replay
is deterministic for one snapshot digest. The plan never grants write or permit
authority.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Pushing before authorization would let hidden columns participate in adapter
filters. Treating unsupported operators as pushed would let adapters silently
change truth. Silent local fallback after a digest mismatch would manufacture
success. Live catalog I/O would make remote storage and credentials into
authority.

## Consequences

Operators can inspect pushed versus residual predicates on every projection.
Follow-up work may add gRPC transport or live adapter engines.

## Validation

Pure tests cover Iceberg and Parquet equivalence, residual local predicates,
hidden and sensitive denial, digest mismatch failure, and digest-stable replay.
