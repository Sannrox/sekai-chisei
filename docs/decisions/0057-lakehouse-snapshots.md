# ADR 0057: Export partitioned lakehouse snapshots with schema evolution

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/751
- Issue: https://github.com/Sannrox/sekai-chisei/issues/712 (#712)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0036](0036-open-table-projections.md),
  [ADR 0056](0056-warehouse-projections.md)

## Context

Open-table query admits Iceberg and Parquet snapshots. Warehouse export
admits incremental pages. Neither exports partitioned, versioned
lakehouse snapshots that carry schema evolution, redaction, deletion,
re-import, provenance, and `sekai.security-metadata/v1` pins.

## Decision

Accept `sekai.lakehouse-snapshot/v1`. Identity is
`(namespace, snapshot_id)`. Two domain-neutral adapters
(`adapter.lakehouse.events`, `adapter.lakehouse.metrics`) register a
partitioned snapshot. Additive schema upgrade is a successor version.
Redaction and partition deletion are explicit markers. Exact digest
re-import is idempotent. Revocation is terminal. Security metadata
constrains classification, purpose, residency, and trust; it is not a
grant. Hidden columns, foreign tenants, and unknown versions fail
closed.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Reusing Iceberg query as the lakehouse export was rejected because
query does not carry schema upgrade, redaction, or re-import. Treating
warehouse incremental pages as lakehouse partitions was rejected
because partitions are versioned wholes, not contiguous offsets.

## Consequences

Operators register, reimport, upgrade, redact, delete, get, and revoke
through `sekaictl admin lakehouse`. Existing table and warehouse
surfaces remain.

## Validation

Two adapter fixtures cover deterministic partitions, schema upgrade,
redaction, deletion, re-import, and provenance.
