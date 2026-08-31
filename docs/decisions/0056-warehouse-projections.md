# ADR 0056: Export warehouse projections with security-metadata pins

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/751
- Issue: https://github.com/Sannrox/sekai-chisei/issues/711 (#711)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0036](0036-open-table-projections.md),
  [ADR 0048](0048-governed-event-subscriptions.md)

## Context

Open-table and event-stream projections already admit authorized rows.
They do not yet export warehouse-shaped snapshot and incremental pages
that carry replay, deletion, lineage, and `sekai.security-metadata/v1`
pins. Without that export, adapters can lose deletion or visibility
semantics or acquire grant authority.

## Decision

Accept `sekai.warehouse-projection/v1`. Identity is
`(namespace, projection_id)`. Two domain-neutral adapters
(`adapter.warehouse.orders`, `adapter.warehouse.inventory`) register a
projection, export a snapshot, then contiguous incremental pages that
may tombstone rows. Exact last-page replay is idempotent. Revocation is
terminal. Security metadata constrains classification, purpose,
residency, and trust pins; it is not a grant. Hidden columns, stale
cursors, foreign tenants, and unknown versions fail closed.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating a warehouse cursor as a live grant was rejected because grants
are rechecked on each export. Pushing rows into an external warehouse
engine was rejected because the plane does not own external systems.
Reusing Iceberg/Parquet query as the warehouse export was rejected
because it does not carry incremental deletion or security-metadata
pins.

## Consequences

Operators register, export, get, and revoke through
`sekaictl admin warehouse`. Existing table and stream query surfaces
remain.

## Validation

Two adapter fixtures cover snapshot, incremental, replay, revocation,
field visibility, and tenant scope.
