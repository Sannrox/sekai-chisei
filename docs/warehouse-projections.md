# Governed warehouse projections

Export authorized snapshot and incremental warehouse pages with replay,
deletion, lineage, and security-metadata pins. See
[ADR 0056](decisions/0056-warehouse-projections.md).

## Contract

`sekai.warehouse-projection/v1` binds:

- identity `(namespace, projection_id)`
- adapter `adapter.warehouse.orders` or `adapter.warehouse.inventory`
- authorized columns and classifications
- `sekai.security-metadata/v1` ceiling, purpose, residency, and trust pin
- a generation-fenced cursor and last page digest

The first export is a snapshot. Later incremental pages are contiguous
and may tombstone rows. Exact replay of the last page digest does not
advance the cursor. Revocation is terminal.

## Operator workflow

```text
sekaictl admin warehouse register --projection ./projection.json --actor integrator
sekaictl admin warehouse export --page ./snapshot.json --actor integrator
sekaictl admin warehouse export --page ./incremental.json --actor integrator
sekaictl admin warehouse get --namespace ops --projection-id wh:orders --actor integrator
sekaictl admin warehouse revoke --namespace ops --projection-id wh:orders --actor integrator
```

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, revoked, hidden-column, stale, or gapped page | `warehouse projection is unavailable` |
| Unknown contract revision | `warehouse projection revision is unsupported` |

SQLite stores projections and pages. PostgreSQL surfaces stay unavailable.
Adapters never receive grants, credentials, or receipt authority.
