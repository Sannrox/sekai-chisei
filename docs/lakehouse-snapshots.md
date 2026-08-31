# Governed lakehouse snapshots

Export partitioned versioned snapshots with schema evolution, redaction,
deletion, re-import, provenance, and security-metadata pins. See
[ADR 0057](decisions/0057-lakehouse-snapshots.md).

## Contract

`sekai.lakehouse-snapshot/v1` binds:

- identity `(namespace, snapshot_id)`
- adapter `adapter.lakehouse.events` or `adapter.lakehouse.metrics`
- partition keys and digest-bound partitions
- additive schema versions
- `sekai.security-metadata/v1` ceiling, purpose, residency, and trust pin
- provenance over each mutation

Exact digest re-import is idempotent. Schema upgrade is additive.
Redaction removes column values. Partition deletion is a tombstone.
Revocation is terminal.

## Operator workflow

```text
sekaictl admin lakehouse register --snapshot ./snapshot.json --actor integrator
sekaictl admin lakehouse reimport --snapshot ./snapshot.json --actor integrator
sekaictl admin lakehouse upgrade --snapshot ./upgrade.json --actor integrator
sekaictl admin lakehouse redact --namespace ops --snapshot-id lh:events --column note --actor integrator
sekaictl admin lakehouse delete --namespace ops --snapshot-id lh:events --partition 2026-08-30 --actor integrator
sekaictl admin lakehouse get --namespace ops --snapshot-id lh:events --actor integrator
sekaictl admin lakehouse revoke --namespace ops --snapshot-id lh:events --actor integrator
```

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, revoked, hidden-column, or gapped schema | `lakehouse snapshot is unavailable` |
| Unknown contract revision | `lakehouse snapshot revision is unsupported` |

SQLite stores snapshots. PostgreSQL surfaces stay unavailable.
Adapters never receive grants, credentials, or receipt authority.
