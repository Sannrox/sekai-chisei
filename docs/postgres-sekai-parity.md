# Reusable Sekai PostgreSQL parity

This note closes the parent reusable-Sekai PostgreSQL parity track. It does not
activate the community process against PostgreSQL.

## Outcome

Every remaining tenant-free `SekaiService` operation required by the public
reusable runtime has PostgreSQL persistence with shared SQLite/PostgreSQL
conformance, or is an explicit computed/query path with named durable
dependencies.

Evidence is checked in as:

| Artifact | Role |
| --- | --- |
| `tests/fixtures/sekai_rpc_inventory/v1.json` | Fail-closed map of every `SekaiService` RPC to evidence |
| `tests/fixtures/runtime_backend/postgres-sekai-complete-v1.json` | Complete reusable Sekai capability advertisement |
| `tests/*_backend_conformance.rs` and related harnesses | Shared SQLite/PostgreSQL surface fixtures |
| `src/db/sekai_rpc_inventory.rs` | Inventory load/validation and complete-capability helper |

## Delivery slices

| Issue | Outcome |
| --- | --- |
| #248 | Reusable definitions, datasets, ontology, actions, leases, credentials |
| #249 | Coordination and work admission |
| #250 | Evidence, attestations, and handoffs |
| #251 | Retention, scoped content, and reconciliation |
| #252 | RPC inventory and complete-Sekai capability evidence |
| #259 | Action policy and approval |
| #261–#265 | Capability packages, guarded mutations, definition lifecycle, decisions, team namespaces |

## Still outside this parent

- Chisei governed-decision and execution persistence (#237) — closed; see
  `docs/postgres-chisei-parity.md`
- Community PostgreSQL runtime activation (#238)
- Tenant state, tenant RPCs, OIDC, and OAuth

## Operator posture

SQLite remains the default community backend. PostgreSQL may be used for
composition and isolated conformance. Public runtime selection of PostgreSQL
still fails closed until the remaining Chisei and gateway surfaces can be
advertised truthfully.
