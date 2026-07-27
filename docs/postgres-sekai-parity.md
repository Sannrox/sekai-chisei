# Reusable Sekai PostgreSQL parity

This note closes the parent reusable-Sekai PostgreSQL parity track. Community
PostgreSQL runtime selection is activated by #238.

## Outcome

Most tenant-free `SekaiService` operations required by the public reusable
runtime have PostgreSQL persistence with shared SQLite/PostgreSQL conformance,
or are explicit computed/query paths with named durable dependencies.

**Known SQLite-only public paths** (community Postgres fails closed; do not
treat inventory “complete” as dual-backend for these RPCs):

- audited ontology mutations and definition proposals
  (`upsert_*_with_audit`, proposal review/get/list, evidence-driven propose);
- SQLite FTS `SearchText` / hybrid text adapter (see [text-fts.md](text-fts.md));
- multi-control-plane federation site/peer tables (see
  [federation-profile.md](federation-profile.md));
- selective bitemporal history storage (SQLite-first; see
  [temporal-history-storage.md](temporal-history-storage.md)).

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
- Community PostgreSQL runtime activation (#238) — complete; select with `SEKAI_DB_BACKEND=postgres`
- Tenant state, tenant RPCs, OIDC, and OAuth
- Selective bitemporal history storage (#225) is **SQLite-first**; see
  `docs/temporal-history-storage.md` for PostgreSQL implications without a
  present parity claim

## Operator posture

SQLite remains the default community backend. Select PostgreSQL with
`SEKAI_DB_BACKEND=postgres` and `DATABASE_URL` for the reusable public control
plane when you need shared multi-replica authority for the dual-backend
surfaces above (see [configuration.md](configuration.md) and #238). Prefer
SQLite when you need the SQLite-only paths listed under Outcome.
