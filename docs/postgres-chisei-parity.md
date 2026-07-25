# Chisei PostgreSQL parity

This note closes the Chisei governed-decision and execution PostgreSQL parity
track (#237). It does not activate community PostgreSQL runtime selection
(#238).

## Outcome

Every reusable Chisei decision and execution surface has PostgreSQL persistence
with shared SQLite/PostgreSQL conformance evidence, or is an explicit
computed/query path with named durable dependencies.

| Surface | Status | Evidence |
| --- | --- | --- |
| `chisei.budget` | Proven | `tests/chisei_budget_backend_conformance.rs` |
| `chisei.execution` | Proven | `tests/chisei_execution_backend_conformance.rs` |
| `chisei.evaluation` / samples | Proven | `tests/chisei_eval_backend_conformance.rs` |
| `chisei.portfolio` | Proven | `tests/chisei_portfolio_backend_conformance.rs` |
| `chisei.policy` | Proven (graph objects) | `tests/chisei_policy_backend_conformance.rs` |
| `chisei.approvals` | Proven | `tests/chisei_external_action_backend_conformance.rs`, `tests/chisei_external_permit_backend_conformance.rs` |
| `chisei.learning` | Proven | `tests/chisei_kioku_backend_conformance.rs` |
| `chisei.observations` | Proven | eval sample harness |
| `gateway.governance` | Proven | receipt aliases + gateway audit harness |

## Inventory

| Artifact | Role |
| --- | --- |
| `tests/fixtures/chisei_rpc_inventory/v1.json` | Fail-closed map of every Chisei/LLM RPC |
| `tests/fixtures/runtime_backend/postgres-chisei-complete-v1.json` | Complete Chisei capability advertisement |
| `src/db/chisei_rpc_inventory.rs` | Inventory validation and capability helper |
| `tests/chisei_*_backend_conformance.rs` | Shared SQLite/PostgreSQL harnesses |

`complete_chisei_surfaces` lists only surfaces with dual-backend evidence.
`remaining_surfaces` is empty after closeout.

## Delivery slices

| Slice | Outcome |
| --- | --- |
| Receipts / gateway aliases / budget events | Foundation PR |
| Eval / portfolio / policy / gateway audit harnesses | Dual harnesses for existing methods |
| External-action authorization and permits | PostgreSQL methods + harnesses |
| Kioku learning lifecycle | PostgreSQL methods + harnesses |
| Inventory complete capability | This closeout |

## Still outside this track

- Community PostgreSQL runtime activation (`SEKAI_DB_BACKEND=postgres`) — #238
- Tenant state, OIDC, and OAuth
- Full permit redemption crypto paths that stay host-local

## Operator posture

SQLite remains the default community backend. PostgreSQL may be used for
composition and isolated conformance. Public community runtime selection of
PostgreSQL still fails closed until every community-required surface—including
Sekai foundations and operations health—can be advertised truthfully (#238).
