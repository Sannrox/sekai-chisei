# Chisei PostgreSQL parity

This note closes the Chisei governed-decision and execution PostgreSQL parity
track (#237). Community PostgreSQL runtime selection is activated by #238.

## Outcome

Most reusable Chisei decision and execution surfaces have PostgreSQL
persistence with shared SQLite/PostgreSQL conformance evidence, or are
explicit computed/query paths with named durable dependencies.

| Surface | Status | Evidence |
| --- | --- | --- |
| `chisei.budget` | Proven | `tests/chisei_budget_backend_conformance.rs` |
| `chisei.execution` | Proven | `tests/chisei_execution_backend_conformance.rs` |
| `chisei.evaluation` / samples | Proven | `tests/chisei_eval_backend_conformance.rs` |
| `chisei.portfolio` | Proven | `tests/chisei_portfolio_backend_conformance.rs` |
| `chisei.policy` | Proven (graph objects) | `tests/chisei_policy_backend_conformance.rs` |
| `chisei.approvals` | Proven for issue/revoke/policy; **online redeem SQLite-only** | `tests/chisei_external_action_backend_conformance.rs`, `tests/chisei_external_permit_backend_conformance.rs` (issue/revoke paths); `RuntimeDb::redeem_permit` fails closed on Postgres |
| `chisei.learning` | Proven for Kioku lifecycle; **Gunshi allocation state SQLite-only** | `tests/chisei_kioku_backend_conformance.rs`; see [gunshi-auto-allocation.md](gunshi-auto-allocation.md) |
| `chisei.data-quality-rule` | **SQLite-only**; PostgreSQL fails closed | `src/chisei/data_quality.rs`; see [data-quality-rules.md](data-quality-rules.md) |
| `chisei.observations` | Proven | eval sample harness |
| `gateway.governance` | Proven | receipt aliases + gateway audit harness |

## Inventory

| Artifact | Role |
| --- | --- |
| `tests/fixtures/chisei_rpc_inventory/v1.json` | Fail-closed map of every Chisei/LLM RPC |
| `tests/fixtures/runtime_backend/postgres-chisei-complete-v1.json` | Complete Chisei capability advertisement |
| `src/db/chisei_rpc_inventory.rs` | Inventory validation and capability helper |
| `tests/chisei_*_backend_conformance.rs` | Shared SQLite/PostgreSQL harnesses |

`complete_chisei_surfaces` lists surfaces with dual-backend *storage* evidence
for the track’s inventory. Operators still hit SQLite-only fail-closed methods
for online permit redeem/reconcile/delegation validation and Gunshi allocation
CAS (see table above).

## Delivery slices

| Slice | Outcome |
| --- | --- |
| Receipts / gateway aliases / budget events | Foundation PR |
| Eval / portfolio / policy / gateway audit harnesses | Dual harnesses for existing methods |
| External-action authorization and permits | PostgreSQL methods + harnesses |
| Kioku learning lifecycle | PostgreSQL methods + harnesses |
| Inventory complete capability | This closeout |

## Still outside this track

- Tenant state, OIDC, and OAuth
- Host-local permit verification crypto (`verify_for_executor`) — never a
  control-plane dual-backend claim
- Control-plane **online redeem**, offline reconcile, delegation-chain
  validation, and Gunshi allocation state (SQLite-only community runtime)

## Operator posture

SQLite remains the default community backend. Select PostgreSQL with
`SEKAI_DB_BACKEND=postgres` and `DATABASE_URL` for dual-backend budgets, policy,
execution, Kioku, and gateway governance. Prefer SQLite when hosts must redeem
online permits or use Gunshi auto-allocation durability (see
[configuration.md](configuration.md) and #238).
