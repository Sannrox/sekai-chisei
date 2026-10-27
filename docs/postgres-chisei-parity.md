# Chisei PostgreSQL parity

This note closes the Chisei governed-decision and execution PostgreSQL parity
track (#237) and the equal-PostgreSQL epic (#1328). Community PostgreSQL
runtime selection is activated by #238. PostgreSQL is a first-class community
backend.

## Outcome

Most reusable Chisei decision and execution surfaces have PostgreSQL
persistence with shared SQLite/PostgreSQL conformance evidence, or are
explicit computed/query paths with named durable dependencies.
`GetEffectivePolicySummary` is also classified `experimental` and is rejected
unless `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled. See [rpc-maturity.md](rpc-maturity.md). SQLite-only RPCs and admin
projections are the shrink-only list
[`tests/fixtures/sqlite_only_surfaces/v1.json`](../tests/fixtures/sqlite_only_surfaces/v1.json).

| Surface | Status | Evidence |
| --- | --- | --- |
| `chisei.budget` | Proven for reserve/usage and limit projection | `tests/chisei_budget_backend_conformance.rs` |
| `chisei.execution` | Proven | `tests/chisei_execution_backend_conformance.rs` |
| `chisei.evaluation` / samples | Proven | `tests/chisei_eval_backend_conformance.rs` |
| `chisei.portfolio` | Proven | `tests/chisei_portfolio_backend_conformance.rs` |
| `chisei.policy` | Proven (graph objects) | `tests/chisei_policy_backend_conformance.rs` |
| `chisei.approvals` | Proven for issue/revoke/policy, online redeem, offline reconcile, and delegation-chain validation | `tests/chisei_external_action_backend_conformance.rs`, `tests/chisei_external_permit_backend_conformance.rs` |
| `chisei.learning` | Proven for Kioku lifecycle and Gunshi allocation | `tests/chisei_kioku_backend_conformance.rs`, `tests/chisei_gunshi_backend_conformance.rs` |
| `chisei.data-quality-rule` | SQLite-only | list entry `admin.data-quality`; see [data-quality-rules.md](data-quality-rules.md) |
| `chisei.observations` | Proven | eval sample harness |
| `gateway.governance` | Proven | receipt aliases + gateway audit harness |

## Inventory

| Artifact | Role |
| --- | --- |
| `tests/fixtures/chisei_rpc_inventory/v1.json` | Fail-closed map of every Chisei/LLM RPC |
| `tests/fixtures/runtime_backend/postgres-chisei-complete-v1.json` | Complete Chisei capability advertisement |
| `crates/sekai-core/src/db/chisei_rpc_inventory.rs` | Inventory validation and capability helper |
| `tests/chisei_*_backend_conformance.rs` | Shared SQLite/PostgreSQL harnesses |

`complete_chisei_surfaces` lists surfaces with dual-backend *storage* evidence
for the track’s inventory. Operators still hit SQLite-only fail-closed methods
named in
[`tests/fixtures/sqlite_only_surfaces/v1.json`](../tests/fixtures/sqlite_only_surfaces/v1.json).

## Delivery slices

| Slice | Outcome |
| --- | --- |
| Receipts / gateway aliases / budget events | Foundation PR |
| Eval / portfolio / policy / gateway audit harnesses | Dual harnesses for existing methods |
| External-action authorization and permits | PostgreSQL methods + harnesses |
| Kioku learning lifecycle | PostgreSQL methods + harnesses |
| Inventory complete capability | Parent closeout |
| Permit redeem, reconcile, and delegation (#1323) | Dual-backend approvals path |
| Equal-PostgreSQL epic (#1328) | First-class community backend closeout |

Tenant state, OIDC and OAuth are not Sekai-owned on any backend (ADR 0099,
#1613); tenant authority comes from the identity extension on either one.

## Still outside this track

- Host-local permit verification crypto (`verify_for_executor`) — never a
  control-plane dual-backend claim
- `PlanExecution` and `PlanContentExecution` fail closed on PostgreSQL:
  both persist the plan through `put_operation_receipt_with_kioku_holdouts`,
  which the community PostgreSQL store rejects even with an empty holdout
  list. This is a public planning limitation, not a shrink-only helper.
- Dest-pair `reconcile_missing_execution_evidence` cannot join the Sekai and
  Chisei stores on one connection and stays fail-closed on PostgreSQL

## Operator posture

SQLite remains the default community backend. PostgreSQL is a first-class
community choice. Combined PostgreSQL opens `SEKAI_DATABASE_URL` +
`CHISEI_DATABASE_URL` with `SEKAI_DB_BACKEND=postgres`. A single
`DATABASE_URL` is retired and refuses boot. Use that dest-pair for
dual-backend budget reserve/usage, limit projection, policy, execution
storage, Kioku, permit redeem/reconcile, and gateway governance (see
[configuration.md](configuration.md) and #238). `PlanExecution` and
`PlanContentExecution` fail closed on PostgreSQL until receipt persist with
Kioku holdouts lands. Remaining shrink-only admin projections
(`admin.data-quality`, `admin.learning-change`) also fail closed.
