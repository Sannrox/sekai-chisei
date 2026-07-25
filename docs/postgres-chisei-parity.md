# Chisei PostgreSQL parity

This note tracks PostgreSQL parity for Chisei governed decisions and execution
(#237). It does not activate community PostgreSQL runtime selection (#238).

## Outcome so far

| Surface | Status | Evidence |
| --- | --- | --- |
| `chisei.budget` | Proven (limits, chain reservation, idempotent events, attributions) | `tests/chisei_budget_backend_conformance.rs`, `src/db/postgres_budget.rs` |
| `chisei.execution` | Proven (receipts, reporter grants, gateway aliases) | `tests/chisei_execution_backend_conformance.rs`, `src/db/postgres_chisei_receipts.rs` |
| `chisei.evaluation` / evolve / samples | Schema + methods present; dual harness incomplete | `src/db/postgres_eval.rs` |
| `chisei.portfolio` | Schema + methods present; dual harness incomplete | `src/db/postgres_portfolio.rs` |
| `chisei.policy` / egress | Durable via graph objects when present; dual harness incomplete | graph conformance + service loaders |
| `chisei.approvals` / external action | Schema migrated; method parity remaining | migration `0017_chisei_execution_parity.sql` |
| `chisei.learning` (kioku / gunshi) | Schema migrated; method parity remaining | migration `0017_chisei_execution_parity.sql` |
| `gateway.governance` | Alias reserve/claim proven; full gateway audit path remaining | receipt harness |

## Inventory

`tests/fixtures/chisei_rpc_inventory/v1.json` maps every `ChiseiService` and
`LlmService` RPC to persistence kind, surfaces, and evidence. Validation lives
in `src/db/chisei_rpc_inventory.rs`.

`complete_chisei_surfaces` lists only surfaces with shared SQLite/PostgreSQL
harness evidence. Remaining surfaces stay fail-closed for community runtime
selection.

## Remaining work for #237 closeout

1. Dual-backend conformance for evaluation, portfolio, sample observations.
2. PostgreSQL methods + harness for external-action authorization and permits.
3. PostgreSQL methods + harness for kioku learning lifecycle.
4. Policy/egress/gateway audit parity evidence beyond graph storage.
5. Advertise complete Chisei surfaces only after every inventory fixture passes.
6. Keep secrets and provider stream content outside durable storage.

## Operator posture

SQLite remains the default community backend. PostgreSQL may run isolated
conformance and partial composition. Public `SEKAI_DB_BACKEND=postgres`
selection still fails closed until every community-required surface is proven.
