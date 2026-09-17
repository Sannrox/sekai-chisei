# ADR 0082: Separate Chisei and Sekai durable stores

- Status: accepted
- Date: 2026-09-17
- Owners: @Sannrox
- Discussion: [Reference platform boundary research](../research/957-reference-platform-boundary.md)
- Issue: none; accepted in the architecture discussion for this change
- Supersedes: none
- Superseded by: none
- Related: [ADR 0065](0065-workflow-action-postgres-parity.md),
  [ADR 0069](0069-operation-correlation.md),
  [ADR 0079](0079-evaluation-promotion-gate.md),
  [ADR 0080](0080-dual-community-runtime-storage.md)

## Context

The current runtime initializes one `RuntimeDb` from `DB_PATH` and builds both
Sekai and Chisei services over that store. That database currently contains
durable Chisei budgets, workflow state, evaluation execution indexes, and
operation receipts alongside Sekai objects, action state, authorization, and
audit records.

That arrangement is compatible with one process, but it does not create a real
authority boundary. A separate Chisei process that still reaches the Sekai
database would only move the coupling behind a transport façade. Conversely,
making Chisei entirely in-memory would lose the durable state required for
budget accounting, workflow recovery, evaluation history, idempotency, and
receipt lookup.

The accepted architecture therefore needs two durable owners and an explicit
protocol for operations that cross them.

## Decision

1. **Use two durable stores.** Sekai and Chisei each own a separate database.
   SQLite uses separate files; PostgreSQL uses separate database URLs or
   databases. A shared PostgreSQL cluster is acceptable, but the databases and
   credentials remain separate.
2. **Sekai owns authoritative facts and commits:** objects, links, schemas,
   semantic descriptors, authorization enforcement, action instances, local
   effects, mutation audit, commit idempotency, and Sekai commit receipts.
3. **Chisei owns decision state:** budgets, reservations, workflow orchestration
   state, policy decisions, evaluations, model/tool execution records, Chisei
   idempotency, and Chisei decision receipts.
4. **Do not use cross-database foreign keys.** Cross-plane records refer to one
   another using a global `operation_id`, immutable digests, and explicit
   service contracts. References are validated by protocol calls, not joins.
5. **Keep receipts plane-specific.** A Chisei decision receipt records policy,
   budget, routing, and evaluation evidence. A Sekai commit receipt records
   authoritative mutation, audit, and effect-intent evidence. A public response
   may correlate both, but neither store becomes a duplicate receipt authority.
6. **Use a durable reservation protocol instead of distributed transactions.**
   Chisei records a decision and reserves budget; Sekai re-checks current
   authority and atomically commits its local mutation; Chisei finalizes or
   releases the reservation after the Sekai result. Unknown outcomes remain
   pending until reconciliation resolves them by `operation_id`.
7. **Combined mode still opens two stores.** The combined process uses the same
   typed boundary with an in-process adapter, but it must not fall back to one
   shared database. This keeps local development and tests honest about the
   production boundary.
8. **Split configuration is explicit.** Introduce separate Sekai and Chisei
   paths/URLs. Existing single-store configuration is migration compatibility,
   not the target architecture.

## Alternatives considered

- **One database with separate schemas.** Rejected as the target because it
  preserves cross-domain transaction convenience at the cost of database,
  migration, backup, and credential coupling. It remains a useful temporary
  migration state only if explicitly treated as non-final.
- **Stateless Chisei with all durable state in Sekai.** Rejected because it
  gives Sekai ownership of policy-ledger, workflow, and evaluation records that
  belong to Chisei, and makes the decision process dependent on a broad
  persistence API. Chisei may use Sekai for facts and commit authority, but it
  owns its own durable decision state.

## Consequences

The split gives each process an enforceable database boundary, independent
backup and restore scope, clearer migrations, and the ability to restart or
scale decision workers without exposing Sekai storage credentials.

The cost is a cross-database failure protocol. Budget reservation, Sekai
commit, receipt finalization, retries, and reconciliation must be idempotent
and observable. A timeout cannot be interpreted as rejection, and a local
Chisei reservation cannot be released until Sekai confirms that the operation
was not committed.

Existing `InvokeActionInstance` behavior remains compatible at the public
façade while its implementation is decomposed into:

```text
read authorized Sekai context
  -> decide and reserve in Chisei
  -> submit revision-bound admission to Sekai
  -> commit Sekai mutation
  -> finalize Chisei state
  -> return correlated decision and commit receipts
```

Chisei code must not receive a `RuntimeDb`, SQL handle, Sekai database
credential, or arbitrary mutation endpoint. Sekai must not accept a Chisei
decision as a substitute for current authorization or action constraints.

## Validation

- SQLite and PostgreSQL each pass conformance for both stores.
- Combined mode opens two independent stores and passes the same contract tests
  as split mode.
- Subprocess tests prove database isolation, wrong-plane rejection, and
  authenticated service-to-service calls.
- Failure tests cover crash after reservation, timeout after Sekai commit,
  duplicate admission, stale revisions, reservation expiry, and reconciliation.
- Restart tests prove that budgets, workflows, evaluations, and receipts remain
  recoverable.
- Backup/restore and migration tests cover both stores independently and verify
  correlation by `operation_id` without cross-database joins.
