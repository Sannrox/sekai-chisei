# Reusable Sekai PostgreSQL parity

This note closes the parent reusable-Sekai PostgreSQL parity track. Community
PostgreSQL runtime selection is activated by #238.

## Outcome

Most tenant-free `SekaiService` operations required by the public reusable
runtime have PostgreSQL persistence with shared SQLite/PostgreSQL conformance,
or are explicit computed/query paths with named durable dependencies. The
reusable `sekai.object-sync` surface and public `ApplySourceBatch` and
`GetSourceSyncState` RPCs also have shared conformance for source binding,
durable batch transactions, identities, results, graph/audit application, and
control-plane-owned checkpoints. Version 2 coverage additionally includes
generation transitions, snapshot/feed handoff, exact replay, contiguous offset
advancement, reordered and overlapping range aborts, missing-range recovery,
and next-generation snapshot reset. Every accepted generation and offset change
shares the transaction that commits objects, object-change audit, identities,
lineage, results, and the checkpoint. The same backend harness covers two-page
snapshot resume, cross-page stable object identity, old-page replay, stale
cursors, and foreign binding isolation.

The reusable `sekai.definition-branch` surface shares insert-only member and
revision storage, expected-head advancement, digest-bound proposals, published
head compare-and-swap, idempotency, and audit semantics across SQLite and
PostgreSQL. PostgreSQL serializes branch, published-head, and idempotency
identities before checking durable state, so concurrent writers cannot both
advance one expected head or publish two change sets onto the same base.

The reusable `sekai.object-security` surface shares immutable policy
revisions, exact replay, complete atomic activation, and SQL-enforced direct
read/list predicates across SQLite and PostgreSQL. Normal CI runs SQLite;
PostgreSQL conformance remains an ignored isolated-database test.

**Known SQLite-only public paths** (community Postgres fails closed; do not
treat inventory “complete” as dual-backend for these RPCs):

- audited ontology mutations (`upsert_*_with_audit`);
- query-time ontology entailment (`RetrieveContext`, `ExpandRelations`, and
  lookup-first expansion in `entailment` mode; see
  [ADR 0001](decisions/0001-query-time-ontology-entailment.md) and
  [capability catalog](capability-catalog.md));
- multi-control-plane federation site/peer tables (see
  [federation-profile.md](federation-profile.md));

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
| #261–#265 | Guarded mutations, definition lifecycle, decisions, team namespaces |
| #462 | Graph-backed governed requirement, invariant, waiver, and invariant-set facts |
| #665, #671, #672 | Bounded source-batch transactions, checkpointed snapshot paging, and generation-fenced ordered feeds |
| #666 | Governed definition branch and immutable revision foundation |
| #683 | Digest-bound proposal, live approval, and atomic published-head merge |
| #667 (first slice) | Activated object-security revisions and direct read/list enforcement |

## Still outside this parent

- Chisei governed-decision and execution persistence (#237) — closed; see
  `docs/postgres-chisei-parity.md`
- Community PostgreSQL runtime activation (#238) — complete; select with `SEKAI_DB_BACKEND=postgres`
- Tenant state, tenant RPCs, OIDC, and OAuth

## Operator posture

SQLite remains the default community backend. Select PostgreSQL with
`SEKAI_DB_BACKEND=postgres` and `DATABASE_URL` for the reusable public control
plane when you need shared multi-replica authority for the dual-backend
surfaces above (see [configuration.md](configuration.md) and #238). Prefer
SQLite when you need the SQLite-only paths listed under Outcome.

Normal CI exercises the object-sync contract against SQLite. Run the ignored
PostgreSQL conformance and concurrent exact-replay fixtures with an isolated TLS
database:

```sh
SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test object_sync_backend_conformance -- --ignored

SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test definition_branch_backend_conformance -- --ignored

SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test object_security_backend_conformance -- --ignored
```

The ordered-feed migration is additive and one-way on both backends. Version 1
transactions and checkpoints remain readable and exactly replayable, but new v1
batches cannot advance a binding after v2 generation state begins. Retain batch
and record-result history with generation and offset state; object-change audit
alone is not continuity evidence and may have a different retention window.

Before enabling v2 on a binding, take one consistent backup containing graph,
object-change audit, source binding, transaction, generation, identity, lineage,
result, and checkpoint tables. Rolling back the binary does not reverse a
committed generation or offset. A binary that cannot read v2 state requires
restoring the complete pre-v2 backup; do not delete or edit individual source
sync rows.

PostgreSQL does not weaken the trust boundary: `GetSourceSyncState` still
requires namespace read authority, `ApplySourceBatch` and recovery snapshots
require namespace write authority from the bound authenticated producer, and
delivery metadata does not grant access. Diagnostics remain bounded and must
not expose source payloads, feed epochs, cursors, credentials, authorization
metadata, SQL text, or database details.
