# Reusable Sekai PostgreSQL parity

This note closes the parent reusable-Sekai PostgreSQL parity track. Community
PostgreSQL runtime selection is activated by #238.
[ADR 0080](decisions/0080-dual-community-runtime-storage.md) keeps SQLite as
the local default and PostgreSQL as the optional community backend.

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
revision storage, proposal and published-head identity, expected-head
advancement, merge receipt compare-and-swap, close reasons, idempotency, and
audit semantics across SQLite and PostgreSQL.
PostgreSQL serializes branch, proposal, and idempotency identities before
checking durable state, so concurrent writers cannot both advance one expected
head or published pointer.

The reusable `sekai.object-security` surface shares immutable policy
revisions, exact replay, complete atomic activation, and SQL-enforced direct
read/list predicates across SQLite and PostgreSQL. Normal CI runs SQLite;
PostgreSQL conformance remains an ignored isolated-database test.
`sekai.geospatial-query/v1` is a computed query on that authorized list:
both backends share the same in-process evaluator after property grants.
`sekai.source-health/v1` is a computed projection of authorized
`get_source_sync_state`: both backends share the same in-process classifier
and add no health table.

The reusable workflow-action bridge stores share the same binding, callback,
and command-replay identities across SQLite and PostgreSQL. Every accepted
submit, park, callback, or cancel shares the `commit_workflow_transition`
transaction. PostgreSQL serializes writers with a transaction-scoped advisory
lock; expected-binding equality remains the commit rule. See
[ADR 0065](decisions/0065-workflow-action-postgres-parity.md).

The reusable event-stream projection and subscription stores share the same
binding, checkpoint, admitted-event, and cursor identities across SQLite and
PostgreSQL. Every accepted checkpoint or cursor change shares the transaction
that commits the compare-and-swap pins and, for projections, the event
commitments. PostgreSQL serializes writers with a transaction-scoped advisory
lock; the CAS predicates remain the commit rule. Normal CI runs SQLite;
PostgreSQL conformance remains an ignored isolated-database test. See
[ADR 0064](decisions/0064-event-stream-postgres-parity.md).

**Known SQLite-only public paths** (community Postgres fails closed; do not
treat inventory “complete” as dual-backend for these RPCs):

- audited ontology mutations (`upsert_*_with_audit`);
- query-time ontology entailment (`RetrieveContext`, `ExpandRelations`, and
  lookup-first expansion in `entailment` mode; those RPCs are classified
  `experimental` and require `SEKAI_EXPERIMENTAL_RPCS=1` or the
  `experimental-rpcs` feature; see [rpc-maturity.md](rpc-maturity.md),
  [ADR 0001](decisions/0001-query-time-ontology-entailment.md), and
  [capability catalog](capability-catalog.md));
- dataset row `append_rows` / `query_rows` through the community `RuntimeDb`
  dispatcher;
- execution-evidence reject and record helpers used by evidence admission;
- SQLite-named retention run/purge/`archive_retained_records` (Postgres uses
  `archive_lifecycle_records` instead);
- multi-control-plane federation site/peer tables (see
  [federation-profile.md](federation-profile.md));
- purpose authorizations for `required_purpose` reads (`sekai.purpose-authorization/v1`;
  see [ADR 0031](decisions/0031-purpose-bound-reads.md));
- classification lattice publication (`sekai.classification-lattice/v1`;
  see [ADR 0032](decisions/0032-hierarchical-classifications.md)); PostgreSQL
  get returns no lattice so the default ceiling remains;
- signed namespace snapshots and imported assertion provenance
  (`sekai.namespace-snapshot/v1`, `sekai.federation-provenance/v1`; see
  [ADR 0029](decisions/0029-signed-namespace-snapshots.md) and
  [ADR 0034](decisions/0034-cross-site-import-provenance.md));
- source-webhook verifying-key pins (`sekai.source-webhook-delivery/v1`; see
  [ADR 0035](decisions/0035-source-webhook-transport.md)); batch apply keeps its
  existing dual-backend path;
- registered source-type descriptors (`sekai.source-type-descriptor/v1`; see
  [ADR 0060](decisions/0060-additive-source-type-descriptors.md)); GitHub
  `ApplySourceBatch` keeps its existing dual-backend path;
- registered Iceberg and Parquet snapshot projections
  (`sekai.open-table-source/v1`; see
  [ADR 0036](decisions/0036-open-table-projections.md));
- governed documents and renditions
  (`sekai.governed-document/v1`; see
  [ADR 0039](decisions/0039-governed-documents.md));
- governed images, renditions, and annotations
  (`sekai.governed-image/v1`; see
  [ADR 0050](decisions/0050-governed-images.md));
- versioned client packages
  (`sekai.client-package/v1`; see
  [ADR 0051](decisions/0051-versioned-client-packages.md));
- capability-package certifications
  (`sekai.capability-package-certification/v1`; see
  [ADR 0052](decisions/0052-capability-package-certification.md));
- federation network contracts
  (`sekai.federation-network-contract/v1`; see
  [ADR 0053](decisions/0053-federation-network-contracts.md));

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
| #667 (first slice) | Activated object-security revisions and direct read/list enforcement |

## Still outside this parent

- Chisei governed-decision and execution persistence (#237) — closed; see
  `docs/postgres-chisei-parity.md`
- Community PostgreSQL runtime activation (#238) — complete; select with `SEKAI_DB_BACKEND=postgres`
- Tenant state, tenant RPCs, OIDC, and OAuth

## Operator posture

SQLite remains the default community backend. Combined PostgreSQL opens
`SEKAI_DATABASE_URL` + `CHISEI_DATABASE_URL` with `SEKAI_DB_BACKEND=postgres`.
A single `DATABASE_URL` is Combined shared-compat and needs
`SEKAI_SHARED_STORE=1`. Use that dest-pair (or hatch) when you need shared
multi-replica authority for the dual-backend surfaces above (see
[configuration.md](configuration.md) and #238). Prefer SQLite when you need
the SQLite-only paths listed under Outcome.

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

SEKAI_TEST_POSTGRES_URL=... \
  cargo test postgres_workflow_transition_matrix -- --ignored --nocapture

SEKAI_TEST_POSTGRES_URL=... \
  cargo test postgres_concurrent_callback_and_cancel_race -- --ignored --nocapture
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
