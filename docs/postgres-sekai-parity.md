# Reusable Sekai PostgreSQL parity

This note closes the parent reusable-Sekai PostgreSQL parity track and the
equal-PostgreSQL epic (#1328). Community PostgreSQL runtime selection is
activated by #238.
[ADR 0080](decisions/0080-dual-community-runtime-storage.md) keeps SQLite as
the local default and PostgreSQL as a first-class community backend.

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
read/list predicates across SQLite and PostgreSQL. Purpose authorizations and
classification lattices (#1321) share the same storage semantics, and a read
a lattice or a missing purpose denies is denied on both. Local `cargo test`
runs SQLite; PostgreSQL conformance runs on every pull request and stays
`#[ignore]` locally behind `SEKAI_TEST_POSTGRES_URL`.
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

The reusable `sekai.governed-document/v1` class shares document and rendition
metadata across SQLite and PostgreSQL. Experimental RPCs admit, attach
renditions, retrieve, hold, expire, and delete with the same owner, purpose,
classification, and hold rules as `sekaictl admin documents`. The plane
stores no bytes and runs no extractor
([ADR 0039](decisions/0039-governed-documents.md),
[documents.md](documents.md)). Normal CI runs SQLite; PostgreSQL
conformance remains an ignored isolated-database test behind
`SEKAI_TEST_POSTGRES_URL`.

The reusable `sekai.governed-transform/v1` class shares JobSpec, checkpoint,
and run-receipt persistence across SQLite and PostgreSQL. Execution is the
in-process `projection` host
([ADR 0097](decisions/0097-in-process-transform-host.md),
[governed-transforms.md](governed-transforms.md)). Isolated-process claim
I/O and partitioned write-back share the same envelope
([ADR 0105](decisions/0105-partitioned-transform-io.md), #1388). Normal CI
runs SQLite; PostgreSQL conformance remains an ignored isolated-database
test behind `SEKAI_TEST_POSTGRES_URL`. Dataset row `append_rows` /
`query_rows` through the community `RuntimeDb` dispatcher run on both
backends (#1320), with shared conformance for order, filters, projection,
paging and empty appends.

The reusable `sekai.connector-certification/v1` admin projection shares
certify, get, verify, revoke, and supersession identities across SQLite and
PostgreSQL. A revoked or unknown certification fails verification on both
backends. Normal CI runs SQLite; PostgreSQL conformance remains an ignored
isolated-database test behind `SEKAI_TEST_POSTGRES_URL`.

The product loop (ontology apply, seed, object reads, object-set evaluate,
governed Action submit and read, operation receipt, and object-security
activation with a denied read) runs on community PostgreSQL with SQLite
semantics. Audited ontology writes commit the definition and its chained
audit decision in one transaction; the relation write keeps the maximum
cardinality lock and tightening check. Synchronous PostgreSQL calls leave the
async worker through `RuntimeDb` before touching the pool, so gRPC handlers
never start a nested runtime. `tests/product_loop_backend_conformance.rs`
drives the loop through the shipped binary on both backends; the PostgreSQL
case is ignored and needs `SEKAI_TEST_POSTGRES_URL` for a server the test may
create a scratch database on.

**Remaining SQLite-only paths** after #1328 (community PostgreSQL fails
closed; do not treat inventory “complete” as dual-backend for these) live in
the shrink-only list
[`tests/fixtures/sqlite_only_surfaces/v1.json`](../tests/fixtures/sqlite_only_surfaces/v1.json)
(experimental ontology deletes and named admin projections) and in the Chisei
planning RPCs `PlanExecution` / `PlanContentExecution` (see
[postgres-chisei-parity.md](postgres-chisei-parity.md)). Execution-evidence
reject and record helpers used by evidence admission share SQLite and
PostgreSQL persistence (#1318).
`SekaiService.SubmitEvidence` is a dual-backend RPC.
Query-time ontology entailment on `RetrieveContext` / `ExpandRelations` runs
on PostgreSQL too (#1320), with a shared case asserting the same results; see
[rpc-maturity.md](rpc-maturity.md),
[ADR 0001](decisions/0001-query-time-ontology-entailment.md), and
[capability catalog](capability-catalog.md)).
Governed images, renditions, and annotations (`sekai.governed-image/v1`; see
[ADR 0050](decisions/0050-governed-images.md)) persist on community
PostgreSQL (#1479). Registered Iceberg/Parquet open-table projections persist
on community PostgreSQL (#1479). Versioned client packages
(`sekai.client-package/v1`; see
[ADR 0051](decisions/0051-versioned-client-packages.md)) persist on community
PostgreSQL (#1477). Capability-package certifications persist on community
PostgreSQL (#1478).

Evidence is checked in as:

| Artifact | Role |
| --- | --- |
| `tests/fixtures/sqlite_only_surfaces/v1.json` | Shrink-only SQLite-only RPCs and admin projections |
| `tests/fixtures/sekai_rpc_inventory/v1.json` | Fail-closed map of every `SekaiService` RPC to evidence |
| `tests/fixtures/runtime_backend/postgres-sekai-complete-v1.json` | Complete reusable Sekai capability advertisement |
| `tests/*_backend_conformance.rs` and related harnesses | Shared SQLite/PostgreSQL surface fixtures |
| `crates/sekai-core/src/db/sekai_rpc_inventory.rs` | Inventory load/validation and complete-capability helper |

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
| #1287 | In-process governed transform JobSpec, checkpoint, and run receipt |
| #1388 | Partitioned streaming transform I/O and atomic partition write-back |
| #1481 | Connector certification certify/get/verify/revoke on PostgreSQL |
| #1475 | Federation network contracts, site/peer tables, conflicts, and revocations |
| #1476 | Signed namespace snapshots, peer grants, and imported-assertion provenance |
| #1477 | Versioned client packages |
| #1478 | Capability-package certifications |
| #1479 | Governed images and open-table projections |
| #1316 | Backend support evidence and PostgreSQL conformance on every pull request |
| #1318 | Execution-evidence rejection and recording |
| #1319 | Action bindings |
| #1320 | Entailment retrieval, dataset rows, and one retention path |
| #1321 | Purpose authorizations and classification lattices |
| #1322 | Source-webhook key pins and source-type descriptors |
| #1325 | Governed documents |
| #1328 | Equal-PostgreSQL closeout: first-class community backend, not partial |

## Still outside this parent

- Chisei governed-decision and execution persistence (#237) — closed; see
  `docs/postgres-chisei-parity.md`
- Community PostgreSQL runtime activation (#238) — complete; select with `SEKAI_DB_BACKEND=postgres`
- Tenant state, tenant RPCs, OIDC, and OAuth
- Dest-pair `reconcile_missing_execution_evidence` cannot join the Sekai and
  Chisei stores on one connection and stays fail-closed on PostgreSQL
- Chisei `PlanExecution` and `PlanContentExecution` fail closed on PostgreSQL
  (receipt persist with Kioku holdouts); see the Chisei parity note

## Operator posture

SQLite remains the default community backend. PostgreSQL is a first-class
community choice: Combined PostgreSQL opens `SEKAI_DATABASE_URL` +
`CHISEI_DATABASE_URL` with `SEKAI_DB_BACKEND=postgres`. A single
`DATABASE_URL` is retired and refuses boot. Use that dest-pair when you need
shared multi-replica authority for the dual-backend surfaces above (see
[configuration.md](configuration.md) and #238). Remaining shrink-only
surfaces fail closed on PostgreSQL, as do Chisei `PlanExecution` and
`PlanContentExecution`.

Every pull request runs PostgreSQL conformance
(`.github/workflows/postgres-conformance.yml`). Local `cargo test` still
exercises the object-sync contract against SQLite. Run the ignored
PostgreSQL conformance and concurrent exact-replay fixtures with an isolated TLS
database:

```sh
SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test it object_sync_backend_conformance -- --ignored

SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test it definition_branch_backend_conformance -- --ignored

SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test it object_security_backend_conformance -- --ignored

SEKAI_TEST_POSTGRES_URL=... \
  cargo test postgres_workflow_transition_matrix -- --ignored --nocapture

SEKAI_TEST_POSTGRES_URL=... \
  cargo test postgres_concurrent_callback_and_cancel_race -- --ignored --nocapture

SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test it connector_certification_backend_conformance -- --ignored
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
