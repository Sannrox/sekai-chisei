# Changelog

## Unreleased

- Certify the catalogued GitHub object-sync connector as a
  `sekai.connector-certification/v1` record. Certification binds producer,
  type digest, signer, and tests to one independently verifiable digest.
  It is not a runtime grant. Exact replay is idempotent. Package or test
  change invalidates verification. Recertification and revocation preserve
  history. Secrets and hidden fields fail closed. `sekaictl admin connectors`
  certifies, retrieves, verifies, and revokes. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Map external workflow steps onto ActionInstance admission through
  `sekai.workflow-action-bridge/v1`. Two domain-neutral adapters project
  job and approval steps. Submit, park, resume, cancel, and callback are
  generation-fenced and idempotent. Adapters never receive policy, budget,
  or receipt authority. `sekaictl admin workflow` submits, parks, resumes,
  cancels, callbacks, and reconciles. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Exchange governed requests, evidence, and outcomes through bilateral
  `sekai.federation-network-contract/v1` contracts. Each plane keeps local
  write authority. Peer loss disconnects without deleting history; reconnect
  restores accepted status; revocation is terminal. Untrusted origin,
  mismatched residency, and tampered envelopes fail closed.
  `sekaictl admin network` accepts, exchanges, marks peer loss, reconnects,
  and revokes. SQLite is the reference store; PostgreSQL stays unavailable.
- Certify capability packages as `sekai.capability-package-certification/v1`
  objects. Each certification binds signer, manifest members, compatibility,
  tests, and revocation to one independently verifiable digest. Replay of a
  live certification is idempotent. Content or dependency change invalidates
  verification. Recertification and revocation preserve history. Certification
  is not a runtime grant. `sekaictl admin packages` certifies, retrieves,
  verifies, and revokes. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Publish versioned `sekai.client-package/v1` objects for Rust, TypeScript,
  and Python clients. Each publication pins protocol, source, and package
  digests plus provenance. Replay of the same live identity is idempotent.
  A later version supersedes the previous publication; the same version cannot
  be silently replaced. Tampered digests, unknown languages, stale contracts,
  and foreign owners fail as unavailable. `sekaictl admin sdk-packages`
  publishes, retrieves, verifies, and smokes. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Govern images as first-class `sekai.governed-image/v1` objects with
  digest-bound content references, thumbnail and derived-metadata renditions,
  and bounded region/label annotations. Admission, retrieval, hold, expiry,
  and deletion are namespace-scoped. Requesting `bytes` or `binary`, a hidden
  or unknown field, a mismatched purpose, or a foreign owner fails as
  unavailable before disclosure. `sekaictl admin images` admits, attaches,
  retrieves, holds, expires, and deletes. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Enforce value-instance access as an optional `value_instance_grants` cell
  grant on `sekai.object-security-policy/v1`. Row predicates and property
  grants still run first. Named cells are authorized before find, list,
  traverse, export, or derived evaluation. Property sorts and non-equality
  filters fail closed while cell grants are enforced. Hidden and unknown
  cells share one unavailable result. Twin objects that differ only in a
  hidden cell are indistinguishable. Revocation applies on the next
  statement.
  SQLite is the reference store; reusable PostgreSQL shares the same
  deny-before-query and in-process projection rules.
- Expose authorized `sekai.event-subscription/v1` consumer cursors over
  admitted event-stream projections. Pages bind stream identity, schema
  revision, and definition digest. Exact replay is idempotent. Gaps, late
  pages, hidden columns, foreign or unknown identifiers, revocation, and
  expired retention fail before disclosure. `sekaictl admin streams`
  subscribe, pull, cursor, and revoke. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Push eligible open-table predicates as a `sekai.virtual-pushdown/v1` plan.
  Authorized `eq`/`neq` filters may execute on the registered Iceberg or
  Parquet adapter. Residual numeric predicates stay local. Hidden, unknown, and
  sensitive columns fail before any row. The projection is admitted only when
  local and adapter digests match. `sekaictl admin tables query --filter`
  inspects the plan. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Report authorized `sekai.source-health/v1` checkpoint age, lag, last success,
  and a bounded failure class for each source. Health is a projection of
  existing object-sync state: it never writes a second checkpoint, stores
  credentials, or probes a remote connector. Hidden and unknown sources share
  one unavailable result. Unknown versions, foreign identity, invalid
  checkpoints, and ambiguous lifecycle fail closed. `sekaictl admin sync health`
  is the operator surface. SQLite and reusable PostgreSQL share
  `get_source_sync_state` and the same in-process projector.
- Evaluate a versioned `chisei.data-quality-rule/v1` against a typed dataset
  revision and retain a `chisei.data-quality-result/v1` receipt. Built-in
  evaluators are digest pin, completeness, and row-count bound. Pass, fail,
  missing, invalid, unknown, cancelled, and unavailable stay distinct and never
  become pass. Replay returns the prior receipt. Restart completes cancelled
  work without rewriting a closed result. `sekaictl admin quality` publishes,
  evaluates, cancels, and restarts. SQLite is the reference store; PostgreSQL
  stays unavailable.
- Query authorized `sekai.geospatial-value/v1` point and polygon claims as a
  `sekai.geospatial-query/v1` effect. Operators are point, distance, contains,
  and intersects. The named property is authorized before match, count, or
  page. Hidden and unknown names share one unavailable result. Hidden and
  absent objects are indistinguishable. Audit records operator, property,
  namespace, and total — not coordinates. `sekaictl admin geospatial query`
  is the operator surface. SQLite and the reusable PostgreSQL graph list
  share the same in-process evaluator. This adds no spatial index table.
- Give every learned proposal a governed `chisei.learning-change/v1` record
  with evidence, before-and-after comparison, approval, activation, and
  reversible supersession lineage. Stale, hidden, unknown, and lease-lost
  inputs fail closed. `sekaictl admin learning` proposes, inspects, approves,
  activates, and rolls back. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Revoke peer, signer, grant, or snapshot-revision authority as governed
  `sekai.federation-revocation/v1` records. Local verify and import fail
  immediately. Snapshots, conflicts, and provenance stay retained.
  Propagation acknowledgement stays `unknown` until reconnect observes
  `denied` or `reconciled`. `sekaictl admin federation` revokes, lists, and
  inspects that evidence. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Preserve concurrent federation assertions as governed
  `sekai.federation-conflict/v1` records. Import stores both claims, never
  overwrites the local object or peer snapshot, and requires an explicit
  reversible resolution. Unknown, untrusted, and hidden peer data still fail
  closed before admission. `sekaictl admin federation` lists, shows, resolves,
  and reopens conflicts. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Generate a revision-pinned Python ontology client from the same selected
  object, link, action, and function members as the TypeScript contract.
  Shared selection, scope, and fail-closed errors stay identical. The
  package embeds the digest and selected names only. Live gRPC
  reauthorization remains the grant. Language-specific package identity
  rejects a tampered Python payload. `tests/fixtures/ontology_codegen/scoped_client.v1.py`
  is the golden. This adds no storage schema.
- Govern documents as first-class objects with digest-bound content
  references and derived renditions. Admission, extraction provenance,
  bounded retrieval, hold, expiry, and deletion are namespace-scoped and
  fail closed on mismatched purpose, hidden fields, unknown formats, and
  foreign ownership. `sekaictl admin documents` admits, attaches, retrieves,
  holds, expires, and deletes. SQLite is the reference store; PostgreSQL
  stays unavailable.
- Authorize property-level reads before every public query surface. Named
  predicates and sorts fail closed whether the property is hidden or unknown.
  Hidden values are omitted from get, list, find, traverse, lineage, and
  context projections and cannot feed computed properties. Revocation applies
  on the next statement.
- Project typed events from registered streams with durable generation, epoch,
  and offset checkpoints. Exact replay is idempotent; gaps, late offsets,
  malformed batches, and foreign ownership fail without moving the checkpoint.
  Hidden fields are omitted. `sekaictl admin streams` registers, projects, and
  inspects checkpoints. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Query typed authorized projections over registered Iceberg tables and
  Parquet files as digest-pinned local snapshots. Hidden or unauthorized
  columns fail the whole query; unrequested hidden fields are omitted.
  Corrupt metadata, unsupported revisions, and foreign ownership fail closed.
  `sekaictl admin tables` registers sources, admits snapshots, and queries.
  SQLite is the reference store; PostgreSQL stays unavailable.
- Admit signed `sekai.source-webhook-delivery/v1` envelopes as collection
  transport into the existing object-sync batch contract. The plane pins a
  verifying key, fails closed on forged, expired, oversized, or unpinned
  deliveries, and reuses the delivery id as the batch idempotency key.
  `sekaictl admin sync` pins keys and admits bundles. SQLite stores pins;
  PostgreSQL pin surfaces stay unavailable.
- Preserve an immutable provenance chain from each imported namespace
  snapshot assertion to signed source evidence. Re-export appends signer,
  transform, and verification hops without rewriting earlier hops. Hidden,
  missing, and revoked assertions return the same unavailable result.
  `sekaictl admin federation show-snapshot-provenance` inspects an authorized
  chain. SQLite is the reference store; PostgreSQL stays unavailable.
- Generate a revision-pinned Python ontology client from the same selected
  object, link, action, and function members as the TypeScript contract.
  Shared fixtures prove names, types, errors, scopes, and package identity.
  Live gRPC reauthorization remains the grant. Empty selection, unknown
  members, stale pins, tampered packages, and excessive scope fail without
  catalog disclosure. Published property keys are preserved.
- Generate a revision-pinned TypeScript ontology client from selected object,
  link, action, and function members of one published definition revision.
  The package embeds the digest and selected names only. Live gRPC
  reauthorization remains the grant. Empty selection, unknown members, stale
  pins, tampered packages, and excessive scope fail without catalog
  disclosure. `function` is a first-class definition member kind.
- Evaluate object markings against an optional namespace-local
  `sekai.classification-lattice/v1`. Dominance is reachability; hops take the
  least upper bound and deny incomparable joins. Unknown tokens and stale
  lattice identity fail closed. Unmarked data and namespaces that never
  publish a lattice keep the evidence ordinal. Credential admins publish the
  lattice through `PutClassificationLattice` and `GetClassificationLattice`.
  SQLite stores it; PostgreSQL get stays empty so the default ceiling remains.
- Require a scoped, expiring purpose authorization for governed reads when an
  activated object-security policy names `required_purpose`. Missing,
  incompatible, expired, wrong-actor, stale-activation, or out-of-scope purpose
  denies before access. Credential admins issue and revoke
  `sekai.purpose-authorization/v1` through `PutPurposeAuthorization` and
  `RevokePurposeAuthorization`. SQLite stores the authorizations; PostgreSQL
  fails closed as unavailable.
- Apply one compiled object-security read predicate to every public query
  path. Property search, external-id lookup, links, linked objects, traversal,
  and lineage omit hidden rows in storage before counts, pagination, or graph
  expansion. Hidden rows stay observationally identical to absent rows. ACL,
  team-namespace, and markings remain additional narrowing layers.
- Export and import bounded signed namespace snapshots under explicit peer
  grants (`sekai.namespace-snapshot/v1`). Signatures prove identity only;
  imports stay non-authoritative replicas. Ungranted, stale, tampered,
  revoked, hidden, or residency-conflicting peer data fails closed. SQLite is
  the reference store; PostgreSQL remains explicitly unavailable.
- Execute one approved checkpointed fact migration from an ancestor definition
  revision onto the published head. Dry-run plans without mutation; execute
  strips removed properties and rebinds objects; blocked transforms leave
  facts unchanged; rollback restores snapshots and fails closed unless the
  stored parent and candidate match. Unknown, stale, or unapproved breaking
  changes fail closed. Live object-security and property grants are rechecked
  at effect; hidden objects are omitted and ungranted properties are not
  stripped. Audit and object lineage share the mutation transaction.
  Published definition revisions stay immutable.
- Deny property access without an explicit grant on activated object-security
  policies. Optional `property_grants` omit hidden values from authorized
  reads, context, export, lineage, and sync projections; ungranted filters and
  writes fail closed. Existing policies that omit the field keep v1 visibility.
- Quarantine source batches that conflict with an admitted type identity or
  immutable source revision. The plane stores a `QUARANTINED` denial with
  per-record reasons, does not mutate objects or advance the checkpoint, and
  returns that exact result on replay. Additive property refreshes still
  commit; malformed reserved properties and invalid checkpoints fail closed
  before mutation.
- Classify two authorized definition revisions as compatible, conditional,
  breaking, or unknown with bounded member and property reasons. Added optional
  types and properties are compatible; new actions, controls, and marking
  changes are conditional; removed members or properties and newly required
  properties are breaking. Unknown constructs and unauthorized revisions fail
  closed. Fact migration remains a separate contract.
- Compare two authorized definition revisions and report deterministic added,
  removed, and changed types, properties, links, actions, and controls without
  returning definition bodies. Unknown constructs and unauthorized revisions
  fail closed.
- Record governed branch proposals as ADR 0026: a change set is a digest-bound
  proposal that compare-and-swaps one namespace published head. Live approval
  is rechecked at merge; signatures, discovery, and package identity are not
  grants. ADR 0024 remains the branch/revision foundation.
- Apply activated `sekai.object-security-policy/v1` rules to writes, traversal,
  linked-object reads, lineage, synchronization, object-bound leases, and
  authority-bound `ListObjects` cursors. Read rules do not grant mutation;
  updates compare the authorized snapshot inside the persist transaction.
- Merge of a governed definition proposal requires the expected published
  digest, compare-and-swaps that pointer, and returns a durable `receipt_id`
  stored on the merged proposal. Exact replay returns the same receipt without
  moving the head again. A candidate that does not descend from the pinned
  base is denied as not mergeable. Close records a canonical reason
  (`operator_abort`, `superseded`, or `policy_denied`) without moving the
  published head.
- Publish or reject one governed definition proposal. A proposal pins exact
  published-base and branch-head digests, frozen evaluation-plan references,
  and named foreign digests; merge compare-and-swaps the namespace published
  head only with a live approval and matching member identity. Stale
  candidates, missing approvals, and foreign digests fail before the head
  moves; exact replay and closed proposals preserve history.
- Add immutable `sekai.object-security-policy/v1` revisions, atomic namespace
  activation, administrative gRPC inspection/mutation, and SQLite/PostgreSQL
  storage-predicate enforcement for direct object reads and `ListObjects`.
  Existing inactive namespaces keep prior ACL and marking semantics.
- Add a separate bounded native content contract for ordered text, image,
  audio, and document descriptors. Content plans preserve the existing text
  RPCs, authorize disclosure through Chisei policy, verify transient payload
  bounds and digests before provider contact, and fail unsupported modalities
  without text coercion.
- Governed Action types can bind one admitted object kind and apply one
  create or update on `SubmitActionInstance`, sharing the caller `request_id`
  and optional `ontology_digest` receipt spine. Domain kinds stay in schemas
  and fixtures, not the core contract.
- `external_mutate` is `pending` when an admitted ActionInstance carries
  `permit_id`, and stays `skipped` without a permit.
- Bounded GitHub object sync onto shared type revisions, with refresh,
  tombstone, and identity-conflict rules.
- Add `sekai.source-batch/v2` generation-fenced snapshot and ordered-feed
  delivery. Terminal snapshots bind a stable source epoch and consistency
  barrier; change batches advance only contiguous offset ranges atomically with
  objects, audit, lineage, results, and the checkpoint. Exact replay is
  idempotent, reordered or overlapping ranges abort, and missing ranges require
  a next-generation recovery snapshot.
- Preserve exact `sekai.source-batch/v1` replay and add one-way additive SQLite
  and PostgreSQL generation/offset migrations. Sources without authoritative
  epoch, sequence, and snapshot/feed handoff support remain explicitly
  unsupported; snapshot absence never implies deletion.
- Dataset-backed object lineage from source record to write-back effect.
- Log successful gRPC request completions at DEBUG instead of INFO so default
  operator logs stay quiet under poll traffic. Non-ok completions remain WARN.
  Metrics are unchanged.

## 1.0.1

- Hosted and community Chisei use one operator-supplied process key per
  provider (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `XAI_API_KEY`) for every
  caller. An enterprise tenant row still wins when present;
  `CredentialNotFound` falls back to the instance key instead of failing
  closed.
- Persist an optional credential-free artifact manifest from `AckActionWork`
  onto the bound operation receipt.
- Keep `runtime_dispatch` receipts open until `AckActionWork` and skip
  replay writes on already-complete receipts.
- Record a not-applicable routing event on governed action-instance receipts so
  exported completeness no longer lists `routing` as missing or uncovered.
- Require namespace and object schemas when authoring action types, and add
  `sekaictl` put/get/list for governed action types.
- Update `h2` to `0.4.16` to close `RUSTSEC-2026-0258` (unbounded empty DATA
  frames).

## 1.0.0

### Stable contract

- Freeze the ontology-first SQLite product loop, principal-scoped credentials,
  `sekaictl`, receipts, and core gRPC capability inventory as the 1.x contract.
- Return only core capabilities from unfiltered discovery. Callers must request
  `all`, `advanced`, or `experimental` to opt into broader catalogs.
- Keep PostgreSQL as a partial community backend with explicit runtime
  capability discovery and fail-closed unsupported paths.
- Integrate Gunshi as the outer fleet-allocation stage for native execution.
  `PlanExecution` can bind an exact issued allocation before its existing
  Kioku enrichment and records the allocation provenance in the plan and
  operation receipt without adding an RPC endpoint.

### Removed

- Remove the pre-1.0 graph Action mutation DSL, its type registry, approval
  queue, execution RPCs, persistence, CLI, and examples. Governed Action Types,
  Action Instances, effects, work, and ActionPolicy remain the v1 contract.
- Remove the server-side `SEKAI_AUTH_TOKEN` root bootstrap. Clients use
  `SEKAI_CREDENTIAL` with a durable principal-scoped credential.
- Remove the unused capability-package and trust vertical: seven package
  lifecycle/trust RPCs, package persistence, and package migrations are gone.
- Remove the experimental scenario-overlay vertical: `EvaluateScenario`, its
  request/response types, capability catalog entry, and in-memory evaluator.
- Remove the experimental text/hybrid retrieval vertical: `SearchText`,
  `HybridRetrieve`, their candidate/fusion wire types, and SQLite FTS index
  maintenance. Core retrieval remains `RetrieveContext`.
- Remove the experimental pattern-plan vertical: `ExecutePatternPlan`,
  `ExplainPatternPlan`, their IR wire types, and the standalone plan module.
- Remove the experimental temporal-history vertical: three historical query
  RPCs, temporal assertion wire types, storage/migration code, and graph
  mutation hooks. Current graph state, audit, and lineage remain supported.
- Remove the experimental assurance-export pair: `VerifyAuditLedger` and
  `ExportAssurance`. Internal ledger and attestation verification remain
  available to retention, provenance, and administrative tooling.
- Remove the advanced evidence-driven ontology-proposal vertical: four proposal
  RPCs, proposal persistence/migrations, and the standalone review workflow.
  Ontology classes and relations remain directly authorable through the core
  authenticated mutation APIs.
- Remove the advanced object-set vertical: four saved-filter RPCs, object-set
  persistence in SQLite/PostgreSQL, graph backend methods, and retention cleanup.
  Callers use the core inline object-list filters instead.
- Remove 21 unserved or non-essential Sekai RPCs, including the public semantic
  resolver, governed-fact/waiver writers, graph function/action authoring,
  runtime-pressure and parked-resolution facades, reservation/coordination
  snapshots, and evidence lifecycle/content facades. The orphaned runtime
  pressure storage/migration/fixture vertical is gone too; claim, lease, park,
  and evidence primitives remain where active execution depends on them. Drop
  the now-unreferenced tenant, coordination-snapshot, function-result, and
  ontology-violation wire messages as well.
- Remove the unserved `LlmService` and message-only `llm.proto` package.
  Provider execution uses internal request types inside governed Chisei and
  gateway flows.
- Remove `ListPipelineRuns`, which never persisted or returned pipeline runs.
  Native planning state is observed through execution plans and operation
  receipts.
- Remove the eight experimental `Evolve*` RPCs and their dedicated enhancement
  storage. Evolution remains an internal learning primitive for capability
  promotion instead of a second public analytics API.
- Remove secondary Chisei RPCs for namespace worker policy, portfolio
  authoring/allocation, model affinity, evidence-gate inspection, and legacy
  eval authoring/listing/analytics. These signals remain internal to routing,
  execution, evaluation, and gateway enforcement.
- Remove the standalone `RunPipeline` RPC and the optional
  `CHISEI_GATEWAY_RUN_PIPELINE` mode. Native callers use `PlanExecution`; the
  gateway receives its sampling decision through the canonical governed
  preflight.
- Collapse the external-action lifecycle from 10 RPCs to four:
  `AuthorizeExternalAction` returns a permit when immediately allowed,
  `TransitionExternalAction` owns approval/cancellation/revocation/delegation,
  `RedeemExternalActionPermit` consumes authority, and
  `SetExternalActionPolicy` owns policy and kill-switch changes.
- Collapse Gunshi from 11 RPCs to three. Recommendation issuance now returns
  aligned auto-dispatch decisions, policy and feedback mutations share
  `SetGunshiAllocationPolicy`, and status includes the advisory scorecard.
- Collapse gateway coordination from five RPCs to three. One
  `ClaimGatewayDispatch` atomically reserves and claims an alias, while
  canonical receipts persist through trusted `RecordUsage` accounting and
  generic audit events use Sekai decisions. The final public Chisei contract
  contains 30 RPCs (133 total with Sekai's 103). The four bounded eval/sample
  read projections retained for active Tenkai and Aldunis consumers are not a
  return of the removed eval authoring or analytics verticals.
- Remove the public unary `ExecutePlan` alias; native execution is streaming-only
  through `ExecutePlanStream`.
- Remove evaluation read/analytics facades, the plan-backed governed-subject
  facade, `CheckBudget`, standalone `ResolvePolicy`, and
  `QueryOperationStatistics`. Gateway admission is owned by
  `DecideGatewayExecution`; historical policy dry-run remains an operator-console
  projection rather than a public RPC.
- Remove the guarded object-mutation RPC aliases. Use `CreateObject`,
  `UpdateObject`, and `DeleteObject` with optional `lease_precondition`.
- Remove public interface-registry CRUD and schema-to-ontology projection RPCs.
  Use ontology-first authoring; the interface registry remains an internal
  schema-validation substrate.
- Remove legacy gateway usage-recovery configuration names, status aliases,
  and provider-registry initialization override.
- Remove the cross-repository Homebrew tap publication job.

### Compatibility

- Restore the authenticated `CreateActionType` compatibility RPC for clients
  that still execute the legacy graph mutation DSL. It preserves the existing
  `ActionTypeDef` registry and does not map graph actions into governed action
  types; new integrations should use `PutGovernedActionType`.

### Migration

Version 1.0 is a clean break from pre-1.0 releases. There is no in-place public
API, configuration, or state compatibility promise. Export any data that must
be retained, deploy a fresh 1.0 database, create principal credentials through
`sekaictl admin access credential create`, and update clients to the 1.0 proto
and environment names before importing supported domain data.

## 0.2.1

### Security

- Enforce namespace authorization for egress checks, model affinity, and
  request-selected evolution analytics and writes.
- Restrict global evolution reports, patterns, variance, A/B results,
  templates, and unscoped enhancement to control-plane administrators.
- Bound OpenAI-compatible, Anthropic, and buffered gateway responses to
  32 MiB before parsing or continued accumulation.

## 0.2.0

### Migration

Deprecated expert commands have moved under `sekaictl admin`. The old
top-level aliases have been removed:

| Removed command | Replacement |
| --- | --- |
| `sekaictl credential` | `sekaictl admin access credential` |
| `sekaictl team` | `sekaictl admin access team` |
| `sekaictl gateway` | `sekaictl admin gateway` |
| `sekaictl action` | `sekaictl admin governance action` |
| `sekaictl memory` | `sekaictl admin governance memory` |
| `sekaictl gunshi` | `sekaictl admin governance gunshi` |
| `sekaictl governed-subject` | `sekaictl admin governance subject` |
| `sekaictl attest` | `sekaictl admin assurance attest` |
| `sekaictl compliance` | `sekaictl admin assurance compliance` |
| `sekaictl provenance` | `sekaictl admin assurance provenance` |
| `sekaictl replay` | `sekaictl admin assurance replay` |
| `sekaictl federation` | `sekaictl admin federation` |

Invoking a removed path exits with a migration message naming its canonical
replacement. Command handlers, server authorization, protocols, and persisted
state are unchanged.
