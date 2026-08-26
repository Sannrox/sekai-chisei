# Changelog

## Unreleased

- Export and import bounded signed namespace snapshots under explicit peer
  grants (`sekai.namespace-snapshot/v1`). Signatures prove identity only;
  imports stay non-authoritative replicas. Ungranted, stale, tampered,
  revoked, hidden, or residency-conflicting peer data fails closed. SQLite is
  the reference store; PostgreSQL remains explicitly unavailable.
- Execute one approved checkpointed fact migration from an ancestor definition
  revision onto the published head. Dry-run plans without mutation; execute
  strips removed properties and rebinds objects; blocked transforms leave
  facts unchanged; rollback restores snapshots. Unknown, stale, or unapproved
  breaking changes fail closed. Published definition revisions stay immutable.
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
