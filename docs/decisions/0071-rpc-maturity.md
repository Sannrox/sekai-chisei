# ADR 0071: Classify public RPCs by backend and consumer evidence

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: source Issue [#871](https://github.com/Sannrox/sekai-chisei/issues/871)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/871 (#871)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0019](0019-dual-capability-catalogs.md), [ADR 0058](0058-model-platform-certification.md), [ADR 0059](0059-autonomous-envelopes.md)

## Context

The public surface is 129 Sekai and 32 Chisei RPCs. Operators cannot tell which
RPCs are runnable against real backends. Capability `product_tier` describes
catalog packs; it does not mark wire maturity or gate invocation.

## Decision

Every public RPC is classified `stable`, `experimental`, or `remove` from
backend and consumer evidence. The table in [rpc-maturity.md](../rpc-maturity.md)
is a projection, not a second authority.

- `stable` requires a real (non-fixture) backend. The default public loop and
  its required siblings stay at most 68 RPCs (see Amendments).
- `experimental` RPCs keep their wire contract, authorization, and receipts.
  Invocation requires `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs`
  Cargo feature. Both are off by default.
- `remove` is a deprecation classification only. Deletion is a later
  major-version change set. Removal of an RPC that later has an external
  consumer needs a Design Discussion first.
- `DiscoverCapabilities` reports `sekai.rpc.experimental` on the core pack.
  Visibility is not a grant.
- Stable SDK generation omits experimental and remove backing RPCs without a
  denylist.

Fixture-only paths are not reachable in the default build.

## Alternatives considered

- Use `product_tier` as maturity. Rejected: that redefines dual-backend and
  catalog-pack claims.
- Delete experimental RPCs in this change set. Rejected: the Issue keeps
  removal for a later major version and preserves wire contracts that still
  have real backends.

## Consequences

Default servers reject experimental and remove RPCs with
`FAILED_PRECONDITION`. Operators who need those paths enable the flag.
Security review and SDK generation shrink to the stable set.

## Validation

A deterministic test compares the checked-in table and `docs/rpc-maturity.md`
with both proto services, classifies every RPC exactly once, and proves the
default gate cannot reach an experimental RPC. Real backend cells must match
the shrink-only SQLite-only list.

## Amendments

- 2026-09-21, Issue [#1090](https://github.com/Sannrox/sekai-chisei/issues/1090):
  the stable ceiling moves from 60 to 63. `PutEvaluationPlan`,
  `ResolveEvaluationPlan`, and `ExecuteEvaluationManifest` become `stable`
  because `sekaictl admin evaluation plan` is a real consumer that publishes,
  resolves, executes, and compares receipted evaluations. The ceiling is a
  ratchet, not a target: it rises only in the change that adds a consumer
  proof for each promoted RPC and only by the number promoted, so a stable RPC
  still needs a real backend plus a consumer or a required-sibling reason.
  `CancelEvaluationExecution` and `GetGovernedFactVersion` stay `experimental`:
  no default verb cancels, and `validate` reads exact invariant versions
  through `GetGovernedFactVersion` only without `--offline`, while `apply`
  remains the authoritative publication check.
- 2026-09-23, Issue [#1087](https://github.com/Sannrox/sekai-chisei/issues/1087):
  the stable ceiling moves from 63 to 66. `RetrieveContext`,
  `ExpandRelations`, and `ExplainDerivation` become `stable` because
  `sekaictl ontology context`, `expand`, and `explain` are real consumers
  on the product-loop fixtures, and the generated TypeScript and Python
  HTTP facades carry the three methods. Availability was backend-scoped
  here (entailment SQLite-only); since #1320 entailment runs on community
  PostgreSQL too. Authorization, namespace, and object security are
  rechecked on every call, and computed properties stay query-time overlays.
- 2026-10-08, Issue [#1316](https://github.com/Sannrox/sekai-chisei/issues/1316):
  the Real backend column is a projection of RuntimeDb fail-closed evidence and
  the shrink-only list `tests/fixtures/sqlite_only_surfaces/v1.json`. `stable`
  may be `yes` or `sqlite only`; `fixture only` cannot. PostgreSQL conformance
  runs on every pull request.
- 2026-10-09, Issue [#1314](https://github.com/Sannrox/sekai-chisei/issues/1314):
  the stable ceiling moves from 66 to 68. `DecideActionInstance` and
  `ListActionInstances` become `stable` because community PostgreSQL now
  grants or denies a parked instance with the same named-approver rules as
  SQLite, `ListActionInstances.status` is the parked inbox, and
  `native_server_smoke` plus the generated HTTP facades consume both RPCs.
- 2026-10-28, Issue [#1912](https://github.com/Sannrox/sekai-chisei/issues/1912):
  the stable ceiling is removed. The stable surface is not capped; promoting
  an RPC edits only its entry in `tests/fixtures/rpc_maturity/v1.json`. A
  stable RPC still needs a real backend plus a consumer or a required-sibling
  reason, and the table still fails by name on a missing, unknown, or
  duplicate RPC.
- 2026-11-07, Issue [#2095](https://github.com/Sannrox/sekai-chisei/issues/2095):
  `CreateDefinitionBranch`, `ApplyDefinitionBranchEdit`,
  `CompareDefinitionRevisions`, `ReportDefinitionConsumerImpact`, and
  `CreateDefinitionProposal` become `stable` because the MCP adapter
  (`sekai.definitions.branch.create`, `.edit`, `.diff`, `.impact`,
  `.proposal.create`), `tests/mcp_definition_branch.rs`, and
  `examples/shikigami-definition-branch/` consume them on the default build.
  Approve and merge stay `experimental` and off MCP. The HTTP/JSON projection
  and generated stable SDKs pick the five up as unary stables.
- 2026-11-10, Issue [#2243](https://github.com/Sannrox/sekai-chisei/issues/2243):
  `Search` and `GetSearchIndexStatus` become `stable` after meeting the #2089
  promotion criteria: a fenced scheduled index worker (#2250), a query-bound
  page cursor (#2251), and bounded query cost with PostgreSQL RPC tests
  (#2252). The MCP adapter (`sekai.search.query`) consumes `Search`;
  `GetSearchIndexStatus` is its required sibling for index lag. The HTTP/JSON
  projection and generated stable SDKs pick both up as unary stables.
- 2026-11-11, Issue [#2266](https://github.com/Sannrox/sekai-chisei/issues/2266):
  the seven governed-document RPCs (`AdmitGovernedDocument`,
  `AttachGovernedDocumentRendition`, `GetGovernedDocument`,
  `HoldGovernedDocument`, `ReleaseGovernedDocumentHold`,
  `ExpireGovernedDocument`, `DeleteGovernedDocument`) become `stable` after
  meeting the #2089 promotion criteria: namespace authorization (#2248), the
  namespace classification lattice and an admission input (#2245), a
  rendition input without server-set fields, and RPC-level tests on SQLite
  and PostgreSQL (#2266). `native_server_smoke` consumes all seven on the
  spawned binary, as for `DecideActionInstance` (#1314). The HTTP/JSON
  projection and generated stable SDKs pick them up as unary stables.
- 2026-11-14, Issue [#2282](https://github.com/Sannrox/sekai-chisei/issues/2282):
  `RegisterObjectTypeDatasource`, `ReindexObjectType`,
  `GetObjectTypeIndexStatus`, and `PutObjectTypeIndexEdit` become `stable`
  after meeting the #2089 promotion criteria: namespace and credential-admin
  authorization, typed `PropertyValue` cells on index edits (#2283), and
  RPC-level tests on SQLite and PostgreSQL. Request and response names stay
  as frozen: `PutObjectTypeIndexEditRequest.properties` is
  `map<string, PropertyValue>`; `PutObjectTypeIndexEditResponse` is empty
  and callers read status; `RegisterObjectTypeDatasourceRequest.idempotency_key`
  remains on the wire for growth through `..Default::default()`.
  `native_server_smoke` consumes all four on the spawned binary. They are
  required siblings of `EvaluateObjectSet` once objects derive from datasets.
  The HTTP/JSON projection and generated stable SDKs pick them up as unary
  stables.
- 2026-11-17, Issue [#2415](https://github.com/Sannrox/sekai-chisei/issues/2415):
  `ListDatasets`, `ListDatasetVersions`, `GetDatasetVersion`,
  `RollbackDataset`, `PutDatasetHealthCheck`, `ListDatasetHealthChecks`,
  `ListDatasetHealthResults`, `RunDatasetHealthChecks`, and
  `ListDatasetAlerts` become `stable` after meeting the #2089 promotion
  criteria: list calls and version rows page (#2532), health runs judge on
  the server clock (#2533), tenant and column authorization run before the
  limit (#2099), and RPC-level tests run on SQLite and PostgreSQL. Messages
  were reviewed once before the freeze and stay as they are:
  `RollbackDatasetResponse.rows` and `RunDatasetHealthChecksRequest.now_ms`
  stay on the wire as deprecated fields, and health check `kind` stays a
  string (`freshness`, `row_count`). A rollback of a dataset that a
  registered, non-edits-only object type datasource reads is refused with
  `FAILED_PRECONDITION` naming the index, so derived objects never sit on
  rows the dataset no longer holds. `native_server_smoke` consumes all nine
  on the spawned binary. The HTTP/JSON projection and generated stable SDKs
  pick them up as unary stables.
- 2026-11-17, Issue [#2416](https://github.com/Sannrox/sekai-chisei/issues/2416):
  `GetLineage` becomes `stable` after meeting the #2089 promotion criteria.
  The caller's visibility and purpose checks run inside the walk, so a node
  the caller may not read takes no slot of `max_nodes`, is not walked past,
  and cannot set `truncated` (#2542). A dataset-backed object reaches its
  dataset, the transforms that write it and their inputs, and the source
  that lands it, as ephemeral nodes under the same checks (#2543). The walk
  is capped at 500 nodes (default 200) and is shared by SQLite and
  PostgreSQL; RPC-level tests run on both. Messages were reviewed once
  before the freeze and stay as they are: `max_nodes` stays `int32`, with 0
  or a negative value meaning the default, and ephemeral nodes reuse
  `LineageNode.object` with `id`, `kind`, `namespace` and `external_id`.
  `native_server_smoke` consumes it on the spawned binary. The HTTP/JSON
  projection and generated stable SDKs pick it up as a unary stable.
- 2026-11-19, Issue [#3266](https://github.com/Sannrox/sekai-chisei/issues/3266):
  `AcquireLease`, `GetLease`, `RefreshLease`, `ReleaseLease`, and
  `TakeoverExpiredLease` become `stable` after meeting the #2089 promotion
  criteria. Every call checks namespace tenant context and team namespace,
  and object-bound keys (`object:<id>`) need object read or write (ADR
  0005). Lease state, retry results, and audit commit together, a stale
  generation can neither refresh, release, nor take over, and a crashed
  owner's lease is taken over at the next generation. Inputs are bounded
  the same way on both backends: text fields at most 512 bytes and `ttl_ms`
  at most 24 hours. RPC-level tests run on SQLite and PostgreSQL. Messages
  were reviewed once before the freeze and stay as they are: `Lease.status`
  stays a string (`active`, `released`). `native_server_smoke` consumes all
  five on a spawned default plane, ahead of the external runner adapter
  (#2182). The HTTP/JSON projection and generated stable SDKs pick them up
  as unary stables.
- 2026-11-23, Issue [#3036](https://github.com/Sannrox/sekai-chisei/issues/3036):
  `PutActionBinding` and `RunActionBinding` become `stable`, with the new
  `GetActionBinding` and `ListActionBindings` reads, after meeting the #2089
  promotion criteria. Every call checks tenant context; install needs
  namespace administration, and run and read need the binding's `run_as`
  principal or a namespace administrator, filtered before the page is cut.
  A run persists its page before any submit and derives idempotency keys
  from events, so a crash resumes without double submits. Lists page at most
  100 bindings and a run reads a bounded page. RPC-level tests run on SQLite
  and PostgreSQL through the typed `sekai-client` methods on a plane with
  experimental RPCs off. Messages stay as they are: a binding travels as
  `sekai.action-binding/v1` JSON.
