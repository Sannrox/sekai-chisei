# Changelog

## Unreleased

- The guarded isolation probe runner executes declarative probe specs
  (`sekai.probe-spec/v1`): a read-only object-scoped RPC, the principal to
  call as and the expected denial, with no endpoint, credential, tenant or
  object of their own. `sekaictl admin assurance probes run --specs <dir>`
  validates them before any call; a spec not denied as expected is a
  finding with the spec as reproduction, and `tests/fixtures/probe_specs/`
  runs promoted specs in the regression suite (docs/isolation-probes.md,
  #1680).

- Experimental fence bindings (ADR 0121): `PutFenceBinding` binds Ezu
  geofence events (enter, exit, inside, dwell) for one collection to a
  pinned governed Action type run as a service principal, and
  `RunFenceBinding` submits one Action per bound event from a bounded page
  after the binding's durable cursor. Submits are idempotent by Ezu event
  id, approval policies park them, every event keeps a receipt with its id,
  and `sekai_fence_binding_lag_ms` reports lag. Configure `SEKAI_EZU_URL`
  and `EZU_TOKEN` (#1564).

- Experimental signed definition packages: `ExportDefinitionPackage` signs a
  published revision as a namespace-independent `sekai.definition-package/v1`
  envelope, and `ImportDefinitionPackage` verifies it against the plane's
  trusted package keys and opens a proposal holding exactly its members, with
  `source_package_digest` recorded. Import never merges; tampered,
  unverified, or incompatible packages are refused by name and write nothing
  (docs/definition-branches.md, #1700).

- Experimental live policy shadow: `StartPolicyShadow` evaluates a candidate
  namespace route policy beside the active one on every live resolution,
  without changing the decision. `GetPolicyShadowReport` shows the match
  rate and bounded samples of differing decisions, and `SetNamespacePolicy`
  refuses the shadowed candidate until the report passes. Start and stop
  are recorded as decisions (docs/policy-dry-run.md,
  `0090_chisei_policy_shadow`, GATE:mig, #1630).

- Experimental `GetOntologyChangelog` lists what changed in a reader's
  namespaces over a window: each published definition revision with a
  plain-language summary, compatibility, author, approvers, publisher and
  affected registered consumers, and policy activations. A credential admin
  can build a team's weekly digest, authorized as that team alone; a
  namespace the reader cannot read contributes nothing
  (docs/ontology-changelog.md, #1471).

- A consumer can mark its definition consumer binding `blocking`.
  Publishing a revision that breaks a valid blocking binding then fails and
  names it, unless the proposal is an approved major revision
  (`major_revision`). Blocking bindings are disclosed to producers in
  impact reports; advisory bindings keep the ADR 0067 non-disclosure
  (ADR 0067 amended, #1635).

- Experimental transform replays (ADR 0120): `ReplayGovernedTransform`
  re-runs a governed transform, as stored or as a candidate definition,
  over input dataset versions pinned by id or by time, on a fresh branch of
  its output. The record pins inputs, definition and engine, flags
  non-deterministic SQL, diffs the result against a baseline output version
  by key and names the datasets and object types downstream. Promote it by
  merging the branch, discard it by deleting it. `GetTransformReplay`
  returns the record (#1585).

- Experimental comment threads on objects and their properties, with
  mentions, resolve and reopen. A comment is visible only to callers who
  can read its object and property, quoted values of hidden properties are
  redacted, and mentioning a principal without read access is refused.
  Every write is in the audited object change log, which is the edit
  history and the receipt (docs/object-comments.md, #1442).

- Experimental trust scores: a versioned per-namespace scoring rule turns
  source health, age against expected freshness, manual verification and
  corroborating or contradicting links into a 0 to 100 score per object
  with its reasons. `ScoreObjectTrust` scores an object-set page as the
  caller and filters or sorts by score. Rule changes are credential-admin,
  compare-and-set and audited in the object change log
  (docs/trust-scores.md, #1456).

- `QueryCounterfactualView` shows what a namespace's objects would have
  shown at a past time under candidate object security policies or a
  candidate marking rule, per principal: visible then, visible under the
  candidate, hidden and revealed. The object set is rebuilt from the
  recorded change log; objects deleted since, rules changed since and times
  before the retained history fail closed. Credential-admin, read-only,
  recorded as a decision, and behind
  `SEKAI_EXPERIMENTAL_RPCS` (#1453).

- Experimental gRPC for dataset branches (ADR 0119): create, list, delete,
  compare, propose a merge, merge, and run a governed transform on a branch.
  The tenant comes from the authenticated context, reads need dataset read
  access and changes need write access, and a merge is refused for the
  proposer (#1444).

- Experimental `ExpandNeighborhood` and `FindPaths` explore how objects are
  linked: a bounded expansion from seed objects with a total count, and all
  shortest paths between two objects up to depth 4. Every hop applies the
  caller's read policy, including the marking join along the path. Hidden
  objects are omitted, never counted, and never used as a step; a hidden
  start object is the same not-found as a missing one
  (docs/graph-exploration.md, #1562).

- A governed transform can run on a dataset branch (ADR 0119). Inputs read
  their branch where it exists and the parent otherwise. The output is
  written only to the output dataset's branch, so the parent's rows,
  checkpoint and marking stay as they were. A run that would raise the
  output marking, or that targets another tenant's branch, is refused; an
  isolated-process transform cannot run on a branch yet (#1444).

- Datasets have branches (ADR 0119): a branch is one working copy forked from
  a version, and until its first write it reads that version, so creating one
  copies nothing. Branch writes never touch the parent. Compare reports
  columns, row counts and a row digest against the parent. A merge goes
  through a proposal that pins both heads, is merged by another principal,
  and writes exactly one new version with a receipt id; a replay writes
  nothing. Deleting a branch frees its rows, and retention keeps any version
  an open branch forks from (`0088_dataset_branches`, GATE:mig, #1444).

- `sekaictl admin assurance probes run` checks an allow-listed deployment's
  object reads for isolation (unauthenticated and cross-tenant) as two
  synthetic tenants. The
  target guard fails closed on an endpoint off `SEKAI_PROBE_TARGET_ALLOWLIST`
  or a tenant that is not synthetic. Every attempt is appended to a ledger,
  `probes summary` reports the week from it, and a bypass writes a private
  advisory draft with reproduction steps instead of any public report
  (`docs/isolation-probes.md`, #1621).

- The game reference workload is a synthetic tenant domain (`GameWorkload`):
  its kinds and links come from the pinned `hoshi-ontology/v1` package
  (players own planets, fleets are stationed at planets, players ally), and
  it runs through the same `generate` and `apply` as every domain, with
  seeded markings, principals and governed fleet orders (#1616).

- Relational change capture beyond PostgreSQL has one contract (ADR 0118):
  per-family positions (LSN, GTID set, SCN) with a comparison rule, snapshot
  handoff, committed records with optional transaction markers, schema
  change classes mapped onto drift handling, and a distinct retention-loss
  state. `sekai-source-sdk` 1.3.0 adds `assert_change_capture` and per-family
  fixtures; the conformance digest covers them (#1578).

- The certification gate lists each agent member's bound tools with the
  derived effect and whether it blocks publish, and `DiscoverCapabilities`
  returns `tool_effect` on Action entries. Effects now use the enabled versions
  of an Action type (#1646).

- Agent definitions can bind tools (`action`, `query` or `gateway`), each
  with an optional approval policy. Effects are derived from the governed
  Action type, and unknown Actions and gateway tools count as destructive.
  Merge and the certification gate refuse a mutating or destructive tool
  without a policy (`agent_tool_approval_required:<tool>`). Definitions
  without tools keep their digests (#1644).

- Agent promotion refuses a regressed candidate: binding a certification
  records the run's mean case score, and a candidate scoring more than
  `SEKAI_AGENT_PROMOTION_MAX_REGRESSION_PERCENT` (default 20) below the
  published revision's certification on the same suite is refused with
  `agent_promotion_eval_regression` at the gate and at merge. Unscored rows
  keep the pass/fail gate (`0087_agent_certification_score`, GATE:mig, #1640).

- Identity assertion replay state keeps each nonce only until its assertion's
  expiry plus clock skew, so a caller that mints one assertion per request no
  longer grows the core's memory with total traffic. Replay protection inside
  the live window is unchanged (#1638).

- Embedding index for object properties: an embedding spec names an object
  kind, source properties, chunking and dimension. Catch-up follows the
  object-change feed and re-embeds only changed chunks; a spec or model
  version change is a recorded rebuild. Vectors carry model, version, source
  digest, the object's marking and each source property's classification. An
  external route refuses properties the egress policy keeps in the
  deployment. Writes are fenced per spec (ADR 0117, `0086_embedding_index`, GATE:mig,
  #1581).

- Isolated-process streaming workers can apply a batch of Action-written
  object edits together with an input checkpoint in one transaction.
  Replay of the same `(run_id, checkpoint)` returns the original receipt.
  An older claim generation is fenced. Action policy Deny and
  RequireApproval fail closed. `ApplyStreamingTransformBatch` stays behind
  `SEKAI_EXPERIMENTAL_RPCS` (`0085_streaming_transform_apply`, GATE:mig,
  #1583).

- Grant and deny on parked Actions store structured decision memory. A later
  similar Action of the same type surfaces those precedents on
  `GetActionInstance`, omitting decisions the caller cannot read and labelling
  superseded rows (`0084_decision_memory`, #1465).

- MCP lists definition-branch tools so an agent can create a branch, edit it,
  diff, report impact, and open a proposal. Approve and merge stay off MCP.
  The creating agent principal cannot approve or merge, including when it
  holds changed-member admin. Backing RPCs stay behind
  `SEKAI_EXPERIMENTAL_RPCS` (#1311).

- Agents start propose-only. After enough unchanged approvals and no
  incidents, an admin can grant auto-apply for that Action type against a
  live bounded envelope. Matching submits skip review; other types still
  park. A rejected Action, a dead envelope, or a model pin change revokes
  the grant. Grant and revoke write Decision receipts
  (`sekaictl admin autonomy offer|grant-auto-apply|revoke-auto-apply`,
  #1469).

- Parked Actions can route to a review queue on the type: SLA, assignee pool,
  threshold, and auto-deny or reassign escalation. `DecideActionInstance`
  refuses a reviewer who is not the assignee. The approval receipt names the
  queue, reviewer, and reason (#1455).

- Invoice extraction function revisions are scored on a labelled fixture
  set before publish. A worse vendor extraction is denied; an unchanged
  revision still publishes (#1327).

- Operators can freeze writes or agent Actions by tenant, namespace, principal,
  or Action type. The next object write and Action admission fail closed with
  the freeze reason. In-flight claims fail at ack. Freeze and unfreeze write
  Decision receipts. `SetWriteFreeze` / `ListWriteFreezes` stay behind
  `SEKAI_EXPERIMENTAL_RPCS` (`0083_write_freeze`, GATE:mig, #1458).

- `DiscoverCapabilities` lists enabled governed Action types as
  `sekai.actions.{type_id}` on the core pack, with parameter schema,
  selected `action_version`, description, approval matching submit
  admission, and visible markings from the bound object kind.
  Catalog-bound `SubmitActionInstance` rechecks the live catalog and fails
  closed after revoke. Hidden types, restricted properties, and markings stay
  off the catalog. The response carries `ontology_revision` (ADR 0116, #1459).

- New grants can require a purpose and an end date when a namespace opts in.
  Permanent grants need an explicit exception. Expired grants stop authorizing.
  Create and renew write Decision receipts (#1462).

- Action, transform-run, and agent-turn receipts join a per-namespace
  Ed25519-signed hash chain when `CHISEI_RECEIPT_CHAIN_SIGNING_KEY` is set.
  Genesis and periodic checkpoints detect truncation. `sekaictl admin
  assurance receipts export|verify` checks a bundle offline and names the
  first bad position when `--trusted-key` matches the operator key.
  Isolated-process `TransformRun` JSON verifies with the same tool.
  Dataset field redaction rewrites chained transform-run bodies and re-signs
  the namespace (`0081_receipt_chain`, GATE:mig, ADR 0114, #1449).

- gRPC GetObject, ListObjects, ApplySourceBatch, and object-change reads run
  store work on `spawn_blocking`, bounded by the connection pool, so a slow
  batch does not pin a Tokio worker (#1439).

- ApplySourceBatch authorizes a page with one namespace-scoped external-id
  lookup and one active object-policy load per kind, instead of a lookup
  pair per record (#1438).

- Object-path gRPC workloads (GetObject, ListObjects, EvaluateObjectSet,
  Action apply, policy-checked reads, ApplySourceBatch) are measured at 10⁴/10⁵
  objects on SQLite and PostgreSQL. Scheduled runs start TLS PostgreSQL, fail
  a missed published budget or a >20% p95 regression, and reject a matrix that
  dropped every postgres workload. Pull requests run a wide-budget SQLite smoke
  subset (#1437).

- Object-log dual-read maps min, max, and avg against the tagged object-log
  when reconstructed hop measures agree with the mikura fixture, including
  zero-hop whole-set aggregates. `group_by`, distinct, multi-key sort, and
  min/max whose checked average overflows stay named refusals: SQL still
  requires one group key and falls back to the source key when it is absent,
  counts only numeric distinct values, sorts on one `order_by`, and does not
  share the object-log's checked `(sum, n)` overflow. The plane aggregation
  contract is unchanged. The mikura pin remains `0d43c57` (#1540).

- Object-log identity is `(namespace, kind, key)`. Ingest, generation reads,
  dual-read, and the host client pass the plane namespace. `MIKURAV1` logs
  fail closed until an explicit projection-driven migration. The mikura pin
  is `0d43c57` (#1552, ADR 0112).

- Enterprise-scoped sessions can publish a governed transform definition with
  namespace write and read access to its datasets. A scoped Put cannot name a
  schedule or input-commit trigger. Community Put still requires credential
  administration. Run stays unadmitted for scoped sessions (#1557).

- A space can be shared across tenants when both the owning tenant and the
  member's home tenant approve. The owning tenant names the namespaces, kinds,
  and marking ceiling the space exposes. Members act under their own home
  tenant; storage keys stay per tenant. One-sided approval grants nothing.
  Withdrawal applies to the next request. Only exposed namespaces, kinds, and
  markings are visible; history hides values written while the object was
  above the ceiling and redacts old values when no retained prior write
  attests their original marking. Every cross-tenant access through the space is
  audited (`tenant.shared_space_access`) with the owning resource tenant
  even when membership is denied. Unshared spaces are unchanged
  (`GATE:break`, #1434).

- Isolated transform claims persist a per-run tenant concurrency hold and
  release it once on write, cancel, reclaim, or terminal lease failure
  (`0074_transform_quota_hold`, GATE:mig). The submitting tenant is stored on
  the work row (`0075_transform_work_tenant`, GATE:mig) so a runner without
  tenant context still admits and records usage against that owner. Put
  records the submitting tenant as the quota owner
  (`0076_transform_quota_owner`, GATE:mig) so scheduled and triggered
  isolated enqueue copies that owner onto the work row. In-process
  scheduled and triggered ticks admit and record usage against that owner
  before the run; quota exhaustion skips the slot without advancing the
  schedule cursor. RunGovernedTransform uses that Put owner when the caller
  has no tenant context, so an admin or runner still meters the submitting
  tenant. Isolated claims bind that owner onto empty work even when no
  quota limits are configured. CLI `admin transform run` admits and records
  in-process Put-owner quota the same way.   PostgreSQL discovers persisted
  tenant quota limits for that admission instead of skipping the gate,
  including `GetEffectivePolicySummary` limit projection.
  Quota-denied claims return to the queue even if admission outlasted the
  lease, so a deny does not consume lease expiries. PostgreSQL records
  measured request usage onto `chisei_usage_events`
  (`0077_chisei_usage_events`, GATE:mig) so isolated write-back and
  in-process runs are metered on that runtime too.   Combined Split
  admits and records that usage on the Chisei dest, not the Sekai
  plane that omits budget and usage tables.   Claim and list work
  include that submitting `tenant_id` so a runner can key quotas on
  the owner instead of the namespace. CLI `admin transform run` admits
  and records usage on the Chisei dest in a Combined Split layout.
  PostgreSQL persist of a claim hold locks the work namespace and
  rechecks the live fence so a concurrent cancel cannot leave reserved
  concurrency on cancelled work.   The runtime-claim client exposes
  `transform_quota_tenant_id` so a JobSource keys quotas on that owner
  instead of the namespace.   A fenced write-back that already completed
  records usage on retry instead of returning a lost fence, so a
  failed usage persist after commit can still meter that run once.
  That retry still requires the completing owner, generation, and
  token, including after the completing lease expires. Binding a
  claim tenant requires the current generation and token, so an
  expired first claimant cannot stamp a different owner after a
  later claim. In-process scheduled and triggered commits persist a
  pending usage row (`0078_transform_usage_pending`, GATE:mig) so a
  later tick can meter that run if usage persist failed after the
  run and cursor committed. That pending row stores the original
  completion time so a retry after a period boundary still meters
  the earlier period.   Isolated write-back records the same original
  completion time on retry. An untargeted claim that is quota-denied
  skips that run and continues through later work in the same
  namespace so another tenant's eligible run is not stuck behind
  exhausted work. A Sekai-only plane that omits budget and usage
  tables skips admission and usage instead of failing after the run
  is already durable. PostgreSQL missing-table errors keep the relation
  name so a Sekai-only plane is not treated as Internal. Usage persist
  failures after commit leave the pending row for a later tick instead
  of failing the caller.
  Isolated write-back, cancel, lease-fail, and reclaim restore a taken
  concurrency hold if releasing that reservation fails, so a quota-store
  error after commit does not leave the tenant permanently exhausted.
  Claim-time hold inserts still require CLAIMED work so a delayed insert
  cannot land after cancel. Releasing a reserved concurrency unit reports
  a storage error instead of swallowing it, so the restored hold can retry.
  An in-process run that cannot release concurrency persists a hold without
  work, and Tick retries restored holds on missing or terminal work so the
  tenant is not left exhausted.   An untargeted claim that skips quota-denied
  work defers that run so a later claim can reach another tenant.
  Quota holds are keyed by run and claim generation so restoring an
  older reservation cannot overwrite a live claimant's hold. Tick
  releases only a retryable generation after rechecking current work
  status, so an older restored hold cannot drain a live claimant's
  reservation. Reclaim and older-hold deletes take one generation at
  a time so multiple outstanding holds do not fail PostgreSQL or drop
  extra reservations. A replacement claim copies request-admission onto
  the new generation in the same transaction, so Tick releasing an older
  concurrency hold cannot make that run pay a second request. Abandoning
  an unused admission reports a storage error and persists a retryable
  hold for only the metrics that still need refunding, so a quota-store
  failure cannot leave the tenant permanently exhausted or double-refund
  a metric that already committed.

- `PutDefinitionCertification` copies suite identity and pass/fail from a
  stored eval run, refuses a bind by authors of agent-member changes since
  the published base, treats revocation as one-way, and caps expiry at 90
  days from bind time. A later unrelated edit cannot restore the author's
  ability to self-certify or to clear `revoked_at_ms` (#1513).

- Dataset writes snapshot a retained version id. `ListDatasetVersions` and
  `GetDatasetVersion` read a prior snapshot by id or timestamp; `RollbackDataset`
  restores that snapshot as a new audited version and marks consuming transform
  outputs stale. Retention `0` keeps every version; a positive limit purges
  older snapshots. Additive experimental RPCs and PostgreSQL migration
  `0073_dataset_versions` (`GATE:mig`, #1412). Enable `SEKAI_EXPERIMENTAL_RPCS=1`
  or the `experimental-rpcs` feature to invoke.

- Dataset health checks run after each committed write and on a schedule.
  Freshness, row-count, schema, null/uniqueness, and predicate checks store
  results with the judged version. A failing blocking check quarantines the
  new version so `QueryRows` stays on the last healthy snapshot. Late
  schedules emit one alert and recovery emits a resolve; check and job
  metrics carry tenant and space labels. Additive experimental RPCs and
  PostgreSQL migration `0079_dataset_health_checks` (`GATE:mig`, #1411).
  Enable `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` feature to
  invoke.

- Experimental `ProposeDefinitionRollback` opens an append-only proposal whose
  candidate restores a prior published revision as a new descendant of the live
  head. Merge records `restored_from_digest` on the receipt and refuses when
  the rollback would drop object or dataset properties still present unless a
  migration plan digest is pinned (#1390). Additive experimental RPC and JSON
  fields; no PostgreSQL migration.

- Governed images, renditions, and annotations, and registered Iceberg/Parquet
  open-table projections persist on community PostgreSQL with the same owner
  CAS, parent, tombstone, and snapshot-digest behavior as SQLite (#1479).
  `admin.governed-image` and `admin.open-table` leave the shrink-only
  SQLite-only list. Adds PostgreSQL migration
  `0072_governed_images_and_open_tables` (`GATE:mig`, #1479).

- Capability-package certifications persist on community PostgreSQL with the
  same certify, replay, supersede, and revoke behavior as SQLite (#1478).
  `admin.capability-package` leaves the shrink-only SQLite-only list. Adds
  PostgreSQL migration `0071_capability_packages` (`GATE:mig`, #1478).

- Versioned client packages persist on community PostgreSQL with the same
  publish, replay, live-identity, and supersede behavior as SQLite (#1477).
  `admin.client-package` leaves the shrink-only SQLite-only list. Adds
  PostgreSQL migration `0070_client_packages` (`GATE:mig`, #1477).

- Signed namespace snapshot export/import, peer namespace grants, and imported
  assertion provenance persist on community PostgreSQL with the same sequence,
  upsert, and list behavior as SQLite (#1476). `admin.federation-snapshot`
  leaves the shrink-only SQLite-only list. Adds PostgreSQL migration
  `0069_federation_snapshots_and_provenance` (`GATE:mig`, #1476).

- Federation network contracts, site/peer profile tables, governed conflicts,
  and revocations persist on community PostgreSQL with the same install, CAS,
  and list behavior as SQLite (#1475). `admin.federation-network` leaves the
  shrink-only SQLite-only list. Namespace snapshots, grants, and peer-import
  provenance stay SQLite-only until #1476. Adds PostgreSQL migration
  `0068_federation_network_and_profile` (`GATE:mig`, #1475).

- Gunshi allocation state (`IssueGunshiRecommendations`,
  `SetGunshiAllocationPolicy`, `GetGunshiAllocationStatus`) persists on
  community PostgreSQL with the same CAS install/update behavior as SQLite
  (#1474). The three RPCs leave the shrink-only SQLite-only list. Adds
  PostgreSQL migration `0067_chisei_gunshi_allocation_state` (`GATE:mig`, #1474).

- Service tokens are held to their live service-principal registration:
  requests outside the namespace allowlist, `SubmitActionInstance` and
  `ClaimActionWork` outside the registered Action types, and objects above the
  profile `classification_ceiling` are refused. Runtime tokens from a claim
  made with a service token stay within the same scope; removing the
  registration revokes both. Other callers are unaffected (#1511).

- Experimental `IssueServicePrincipalToken` exchanges client credentials for a
  short-lived tenant-bound service token through an identity-extension issuance
  hook (#1510). The plane reuses the #1507 assertion signing key; the
  authentication boundary admits the token as the registered service principal
  (a machine identity, never a user). Refused without an extension, for an
  unregistered principal, for invalid credentials, or once expired. Additive
  experimental RPC; no existing field changes.

- Concurrent Chisei SQLite opens serialize lookup-index backfill with
  `BEGIN IMMEDIATE`, skip it after `PRAGMA user_version` is set, and create the
  unique lookup index with `IF NOT EXISTS`, so a second opener no longer fails
  with `index already exists` (#1394).

- Property `order_by` on object lists extracts the sort value once per matching
  row (SQLite `MATERIALIZED` CTE, PostgreSQL `LATERAL` with `OFFSET 0`) instead
  of repeating JSON extraction in every `ORDER BY` term (#1374).

- The shrink-only SQLite-only list now includes `ListObjectChanges` and
  `SubmitEvidence`. Community PostgreSQL answers `UNAVAILABLE` for object-change
  listing and execution-evidence admission before that work, instead of
  `INTERNAL` after a partial write. Handler evidence methods are an explicit
  table so a renamed RuntimeDb helper cannot hide a SQLite-only RPC (#1373).

- Experimental `PutServicePrincipal`, `GetServicePrincipal` and
  `DeleteServicePrincipal` register a worker as a service principal with
  allowed Action types and a namespace allowlist, owned by the caller's
  authenticated tenant. The marking ceiling is read from the principal
  profile's `classification_ceiling`. No secret is stored; issuance and
  enforcement follow separately. Adds PostgreSQL migration
  `0066_service_principals` (`GATE:mig`, #1508).

- Experimental `ListPublishedDefinitionRevisions` returns a namespace's published
  definition merge history newest first, with optional member-change filter and
  keyset pagination. Auth matches `GetPublishedDefinitionRevision`. Adds
  PostgreSQL migration `0065_definition_proposal_merged_history` (`GATE:mig`,
  #1354).

- `ClaimActionWork` returns a short-lived runtime token bound to the claiming
  principal, tenant, namespace, effect, runtime and claim generation when an
  assertion signing key is configured and the caller has a tenant;
  `HeartbeatActionClaim` refreshes it. The token authenticates only the
  heartbeat, ack and claim-event calls for that claim and expires no later
  than the claim. New response fields are additive; workers without a token
  keep using their credential. Claim RPCs now accept tenant-scoped
  credentials under the usual namespace and tenant checks (#1507).

- Merging a definition proposal that changes an agent-definition member
  requires a current, non-revoked, baseline-passing certification bound to
  the candidate revision (ADR 0079). Missing, stale, failed, or revoked
  evidence is `failed_precondition`. Direct publish of an agent member is
  still refused. Experimental `PutDefinitionCertification` and
  `GetDefinitionCertificationGate` bind and report that gate. Adds PostgreSQL
  migration `0064_agent_definition_certification` (`GATE:mig`, #1353).

- Opt-in customer-hosted routes can require current Tenkai-signed runtime
  evidence (`tenkai.model_runtime_evidence.v1`) before admission. Chisei
  verifies signatures against installed trust roots, ledgers which evidence
  admitted a route, signs `chisei.model_evaluation_evidence.v1` from pinned
  `EvalStore::compare_runs` results, and stores operator feedback. Default
  routes stay unchanged. Adds ADR 0107, `sekaictl admin model-release-evidence`,
  experimental RPCs, and PostgreSQL migration
  `0063_chisei_model_release_evidence` (`GATE:mig`, #1396).

- Registered customer-hosted routing profiles carry an optional
  `artifact_digest` (`PutRoutingProfileRequest` and `RoutingProfile` field),
  stored on SQLite and PostgreSQL and passed to
  `EnterpriseExtension::admit_model`, so digest-pinned admission works for
  registered routes. Adds PostgreSQL migration
  `0062_routing_profile_artifact_digest` (#1499).

- Channel operators can persist per-namespace model review state and family
  enablement keyed by the #1352 identity and `ResidencyPolicy` region labels.
  Missing state is `disallowed`; a per-model row overrides its provider family
  in the same namespace; a named namespace (model, then family) overrides the
  instance default. Admin RPCs and
  `sekaictl admin model-review` set, revoke, and list with a decision-ledger
  reason. Operators run a one-shot backfill to mark currently routed hosted
  families and registry-canonical policy models `enabled` when still
  `disallowed`. Adds ADR 0106 and PostgreSQL migration
  `0061_chisei_model_review` (#1493).

- Route admission default-denies any model that is not `enabled` for the
  namespace, #1352 identity, and `ResidencyPolicy` region: native planning
  and execution, gateway decide, customer-hosted routes, and gateway
  failover candidates returned with an admitted decide. Refusals use a
  stable reason (`model_review.not_enabled` or
  `model_review.residency_mismatch`) and a decision-ledger row. Unused
  fallbacks are dropped without a ledger row. Backfilled routes keep
  working (#1494).

- Governed transforms stream claim reads inside a byte bound, persist
  optional dataset `partition_keys`, and write named partitions atomically.
  `sekai-client::claim` exposes the partition selector and `max_bytes`.
  Partitioned datasets use `sha256-partitions-v1:` (not folded into
  `sha256-sum-v1:`). Incremental in-process projection appends into changed
  partitions so historical output row IDs stay stable. Adds ADR 0105 and
  PostgreSQL migration `0060_partitioned_transform_io` (`GATE:mig`, #1388).

- Sensitive egress reuses compiled entity literals from a per-namespace
  object-change generation instead of listing the graph on every cache hit.
  SQLite and PostgreSQL advance that generation in the same transaction as
  every object write (create, update, delete, namespace move, sync apply,
  definition-migration rewrites). Adds ADR 0104 and PostgreSQL migration
  `0059_namespace_object_generation` (#1492).

- Governed transforms accept an optional schedule and change trigger. The
  plane admits one run per schedule tick across restarts, runs downstream
  once after an upstream commit or `ApplySourceBatch`, refuses dependency
  cycles at Put, and records the trigger cause on the receipt. Output
  freshness is `fresh`, `stale`, or `blocked`. Cancelling a run skips
  not-yet-started downstream work. Per-namespace concurrency bounds
  isolated admission. Adds `sekai.transforms.scheduler`, experimental tick,
  output-state, and cancel RPCs, ADR 0103, and PostgreSQL migration
  `0058_transform_schedule` (#1387).

- The privacy entity scan lists at most 501 objects in one query that
  excludes `leak_rule` in SQL, instead of paging up to 1000 objects and
  filtering in Rust, and fingerprints the set with a streaming digest
  instead of formatting, sorting, and joining strings (#1491).

- `sekai-client` publishes a versioned runtime-claim module
  (`sekai.sdk-runtime-claim/v1`) so Action and isolated-process transform
  workers share list, claim, heartbeat, ack, claim-event, streamed input
  read, and fenced write-back helpers. Typed errors keep fence loss distinct
  from idle, contention, denial, and unavailability (#1389).

- Isolated-process governed transforms admit claimable work instead of
  computing in-process. A worker claims with a fencing token, streams the
  admitted JobSpec snapshot, and writes the output, receipt, and lineage in
  one transaction. Write-back keeps the admitted destination after a later
  Put. A stale fence or digest mismatch commits nothing. Claim RPCs require
  credential admin. Adds `sekai.transforms.isolated_process`, experimental
  claim RPCs, ADR 0102, and PostgreSQL migration `0057_isolated_transform_work`
  (#1386).

- Enterprise extensions can admit or refuse the resolved model of a provider
  execution before its credential lookup and provider call:
  `EnterpriseExtension::admit_model` receives a `ModelIdentity` (provider,
  model, profile version, pinned `artifact_digest`, and the endpoint the
  provider client uses) and defaults to admit. Provider profiles and hosted
  endpoints gain an optional `artifact_digest`. With an extension installed,
  any `resolve_provider_credential` error, `CredentialNotFound` included,
  now refuses execution instead of falling back to the process key; an
  extension that wants the instance key returns it explicitly (#1352).

- `CreateFunction` refuses a function with an LLM step. The gated publish
  records an approval for the revision digest and stores it; `InvokeFunction`
  and document extraction refuse an LLM revision without that approval, so
  rows stored before this change stay unapproved. Adds PostgreSQL migration
  `0056_function_gate_approvals` (#1384).

- Governed-document hold, release, expire, and delete check and write the
  record in one transaction on SQLite and PostgreSQL, so a concurrent delete
  or expire can no longer drop a hold reported as placed. Delete drops the
  renditions in the same transaction, and a rendition no longer attaches to
  a deleted document (#1381).

- The egress entity scan no longer truncates at 500 literals. Every name and
  external id of the up to 500 scanned objects is checked, so namespaces with
  more than about 250 named objects stop refusing all `Sensitive` egress to
  non-safe providers. A truncated scan (more than 500 objects) now refuses
  with `privacy_scan_truncated: ...` and the `EgressDecision` reason
  `privacy_scan_truncated`, distinct from a leak match. See
  `docs/egress-privacy-scan.md` (#1372).

- Function document extraction resolves the namespace action policy for every
  extraction: `deny` refuses, `require_approval` parks the Action at any
  confidence, and `allow` writes only at or above the threshold. A direct
  write also runs the caller's CreateObject authorization, which
  `FunctionDocumentExtractRequest.authorize_write` now requires (#1382).

- Connector certifications persist on PostgreSQL with the SQLite certify, get,
  verify, revoke, and supersession semantics. Adds PostgreSQL migration
  `0055_connector_certifications` (#1481).

- Source-webhook key pins and registered source-type descriptors persist on
  PostgreSQL, and PostgreSQL `ApplySourceBatch` admits batches for live
  registered descriptors. Register, inspect, and retire descriptor RPCs and
  `sekaictl admin sync pin-webhook-key` now work on both backends. Adds
  PostgreSQL migration `0054_source_registry` (#1322).

- `sekaictl admin connectors new <name> --out <dir>` generates a source
  connector from `crates/sekai-connector-template`: check, discover, and read
  stubs, a fake source, gRPC transport, outbox commit per batch, and a config
  that references credentials by environment variable. CI builds a generated
  connector and runs its conformance tests. `sekai-source-sdk` 1.2.0 adds
  `build_registered_source_batch` for registered descriptors (#1409).

- Source adapters gain `check` (connectivity, zero records) and `discover`
  (kinds, columns, key candidates, optional profile hints). Discovery drafts
  a source-type descriptor; catalog admission stays a separate review.
  Reference GitHub and warehouse adapters implement both (#1408).

- Source adapters depend on the versioned `sekai-source-sdk` crate for the
  batch builder, outbox, snapshot and change-feed runners, and conformance
  kit. A breaking public-API change without a major bump fails CI. Connector
  certification records the SDK version and conformance-suite digest (#1407).

- The identity contract distinguishes the acting tenant from a guest's home
  tenant (`AuthenticatedContext.home_tenant`). Guest contexts are denied
  unless an installed extension's `authorize_guest_namespace` admits the
  namespace and action (default deny); they reach only the namespace object
  RPCs and never approve. Every guest decision is audited with both tenants.
  Extensions must set the new field (`GATE:break`, #1432).
- `authorize_guest_namespace` returns the host tenant's `GuestGrant`: a
  role and a marking ceiling. Guests get only that role and never see or
  write objects the ceiling does not cover, whatever their home authority.
  An activated namespace lattice evaluates the ceiling with dominance;
  otherwise the evidence ordinal. Ceiling denials are audited. Grants are
  asked for on every request, so revocation applies to the next one.
  Extensions implementing the hook must return the grant (`GATE:break`,
  #1433).

- Administrator-approved discovery rules name which tenants, principals,
  spaces, and namespaces another tenant may find. Without a rule,
  cross-tenant list and lookup look missing. A rule never grants read or
  write. Rule changes apply on the next request. Every decision is audited
  as `tenant.discovery`. Extensions implementing `authorize_discovery` must
  return the current rule (`GATE:break`, #1435).

- Derived transform outputs inherit the union of input object and row
  `access_marking` values. Unknown input markings fail closed with no output
  write. Marked runs require a bound output dataset object. Receipts record
  `markings_in` and `markings_out`. Lowering or removing a marking on object
  update requires a principal profile `declassify_markings` grant; owner,
  admin, and trusted service principals do not bypass it. Trusted principals
  may still declassify when that grant is on their sealed profile. Every
  declassify decision is audited (`GATE:mig`, #1403).
- Optional `deny_unmarked` hides unmarked objects unless the caller is a
  trusted service or holds an explicit object ACL grant. Default stays
  fail-open. Enable with namespace property `deny_unmarked=true` or
  `SEKAI_DENY_UNMARKED=1`. `sekaictl admin access unmarked list|apply`
  reports unmarked objects per namespace and can write a default marking
  (`GATE:mig`, #1399).
- Policy understands a discover permission below read. Discoverer space
  roles and human `sekai.discover` list and describe namespaces, object
  types, and datasets (filtered by marking ceiling and object policy) and
  are refused for object reads, queries, aggregates, and counts. Credential
  scopes apply with or without an installed enterprise extension (#1405).
- An LLM function may bind a governed document `extracted_text` rendition.
  Caller-held text must match the pinned digest. Produced objects inherit
  the document classification and carry `derived_from` lineage to a
  namespaced document stub. Confidence below
  `LlmStep.minimum_confidence_micros` parks a `require_approval` Action
  instead of writing the object. Scores and thresholds above 1_000_000 fail
  closed. `LlmStep` gains additive field 5 for the threshold (#1326).
  The parked Action type must create the extracted kind. Granting it writes
  the same object, classification and `derived_from` lineage included,
  after re-checking the lineage against the live document and rendition
  (#1383).
- LLM function revisions are a governed evaluation subject. A fixture set is
  invoked, each output is retained as evidence at the union of input markings,
  and the existing `stochastic_model/v1` rubric scores it. A score below the
  manifest threshold denies publish (`#1312`).
- Restore pre-#1368 `PipelineStep` wire fields 1–9 for operator clients.
  Operator responses include matching legacy and structured representations;
  conflicting inputs are rejected. Structured operator/LLM variants now use
  fields 10/11. Regenerate clients built from the unreleased #1368 protocol
  before upgrading; its incompatible fields 1/2 are not supported (#1371).

- Governed documents and renditions persist on community PostgreSQL with the
  same owner, purpose, classification, and hold rules as SQLite. Experimental
  RPCs admit, attach a rendition, get, hold, release hold, expire, and delete
  (`SEKAI_EXPERIMENTAL_RPCS=1`). The plane still stores no bytes (#1325).
- `DecideActionInstance` and `ListActionInstances` are stable. Community
  PostgreSQL grants or denies a parked instance with the same named-approver
  rules as SQLite; `ListActionInstances.status` is the parked inbox. The
  stable ceiling moves from 66 to 68 ([ADR 0071](docs/decisions/0071-rpc-maturity.md),
  #1314).
- Experimental function pipelines are a `oneof` of operator steps and `LlmStep`
  (prompt revision, input bindings, JSON Schema output, pinned model route).
  Invoke records prompt, input, and output digests on the receipt and fail-closes
  schema-invalid structured output with no fallback route (#1310).
- Public RPC Real backend is a projection of RuntimeDb fail-closed evidence and
  the shrink-only list `tests/fixtures/sqlite_only_surfaces/v1.json`. CI fails
  on a mislabeled row, a new SQLite-only RPC missing from the list, or list
  growth. PostgreSQL conformance runs on every pull request (#1316).
- Versioned evidence and finding package (`pkg:feedback.evidence-finding/v1`) registers Observation, Finding, Investigation result, Hypothesis, External issue reference, and Verification record types plus governed Actions, an evidence schema, and an evaluation member. Hypotheses cannot be verification subjects. Invalid, stale, conflicting, or unauthorized evidence is rejected without creating observation objects (ADR 0095, #1230).
- Combined, both planes, `sekaictl launch`, and single-store `sekaictl` commands refuse `DB_PATH`, `DATABASE_URL`, and `SEKAI_SHARED_STORE` with guidance toward `SEKAI_DATA_DIR`, dest-pair paths/URLs, and `sekaictl admin store relocate`. The server image sets `SEKAI_DATA_DIR=/data` (#1239).
- Combined dest-pair evaluation apply/resolve reads governed invariants from the Sekai store. `sekaictl admin learning` opens the dest pair (or `SEKAI_DATA_DIR`) and writes change records to the Chisei dest (#1239).
- Compliance export, `sekaictl report quality`, and `sekaictl report substitution` refuse Combined Split instead of a Sekai-only bundle and name the gRPC report RPCs (#1264).
- Combined Split records Chisei `RecordDecision` rows on the Sekai dest so `verify_ledger` covers them; relocate leaves that table with Sekai (ADR 0083, #1265).
- Unattested Split with Chisei families still in the Sekai dest refuses restamp and names `sekaictl admin store relocate` (#1263).
- `deploy/tenkai.toml` sets Combined dest-pair `SEKAI_DB_PATH`/`CHISEI_DB_PATH` on `/data` and pins product/image `1.1.0`, matching crate version and compose (#1268).
- Workflow-step admission takes a caller `BudgetTracker` over the Chisei store, or defers when the caller has none, instead of wrapping the Sekai runtime as Chisei state (#1270).
- Chisei persistence goes through per-family store traits. `src/chisei` no longer calls `ChiseiStore::runtime()`, and that method is crate-private. `sekaictl admin quality` opens the dest pair (or `SEKAI_DATA_DIR`) so evaluate/restart can read dataset facts from Sekai (#1237).
- Pipeline implement and evaluable checks reuse the same per-request type cache as property filtering, so context assembly does not re-list schema types per object (#1262).
- Governed transforms are a Sekai in-process class on both community backends: put a JobSpec, run a `projection`, inspect the run receipt. `sekaictl admin transform` and Console `/transforms` are the operator path. RPCs stay experimental (ADR 0097, #1287).

## 1.3.0

Upgrade notes:

- Enterprise identity extensions require a tenant on every authenticated context. Bind or replace tenantless service and gateway credentials before upgrade. Community installs without an extension keep existing credential behavior (#1418).
- Identity extension implementers must advertise `sekai.identity-extension/v2` and populate space, space role, and `act`. Older extension versions fail closed. Protocol field numbers are unchanged ([ADR 0099](docs/decisions/0099-shared-identity-and-tenancy.md), #1415, #1417).
- Delegated apply re-checks the retained `act` principal. Disabled, removed, or under-privileged delegators refuse with `delegator_disabled`, `delegator_not_member`, or `delegator_grant_missing`. Missing planning receipt, action effect, or action instance also refuses apply (#1419, #1423).
- Claim of `runtime_dispatch` work re-checks the same `act` facts before the worker receives a fence, so a disabled or removed delegator cannot reach the side effect. The refused item is failed so later claimable work is not stuck behind it. Community mode treats a principal with no credential rows as disabled. The runtime-claim client surfaces `delegator_*` instead of contention or fence loss (#1421).
- Delegated calls use the service subject, or the intersection of service and human row, property, ACL, and marking authority when `act` is present (#1422).
- Indexed `EvaluateObjectSet` authorizes the live object and fails closed on authorization outages (#1422).
- No store schema migration. A binary or image rollback to 1.2.1 restores prior identity behavior.

## 1.2.1

Upgrade notes:

- Store relocation initializes external-action reservations, authorizations, releases, and blast-radius claims on the Chisei destination. Relocate with this tag's `sekaictl` when those tables already exist (#1414).
- The Git tag, GitHub release, `sekai` archives, and GHCR image are `v1.2.1`. Crate metadata, `compatibility.json`, and `deploy/tenkai.toml` on this tag still report `1.2.0`.

## 1.2.0

Upgrade notes:

- Combined, both planes, `sekaictl launch`, and single-store `sekaictl` commands refuse `DB_PATH`, `DATABASE_URL`, and `SEKAI_SHARED_STORE`. Unset them and use `SEKAI_DATA_DIR` (default `./data`) or destination-pair settings.
- The server image sets `SEKAI_DATA_DIR=/data` instead of `DB_PATH=/data/sekai.db`; relocate an existing single store before upgrading.
- `chisei-plane` refuses remote-only namespace policy resolution during boot and RPC handling (#1291).
- Observation `external_id` is deduplicated by a unique index; existing duplicates refuse startup (#1330).
- The `sekai-domain` and `sekai-obs` crate split changes `obs::logging::init()` to require a default service name (#1306).
- The `remote_sekai` module moved without a protocol change (#1315).
- Governed-transform digest encoding changed; incremental runs require a full rebuild after upgrade (#1307, #1346).
- Both planes require `SEKAI_ENDPOINT`; unattached paths were removed (#1343).
- Policy and execution paths fail closed when namespace policy cannot load, including Gunshi (#1349).
- Hosted transform catalog discovery is experimental and gated through `DiscoverCapabilities` (#1350).

## 1.1.0

Upgrade notes:

- Community SQLite and PostgreSQL apply schema `0029`–`0049` on startup. Backup the store before the first 1.1.0 boot.
- SQL `object_type_index*` is a rebuildable serving projection; object identity is the configured object-log (ADR 0091). Existing tables are retained; rematerialize with `ReindexObjectType`.
- MCP `sekai.links.get` and `sekai.links.create` require every referenced object's namespace to match session `x-sekai-namespace`.
- Combined pins mikura `v0.2.0`. Existing `v0.1.0` object logs still open.
- Provider HTTP clients no longer follow redirects.
- Optional `SEKAI_OBJECT_LOG_HOST` is exclusive with `SEKAI_OBJECT_LOG`.

- TypeScript and Python SDK trees pack (`npm pack`, `pip wheel`) and install from those bytes into a consumer with no in-repo path. Clerk `sdk-packages` records stay digest pins, not the install source (#1093).
- MCP `sekai.links.get` and `sekai.links.create` require every referenced object's namespace to match the session `x-sekai-namespace`. Object ACL on a foreign-namespace id is not enough (#1203).
- Object identity stays in the configured object-log. Action apply writes the clerk receipt and log ingest only, and does not write SQL `object_type_index*`. Those tables remain a rebuildable serving projection for `EvaluateObjectSet` (ADR 0091, #944).
- Warehouse table ingest moves visible row cells into `SourceRecord` properties and drops hidden columns, instead of cloning every cell into an intermediate map (#1209).
- MCP `tools/call` fail-closes missing `operation_id` and reserved metadata on borrowed arguments before cloning or discovering the catalog, and reuses a session `CatalogSnapshot` until `catalog_version` changes (#1208).
- The object-log host client is resolved from the environment once per process. Later admits reuse that client instead of re-reading `SEKAI_OBJECT_LOG_HOST` and re-resolving DNS. The pinned host still serves one JSON line per connection, so each wire op opens its own TCP stream (#1207).
- Hosted-pinned `PlanExecution` reuses the planning catalog for the pin check instead of listing namespace profiles a second time. Execute still re-lists on admit (#1206).
- The capability catalog MCP allowlist is pinned to `rpc_maturity`: `ResolveEvaluationPlan` and `ExecuteEvaluationManifest` stay listed because they are `stable`, and the catalog must not call those RPCs experimental (#1205).
- `CreateLink` assigns a server id when the request id is empty and answers with the stored row. MCP `sekai.links.create` no longer persists an empty primary key or reports a later request as stored (#1201).
- The MCP projection host also lists `chisei.evaluation.resolve` → `ResolveEvaluationPlan` and `chisei.evaluation.execute` → `ExecuteEvaluationManifest`, now that both RPCs are stable. Each binds its request namespace to the session and refuses a foreign namespace. Evaluation compare stays CLI-only because it has no wire RPC (#1093).
- The object-log dual-read canary no longer opens a local `SEKAI_OBJECT_LOG` when `SEKAI_OBJECT_LOG_HOST` is set. Sampled dual-read evaluates fail closed with a message naming both settings, matching the admit path's exclusivity (#1202).
- The MCP projection host (`sekai-mcp` stdio and HTTP `POST /mcp`) now lists `sekai.links.get` → `GetLinks` and `sekai.links.create` → `CreateLink`, because both RPCs are stable. Link creation passes only the endpoints and relation (the server assigns the id), and forged metadata, missing fields, or non-string values fail closed. Registry-published packages remain open in #1093 (#1093).
- Clerk processes can share one mikura object-log host (ADR 0088). `SEKAI_OBJECT_LOG_HOST`, exclusive with a local `SEKAI_OBJECT_LOG`, routes object-log admits and generation reads through `mikura-host`'s wire contract. A non-loopback host requires `SEKAI_OBJECT_LOG_HOST_BEARER`, and host or wire failures fail the ingest closed with no local fallback (#1196).
- Reusable source writeback adapter (`adapters/source_writeback.rs`) that writes a change back to a source system of record through the governed Action path: permit, `SubmitActionInstance`, `external_mutate` effect, conditional source write, execution evidence, and receipt. The warehouse table implementation completes the source → object → Action → source loop; the next ingested snapshot shows the change (#1085).
- New warehouse table ingest profile (`adapters/warehouse_table_ingest.rs`) that hydrates typed objects from a committed table snapshot through a connector outside the plane. It uses registered-source `ApplySourceBatch` batches with the snapshot id as the checkpoint. Restricted columns never leave the connector. Declared schema drift is refused until the new revision is registered, and undeclared drift is quarantined without clobbering the last consistent objects. SQLite-only, like source-type descriptors (#1085).
- Hardened customer-hosted routing:
  - A hosted-shaped model id (`hosted.<name>/…`) is classified as hosted without consulting any registry. When it doesn't resolve, it fails closed instead of reading as an unknown provider that generic routing could replace (#1184).
  - Planning reads a namespace's hosted catalog only after the caller passes the namespace access check (#1187), and only when the request can reach a hosted runtime: a hosted pin, model, or runtime, or a policy that allows one (#1185).
  - Execution no longer extends the registry at the RPC boundary. The one live re-admission, which runs after the cached plan is bound and access is checked, is the only catalog read per hosted execution (#1186, #1187).
- Provider HTTP clients no longer follow redirects. An operator-allowlisted
  customer-hosted origin (or any provider endpoint) answering with a redirect
  now fails the call instead of moving the request and its bearer credential
  to another URL, the same rule the gateway client already applied (#1188).
- `ListRoutingProfiles` now reports a customer-hosted profile's `runtime` as `hosted.<name>` and its model patterns as `hosted.<name>/<pattern>`. Those are the keys namespace policy and plans use, so a policy mirrored from the list admits the route. The list previously reported the `openai-compatible` dialect and bare upstream patterns (#1189).
- `PlanContentExecution` and `ExecuteContentPlanStream` now route to
  customer-hosted profiles under the same rules as native execution. Only the
  namespace's profiles are added, the policy must name the runtime, the route
  is re-admitted from live state before contact, and only the referenced
  credential is used (#1183).
- Customer-hosted routing profiles now execute through `PlanExecution` and
  `ExecutePlanStream` (the content-execution RPCs do not route to them yet
  and fail closed). Planning adds only the
  calling namespace's admissible hosted profiles to the provider registry, as
  runtime `hosted.<name>` with models `hosted.<name>/<model>`. A namespace
  routes to one only when its policy names that runtime. Hosted endpoints are
  always external and never fall back to another provider. `ExecutePlanStream`
  re-admits the profile from live state and authenticates only with the
  referenced credential. Receipts record `routing_mode=customer_hosted`
  (#1171).
- Concurrent definition genesis seeds on community PostgreSQL no longer race
  the published-head insert. They serialize on the namespace's head lock:
  seeds of the same genesis all succeed, and a different concurrent seed
  fails as a stale head (`FAILED_PRECONDITION`) instead of an internal error
  (#1174).
- Experimental `PutRoutingProfile` and `RevokeRoutingProfile` let a namespace
  administrator register a customer-hosted, OpenAI-compatible routing profile
  (`hosted:<name>`, mode `customer_hosted`). The endpoint origin must be in the
  operator-owned `SEKAI_ROUTING_ENDPOINT_ALLOWLIST`, and `credential_ref` must
  resolve (`SEKAI_ROUTING_CREDENTIAL_<REF>` on community). Profiles store only
  the reference. `ListRoutingProfiles` shows a hosted profile only to its own
  namespace while its origin stays allowlisted. Hosted execution is a later
  slice, so a pin on a hosted profile still fails closed (#1171).
- Updated `rustls` to 0.23.45 (with `aws-lc-rs` 1.18.1 and `rustls-webpki`
  0.103.15) for RUSTSEC-2026-0285, a TLS 1.3 handshake-boundary flaw. `cargo
  audit` passes again (#1177).
- The object-log dual-read canary projects clerk property grants into mikura
  `v0.2.0`'s multi-deny ACL instead of skipping every grant-narrowed kind. It
  still skips when the evaluate reads an ungranted property or a narrowed kind
  has no schema, rather than comparing against a view wider than the grants
  (#1112).
- Object-log ingest now group-commits concurrent admits: records queued while
  another admit holds the log commit together as one mikura batch with one
  fsync. Each admit still returns only after the commit that covers its
  record, and a failed combined batch retries each record alone (#1127).
- Combined now pins mikura `v0.2.0` (and its `mikura-ingest` crate) instead of
  `v0.1.0`. Object-log ingest, evaluate, and dual-read keep their `v0.1.0`
  semantics through an adapter. Identity lookups use a direct `Store::load`
  instead of scanning the whole kind after each append. Existing `v0.1.0`
  object logs open unchanged (#1111).
- Experimental `ListRoutingProfiles` lists the model routes a namespace may pin
  (`provider:<runtime>`, mode `local` or `proxied`), and
  `PlanExecutionRequest.routing_profile_id` pins one. A pin that is unknown,
  unavailable, or does not serve the planned route fails the plan closed. Each
  planned receipt's route event records the routing profile, mode, and whether
  it was pinned. Customer-hosted profiles follow in #1171 (#1094).
- A namespace can now publish its first definition revision through the public
  surface. `CreateDefinitionBranch` with an empty `parent_revision_digest`
  branches from a deterministic, empty genesis revision, which is seeded while
  the namespace has published nothing else. The first revision then goes
  through the usual proposal, approval, and merge. The spawned-binary product
  loop now evaluates an object set against a revision published this way, on
  SQLite and PostgreSQL (#1152).
- CI now runs every ignored PostgreSQL conformance suite in a
  `PostgreSQL conformance` workflow against an ephemeral TLS-only PostgreSQL
  with a throwaway CA. `scripts/postgres-conformance.sh` runs the same thing
  locally with Docker or Apple `container` (#1153).
- Link admission on community PostgreSQL reads the link id and the tightest
  mapped relation maximum in one statement after taking the shared relation
  lock. An uncapped insert now costs three statements instead of four, and a
  capped one five instead of six. The ADR 0087 locking order is unchanged (#1144).
- SQLite link admission no longer loads every ontology class and relation
  under the write lock for links whose relation no ontology relation maps. An
  indexed lookup on `mapped_relation` answers that first. Mapped relations are
  still checked and bounded as before (ADR 0087, #1143).
- `RunActionBinding` no longer loses a page when it crashes during a binding's
  first pinned read. The pin is stored before the read that creates the
  binding's subscription, together with a marker that no subscription existed.
  The next run rewinds the new subscription to its pin and delivers the page
  again (#1141).
- `PutActionBinding` now refuses a binding that leaves a `required` parameter
  of the bound Action type unmapped (`INVALID_ARGUMENT` naming the parameter).
  Such a binding used to install and then skip every event for good (#1142).
- The RPC maturity ledger marks `DecideActionInstance`, `PutActionBinding`, and
  `RunActionBinding` as `sqlite only`: community PostgreSQL answers
  `UNAVAILABLE` for them before any work. Only RPCs with a real backend on both
  runtimes may be `stable` (#1150).
- `DiscoverCapabilities` now reports `supports_entailment=0` for
  `RetrieveContext`, `ExpandRelations`, and `ExplainDerivation` on community
  PostgreSQL, where those RPCs serve asserted-only reasoning and fail
  entailment closed. The integration contract lists the PostgreSQL surface as
  asserted-only instead of unavailable (#1149).
- Granting a parked Action now commits the object write and the
  parked-to-admitted transition in one SQLite transaction, re-checking the
  target object under the same lock. A crash can no longer leave an object
  write without its grant, a stale target is denied `stale_on_resume` with no
  write, and concurrent grants apply the write once with no compensating
  restore (#1139).
- The integration contract lists Action approval (park and decide) as
  `experimental` through `DecideActionInstance` instead of `unavailable`, and
  the governed Action instance guide tells consumers how to move from the old
  `require_approval` denial to `parked` plus a decision (#1151).
- A principal named in a governed Action type's `approvers` can now decide a
  parked instance with read-only namespace membership. `DecideActionInstance`
  no longer requires namespace Write before checking the approver entitlement,
  matching ADR 0089. The namespace-admin fallback still requires admin
  standing (#1146).
- Learning records, relationship objects, capability authorizations, and team
  namespace bootstrap now take the SQLite write lock before their existence and
  link-bound reads, as the primary link path does. Concurrent writers wait for
  each other instead of failing with `database is locked` (#1148).
- `DecideActionInstance` now binds an approval to the one subject a bearer or
  enterprise credential established. Self-asserted identities from the local
  socket or insecure transport, comma-listed `x-principal` values, and the
  reserved `root` / `local` names can no longer decide, and namespace-admin
  standing is checked for that single subject only (#1140).
- `ExpandRelations`, `ExplainDerivation`, and `RetrieveContext` now apply the
  enterprise tenant gate like object reads: a request without an authenticated
  context fails `UNAUTHENTICATED` when an identity extension is installed, a
  foreign namespace fails `PERMISSION_DENIED`, and retrieval drops objects in
  namespaces the tenant cannot read (#1147).
- Community PostgreSQL no longer fails with `INTERNAL` on audit-decision
  listing, object-change history and feed, evidence submissions, policy
  attestations, object-type index pages, and work-unit heartbeats. Those
  statements bound integers at a narrower width than PostgreSQL inferred.
  Definition branch and proposal writes, and evaluation manifest resolution,
  no longer send NUL-joined advisory-lock keys, which PostgreSQL text rejects.
  Every ignored PostgreSQL conformance suite now passes against an isolated TLS
  server, and a source guard keeps these bind shapes out (#1155).
- The product loop now runs on community PostgreSQL: `sekaictl ontology
  apply`, seed, object reads, `EvaluateObjectSet`, governed Action submit and
  read, `GetOperationReceipt`, and object-security activation with a denied
  read. Audited ontology class and relation writes, namespace-role lookup, and
  credential creation no longer fail closed. gRPC handlers on PostgreSQL no
  longer panic by starting a nested runtime, policy-scoped object listing binds
  its page window with the right integer width, and principal-scoped listing
  hides reserved governance kinds as SQLite does. A spawned-binary conformance
  test runs the loop on both backends (#1086).
- `RetrieveContext`, `ExpandRelations`, and `ExplainDerivation` are now
  `stable` with `sekaictl ontology context`, `expand`, and `explain` as
  consumers, and they join the generated TypeScript and Python HTTP clients.
  Query-time entailment stays SQLite-only: community PostgreSQL fails closed,
  and the integration contract and capability catalog say so. The stable
  ceiling moves from 63 to 66 ([ADR 0071](docs/decisions/0071-rpc-maturity.md), #1087).
- Object-change automation bindings (`sekai.action-binding/v1`, experimental
  `PutActionBinding` / `RunActionBinding`). A namespace administrator binds a
  kind's changes to one pinned governed Action type through a closed parameter
  mapping. Runs read the subscription as the binding's `run_as` principal and
  submit one idempotent Action per event through normal admission, so hidden
  fields never become parameters and `require_approval` parks. Community
  PostgreSQL answers `UNAVAILABLE` (ADR 0090, #1092).
- A `require_approval` Action policy now parks the instance (`status=parked`)
  instead of denying it. The experimental `DecideActionInstance` RPC lets a
  principal named in the type's new `approvers` field (or a namespace admin
  when none are declared) grant or deny it. The submitter can never decide
  their own instance. A grant resumes the same instance against current state
  and fails closed with `stale_on_resume` if the target object changed. The
  decision completes the instance's receipt with an `approval_decided` event.
  SQLite only; community PostgreSQL answers `UNAVAILABLE` (ADR 0089, #1084).
- A relation's maximum cardinality is now enforced when a link is admitted, on
  SQLite and PostgreSQL. Distinct targets per source count toward the bound,
  duplicates count once, and concurrent admissions cannot exceed it. A link
  over the bound fails `FAILED_PRECONDITION` with
  `relation_cardinality_exceeded`. Publishing a relation whose maximum is
  below existing links is refused; existing links are never rewritten. The
  minimum stays advisory (ADR 0087, #1132). **Breaking** for callers that
  relied on over-bound writes.
- Combined Split pools can be sized per plane with
  `SEKAI_POSTGRES_SEKAI_CONNECTIONS` and `SEKAI_POSTGRES_CHISEI_CONNECTIONS`,
  carved out of `SEKAI_POSTGRES_MAX_CONNECTIONS`; sizes over the budget refuse
  to start. Pool checkouts report per plane (`sekai_db_pool_checkout_seconds`,
  `sekai_db_pool_in_use_ratio`, label `plane` = `shared`, `sekai`, `chisei`)
  so a starved plane is measurable against Shared. The default half split is
  unchanged (#1109).
- `sekaictl admin store relocate` runs online. Triggers on the source's
  Chisei tables record writes, families are bulk-copied from a snapshot while
  writers run, and the writer fence is then enforced in the source database
  itself. Only families written during the copy are copied again under the
  fence, so writers are refused for that catch-up rather than the full family
  load. The report adds `recopied` and `fence_window_ms` (#1107).
- A `PlanExecution` can pin one active governed learning with
  `ExecutionInput.learning_pin`. The pin changes context only, requires an
  approved and activated learning whose digest matches, fails closed with one
  non-disclosing error, and is cited on the plan receipt with its
  verification lineage (`ExecutionPlan.learning_references`, additive proto
  fields; [ADR 0085](docs/decisions/0085-governed-learning-changes-context-only.md), #1091).
- `sekaictl admin evaluation plan compare` diffs two finished evaluation
  executions of one namespace from their operation receipts: per-node and
  gate-verdict changes, required-versus-advisory regressions, and exit `8`
  when the candidate regressed. It reads only and never executes. The
  `PutEvaluationPlan`, `ResolveEvaluationPlan`, and `ExecuteEvaluationManifest`
  RPCs are now `stable` with the CLI as consumer and join the HTTP/JSON
  projection; the stable ceiling moves from 60 to 63 ([ADR 0071](docs/decisions/0071-rpc-maturity.md), #1090).
- Fix: the shipped server registered no compiled deterministic evaluator, so
  every deterministic evaluation node executed as `evaluator_unavailable`; the
  production registry (`subject_content_digest_equals.v1`) is now registered
  on the server path (#1090).
- Operator first-success, Docker/compose, and configuration pages name
  Combined dest-pair boot. `cargo run` does not load `.env`; a lone
  `DB_PATH` needs `SEKAI_SHARED_STORE=1`. Offline `sekaictl` report,
  compliance, and federation CLIs stay single-store readers (#1078).
- Operator pages that name experimental or remove-classified RPCs now
  state the `SEKAI_EXPERIMENTAL_RPCS=1` / `experimental-rpcs` gate.
- Align agent instructions, operator docs, and comments with landed
  two-plane bins, dest-pair stores, and experimental RPC gates.
- Admitted Action object apply no longer appends to the tagged mikura object
  log inline: SQL apply is the durable admission receipt's success signal,
  and ingest into the configured `SEKAI_OBJECT_LOG` runs only after that
  receipt, effects, and audit are durable. A pre-receipt failure leaves no
  log identity, so retry cannot double-apply; replay catch-up is best-effort
  and skips a matching property map so the same mutation does not bump
  generation. Denied submits still never write the log. A receipted admission
  can transiently show as absent from the log until catch-up runs; see
  [ADR 0081](docs/decisions/0081-evaluate-reads-mikura-library.md) (#943,
  #1102, #1114).
- Dual-unstamped Split open auto-stamps only empty green-field stores;
  operator facts without cutover stay refused until restamp (#1043).
- Split pairing epoch advances on both stores at mutating admit so a
  same-generation one-sided restore refuses writes until restamp (#1042).
- Shared Combined Postgres consults the writer fence, and `store relocate`
  accepts three PostgreSQL URLs with the same snapshot-then-fence cutover
  as SQLite (#1028).
- Combined env boot refuses a shared store unless `SEKAI_SHARED_STORE=1`;
  destination pairs stay the default Combined topology (#1032).
- Relocate refuses a `--sekai` that is not the historical `--source`, so a
  new empty Sekai file cannot orphan facts behind the writer fence (#1026).
- Store relocate takes a `VACUUM INTO` snapshot, fences the source, then
  copies Chisei families from the snapshot instead of ATTACH'ing the live
  file for a long DELETE+INSERT window (#1021).
- Combined Split divides the process connection-pool budget across both
  stores so two identities do not double FDs or idle connections (#1020).
- Typed plane handles no longer `Deref`/`From`/`AsRef` to `RuntimeDb`, and
  Sekai no longer holds a Chisei `BudgetTracker`; shared identity stays an
  explicit `from_shared_runtime` constructor (#1031).
- Split restore-fence admits a matched generation once per restamp/open
  epoch instead of selecting both stores on every mutating RPC (#1047).
- Audited object create takes a Deferred writer lock and upgrades to
  Immediate only after SQLITE_BUSY. Profile conflict converge waits at
  most 30ms instead of 160ms (#1045).
- Combined PostgreSQL Split treats `localhost`, `127.0.0.1`, and `::1` as
  one host so alias pairs cannot open two writers on the same database
  (#1018).
- Execution-evidence reconcile takes one Immediate writer lock for a due
  batch and backs off to 60s when idle, so empty 10s ticks no longer hit
  the Sekai evaluate pool (#1022).
- ADR 0084 records that a valid System One Preview fill may persist a
  bounded typesafe Decision; Submit stays the only ActionInstance write
  (#1050).
- Relocate refuses `--sekai` and `--chisei` that resolve to the same SQLite
  file or inode, so Split cutover cannot land both planes on one identity
  (#1027).
- Gateway-report opens Combined stores through `open_layout_or_fence`, so a
  fenced Shared `DB_PATH` cannot still boot a writer for egress rows (#1029).
- Restore fence treats `PreviewObjectAction` as mutating so TypeSafe fill,
  egress, and Decision audit stay refused while split generations disagree
  (#1048).
- Remote Sekai commit lookup reuses one gRPC channel and the current Tokio
  runtime (or one parked fallback runtime) instead of spawning a thread,
  runtime, and connect on every hop (#1046). Combined stays in-process.
- Shared-compatibility Combined open refuses when the writer fence is
  raised, so `from_env` cannot boot a single-file writer after relocate
  (#1019).
- Preview records TypeSafe egress audit only when the post-fill preview
  stays `valid`. A filled body that fails the second preview clears
  proposed parameters and does not persist a typesafe Decision (#1044).
- Combined SQLite destinations that resolve to the same inode are refused
  even when the path strings differ (hardlinks). Canonical-equal paths
  still refuse (#1017).
- MCP Preview that may fill uses the Function host request timeout
  (`LLM_HTTP_REQUEST_TIMEOUT_SECS`, default 120s) instead of a hard 5s
  deadline. Submit stays at 5s (#987).
- Shared and owned-plane opens of a stamped store compare `SEKAI_STORE_PEER`
  or refuse mutating RPCs until an operator restamp. An unstamped single
  file stays Shared compatibility (#1049).
- Admit and valid Preview stamp `system_one_fill_json` with the type
  version's pinned System One bind and a digest of the admitted parameter
  body. Submit does not re-invoke the Function (#981).
- Combined destination pairs stamp a split generation on each store and
  refuse mutating RPCs when the pair disagrees after a one-sided restore
  until `sekaictl admin store restamp` (#1009).
- Preview treats a blank string, JSON `null`, or `{}` as empty parameters
  for System One fill. After a fill, `request_digest` binds to the filled
  body (#988).
- Concurrent governed-fact profile creates take an Immediate writer lock
  and treat SQLite lock errors as converge-if-identical, so two pools on
  one file no longer unwrap `database is locked` (#1030).
- Preview fills System One proposals only after revision, criteria, policy,
  and budget would allow, and records a TypeSafe egress audit (#982).
- Object-log dual-read samples and skips unexpressible compares before
  loading `active_object_policy`, so unsampled evaluates do not pay
  per-kind policy fetches (#1024).
- Bind TypeSafe Jev as an Action-filling Function, not a write path
  ([ADR 0084](docs/decisions/0084-system-one-action-function.md), #975). A
  registered Action type may declare a pinned System One bind. Preview with
  empty parameters returns `proposed_parameters_json` from an authorized
  object projection. `SubmitActionInstance` remains the only write.
- Project object-type index member properties and page bounds in SQL so
  EvaluateObjectSet does not decode the wide JSON row and apply
  `LIMIT`/`OFFSET` after the stream (#1023).
- `sekai-plane` and `chisei-plane` run as separate processes. Each opens only
  its own store and credentials, stamps that ownership, and rejects
  wrong-plane RPCs. The ontology CLI keeps the `sekai` binary name. Chisei hops
  to Sekai with `SEKAI_ENDPOINT` / `SEKAI_CREDENTIAL`; Sekai rechecks current
  caller authorization at commit. Combined mode keeps the typed two-store
  contract. The gateway stays a translator (#1008).
- Combined two-store admission reserves on Chisei, commits through
  `SubmitActionInstance` on Sekai, and finalizes or releases only after a
  typed hop. Timeout is not rejection; reconcile never treats a late commit
  as reject. Gateway and native submit share the same clerk (#1007).
- Combined two-store startup reconciles Sekai execution evidence against
  the Sekai runtime, not the Chisei destination (#1013).
- Offline Chisei-family relocation copies destination tables family by
  family, validates counts, and raises a writer fence so a single `DB_PATH`
  writer refuses to start (`sekaictl admin store relocate`, #1006).
- Combined mode opens two physical stores when `SEKAI_DB_PATH` and
  `CHISEI_DB_PATH` (or two PostgreSQL destination URLs) are set, and refuses
  a pair that resolves to the same file or database (#1005). Gateway stays a
  translator. A single `DB_PATH` / `DATABASE_URL` remains one-file
  compatibility until relocation.
- Introduce typed `SekaiStore` / `ChiseiStore` handles so Chisei constructors
  no longer take `RuntimeDb` (#1004). Combined destination mode now opens two
  files (#1005); a single `DB_PATH` still uses `split_shared_runtime`.
- Record two-store implementation contracts (#999): ADR 0083 (offline
  relocation, lifecycle ownership, reservation recovery, one-sided restore
  fence), ADR 0082 corrections (`SubmitActionInstance`, per-plane
  `operation_id` collision scope, no cross-plane store handles), and
  implementation Issues #1004–#1009 (first slice #1004 ready).
- Document the #963 hop-projection default ops contract (#970): unset or
  empty `SEKAI_OBJECT_INDEX_ENGINE` is hop-projection, including `parse("")`.
  Operators must `ReindexObjectType` for hop kinds. Pinning nested-loop
  does not bypass an unready generation.
- Object-log dual-read skips unexpressible grammar (`group_by`, filters,
  incoming hops, path multiplicity, non-i64 sum) and keeps the SQL answer
  (#990). After #980 every production multi-hop has `group_by`; the canary
  is no longer a kill switch. Mismatch, missing log, and missing
  `max_rows_scanned` still fail closed.
- Object-log dual-read refuses incoming (and other non-outgoing) hop
  directions instead of comparing them as outbound (#989). Tagged mikura
  `v0.1.0` has no incoming hop; mapping waits on a later published tag.
- `.env.example` object-log dual-read comments match configuration.md after
  #980: refuse `group_by`, path multiplicity, and non-i64 sum, and note that
  production multi-hop always refuses the canary (#986).
- Incremental `ReindexObjectType` clears hop-projection ready before member
  upserts and keeps it false until join rewrite commits (#985). Concurrent
  evaluate cannot pair updated member JSON with stale hop edges.
- Nested-loop multi-hop EvaluateObjectSet honors the hop-projection ready
  fence (#984). After a same-digest datasource rebind or an unready join
  generation, the debug engine fails closed until `ReindexObjectType`.
- Aggregate EvaluateObjectSet checks `aggregation.property` against property
  grants on the leaf hop kind (#983). Denied numeric properties fail closed
  instead of contributing to sum/min/max.
- Object-log dual-read projects clerk property grants into the tagged deny-list
  (#969). A non-empty grant allow-list cannot be witnessed by the tagged
  single-deny API, so the canary stays off and evaluate keeps the SQL answer.
  Soak remains allow-all-only.
- Object-log dual-read is a canary: it requires `max_rows_scanned` and samples
  one of `SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE` requests (default 32) so enabling
  the flag does not open the object store on every evaluate (#968). Set
  sample to `1` for CI. Unsampled requests keep the SQL answer.
- Hop-projection evaluate reads one ready+generation+digest fence per query
  (#967). Matching generation skips join/member COUNT; empty generation keeps
  the wipe-detector COUNT path. Publish and invalidate clear the stamp.
- Indexed EvaluateObjectSet filters push eq/gt/gte/lt/lte onto stored member
  JSON in SQL (#966). Non-matching kind rows are excluded before the full
  property map is decoded. Unknown operators fail closed.
- Object-log dual-read fails closed when the tagged evaluate API cannot
  witness the SQL answer: `group_by` buckets, path multiplicity, or a
  non-i64/missing sum (#965). Vacuous root-count/sum matches no longer
  stamp Ok.
- `RegisterObjectTypeDatasource` that changes join-relevant binding fields
  clears hop-projection ready even when `definition_digest` is unchanged
  (#964). Identical re-register does not. Evaluate stays fail-closed until
  `ReindexObjectType`.
- Aggregate `EvaluateObjectSet` loads only group_by, numeric, filter, and
  nested-loop join properties on hop members (#953). Unused JSON keys are
  dropped; count-only leaf fetches skip property maps.
- Hop-projection join lookup uses the stored raw join value instead of
  SHA-256 hashing every parent key on each hop (#952). PostgreSQL binds
  `ANY($::text[])`; SQLite keeps a bounded `IN` list. Digest remains the
  write-time uniqueness key.
- Object-index dual-read stays off by default and fails closed without
  `max_rows_scanned` (#951). Both nested-loop and hop-projection share that
  meter so a canary cannot run as an unbounded production path.
- Kind reindex writes join rows once, in one transaction, after member upserts
  (#950). Per-member join DELETE/INSERT during upsert is gone; PostgreSQL
  rebuild uses a single pooled connection.
- Hop-projection evaluate walks join-table edges instead of rematerializing
  every hop and re-hashing child properties (#949). Intermediate hops load
  source_key/object_id only; full member JSON is fetched at the leaf.
- Multi-hop `EvaluateObjectSet` defaults to hop-projection (#948). Nested-loop
  remains an explicit debug engine (`SEKAI_OBJECT_INDEX_ENGINE=nested-loop`).
  Unready or stale join generations still fail closed.
- Definition-branch publish clears hop-projection ready until `ReindexObjectType`
  restamps the datasource digest (#947). Hop-projection evaluate fails closed
  when join status is unready or the datasource revision is not the published
  head.
- Indexed `EvaluateObjectSet` property filters use the same eq/gt/gte/lt/lte
  matcher as dataset rows (#946). Non-eq ops no longer empty the SQLite index
  path or collapse to string equality on PostgreSQL; non-numeric inequalities
  fail closed.
- Dual-read `EvaluateObjectSet` against a tagged mikura object log when
  `SEKAI_OBJECT_LOG_DUAL_READ=1` (#942). Hop count and sum must match; a
  missing log, mismatch, or unmappable descriptor (filters, non-sum/count)
  fails closed. SQL index writes continue.
- Share the gateway git-version emitter and provider SSE `data:` parser instead
  of keeping byte-identical copies, and hoist adapter timestamp/required-field
  helpers onto the evidence SDK.
- Point TypeScript and Python `executePlan` helpers at `ExecutePlanStream`.
  The public unary `ExecutePlan` RPC is gone; `runCoreLoop` no longer calls it.
- Keep SQLite and PostgreSQL as the community control-plane pair
  ([ADR 0080](docs/decisions/0080-dual-community-runtime-storage.md), #870).
  SQLite stays the local default. PostgreSQL stays optional. The embedded
  PostgreSQL envelope remains a feasibility measurement, not a runtime pick.
  Ontology CLI SQLite stays a different database.
- Evaluate object-set hops on a pluggable index engine (#889). Default
  `nested-loop` keeps the original scan. `SEKAI_OBJECT_INDEX_ENGINE=hop-projection`
  uses the rebuildable join-key projection from the #889 envelope; switch
  is a reindex, receipts and authorization are unchanged. Dual-read
  (`SEKAI_OBJECT_INDEX_DUAL_READ=1`) fails closed on a path mismatch.
  Hidden rows stay out of both engines. Not a vendor engine pick.
- Publish the #889 hop-projection envelope: the #877 product nested-loop
  two-hop misses 500 ms at 10⁵ (distinct 963 ms; all-paths 65 s); on-the-fly
  SQL and hash-join miss at 10⁷ and 10⁸; a rebuildable reachability
  projection query holds (0 ms p95) with matching counts. Not a vendor
  engine pick.
- Publish the #870 embedded-PostgreSQL envelope: cold start 136 ms and
  ~161 MiB complete footprint (prefix + data + linked dylibs including ICU)
  on macOS PostgreSQL 17.10; Docker `postgres:17-alpine` 110 MiB / 1.09 s to
  TCP readiness. Discussion 906 kill signals hold. Not a runtime pick.
- Pin the Rust toolchain to 1.98.1 and digest-pin the Debian runtime image.
  Cargo is the local and CI gate (`cargo fmt-check`, `cargo clippy-all`,
  `cargo test-all`). `./build/release-images.sh` is the only image build
  (git-describe tag; dirty trees are refused). `./build/release.sh` pushes
  that same tag. Binaries record git describe identity at startup.
- Honor a presented bearer on insecure TCP and HTTP the same way UDS
  already does (#929). Missing bearer stays local; caller-selected tenant
  headers still fail closed. Token-auth TCP is unchanged.
- Coordinate definition-branch edits across object types, functions,
  transforms, and policies in one revision (#890). Merge refuses a
  breaking function, transform, or policy change, or any unknown kind,
  naming `compatibility_gate:{member_kind}` and leaving the published
  head unchanged. Consumer impact lists registered dependents of all
  four kinds. `GetDefinitionBranch` returns a content-addressed
  `pin_digest` for delivery consumers. Breaking object-type publication
  stays available for fact migration.
- Invoke ontology functions on the in-process host with recorded clock
  and rng, step/time/output budgets, and principal-scoped reads (#882,
  [ADR 0072](docs/decisions/0072-in-process-function-host.md)). Guest
  isolation remains later. `InvokeFunction` is experimental.
- Run plane-owned incremental dataset transforms with lineage and
  quality quarantine (#880). Definitions are content-addressed; secrets
  are rejected; a failing rule keeps the previous output queryable and
  names the rule on the run receipt. In-process `projection` execution,
  not an engine pick. SQLite community path; PostgreSQL fails closed.
- Evaluate revision-bound object sets with grouped aggregations and
  bounded multi-hop traversal (`sekai.object-set/v2`, #878). Plans use
  the #877 membership index and refuse named cost limits rather than
  truncating. Hidden rows stay out of aggregates. Two-hop at 10^7 remains
  outside the 500 ms envelope recorded in the #876 note; an alternate
  engine stays #889.
- Register a dataset as the membership source for an object type revision
  and maintain a rebuildable incremental projection (#877). Schema drift
  quarantines the batch and leaves the last index readable and stale.
  Action deltas survive a full rebuild. Hidden rows are absent from
  members and counts. `EvaluateObjectSet` may require freshness and fails
  closed when the index is stale or lagging. The index is not authority.
- Publish the #876 object-index envelope: 10⁷ synthetic Customer → Order →
  Shipment rows on a named Apple M2 Pro profile. Membership materialize,
  1_000-key incremental, filter, aggregate, and rebuild-from-source hold;
  two-hop p95 misses 500 ms. #877 is unblocked as a projection; #878 and
  #889 stay measurement-gated. The harness is not the product indexer.
- Verify configured `sia1.` identity assertions on the live
  `TokenAuthInterceptor` path from `SEKAI_ASSERTION_ISSUER`,
  `SEKAI_ASSERTION_AUDIENCE`, and `SEKAI_ASSERTION_HMAC_KEY`. Make
  `CompiledObjectAccess::decide` the live object read/write/link
  authority; the 10k differential compares that product to the pre-PDP
  evaluators rather than a copy of `decide`.
- Accept audience-bound, one-use signed identity assertions that fill the
  existing `AuthenticatedContext` (#888,
  [ADR 0078](docs/decisions/0078-audience-bound-assertions.md)). No configured
  authority stays community and tenant-free. Caller-selected tenant headers
  fail closed. The in-process extension trait stays until this path has
  documented parity. `compatibility.json` names
  `sekai.identity-assertion/v1`.
- Compile every object read and write through one crate-visible policy
  decision point over the shipped v1 vocabularies (#885,
  [ADR 0076](docs/decisions/0076-compiling-policy-entry.md)). Mandatory
  markings stay mandatory; grants, purpose, property, and value-instance
  rules narrow after that. `SimulateObjectPolicyChange` is a read
  projection and never a grant. `QueryObjectPolicyAudit` returns allow or
  deny with policy identities and revision and omits hidden values. Both
  RPCs stay experimental.
- Let a `GovernedActionType` declare closed submission criteria and a
  declared effect-kind subset (#883,
  [ADR 0077](docs/decisions/0077-action-type-criteria.md)). Preview names a
  failing visible criterion; submit rechecks live state and refuses with the
  same code. Hidden or ungranted properties fail closed as unavailable.
  Function-backed rules and a webhook family stay out of this slice.
- Serve stable unary RPCs as an in-process HTTP/JSON projection of the same
  gRPC handlers, auth interceptor, and maturity gate (#875,
  [ADR 0075](docs/decisions/0075-http-ontology-projection.md)). Routes are
  `POST /sekai.SekaiService/{Method}` and `POST /chisei.ChiseiService/{Method}`
  on `SEKAI_HTTP_PORT` (default 50080). Experimental RPCs stay refused.
  Streaming stays on gRPC. `/mcp` reuses the same bearer. Generated
  TypeScript, Python, and Rust HTTP clients are CI goldens, not a second
  resource model.
- Record accepted Design Discussions for transforms, the HTTP ontology
  projection, one compiling policy entry, Action-type criteria, audience-bound
  assertions, and evaluation-gated promotion (Discussions 908, 902, 903, 904,
  905, 901; [ADR 0074](docs/decisions/0074-plane-owned-transforms.md)–[0079](docs/decisions/0079-evaluation-promotion-gate.md)).
  Dual runtime storage stays measurement-gated (Discussion 906). No engine or
  vendor runtime is named.
- Record that typed objects are facts of a type revision produced by
  registered sources or versioned Actions. Graph rows are persistence. A
  derived index is a rebuildable projection, never a second authority
  (#876, [ADR 0073](docs/decisions/0073-source-and-action-objects.md)).
- Record that ontology functions are an in-process host API: grow the
  existing `CreateFunction` pipeline; never run them as an agent harness;
  isolate guest code later behind that same host without picking an engine
  (#881, [ADR 0072](docs/decisions/0072-in-process-function-host.md)).
- Share one ontology definition design across portable `sekai` import and
  `sekaictl ontology apply`. Class, relation, property, cardinality, and
  mapped_kind fields mean the same thing on both I/O paths. Apply-only
  hints (`ensure_kind`, `kind_description`) stay off the portable meaning
  model (#900).
- Add `sekai setup` so a scoped portable ontology, directory vocabulary,
  optional directory index, and agent skill can be created in one idempotent
  command. Default setup writes `.sekai/knowledge.db` instead of a bare
  `knowledge.db`. Existing `init`, `directory`, and `skill` commands stay
  available for scripted steps.
- Ship a versioned portable product vocabulary pack that agents can import
  into a fresh `sekai` database and query with provenance (#895). The pack is
  contributor vocabulary for this repository, not a built-in server ontology
  and not `directory init` vocabulary.
- Split the three largest service files into handler-family modules so each
  facade stays under 2,000 lines (#872). Shared helpers move with the family;
  each service keeps one trait impl that delegates. CI fails if any of the
  three files regrows past that ceiling.
- Classify every public RPC as `stable`, `experimental`, or `remove` from
  backend and consumer evidence (#871). The default build invokes at most 60
  stable RPCs. Experimental and remove-classified RPCs keep their wire
  contract but require `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs`
  feature. `DiscoverCapabilities` reports `sekai.rpc.experimental` on the
  core pack; visibility is not a grant.
- Publish `compatibility.json` (`sekai.compatibility-matrix/v1`) as a
  projection of shipped server, proto, and SDK versions (#873).
  `sekaictl admin compatibility check` reports on-matrix or off-matrix and
  names the expected revision. Vendored TypeScript copies stay off-matrix
  until replaced by a package pin.
- Stamp one caller operation identity (`x-sekai-operation-id` /
  `request_id`) on the inbound span, the operation receipt, and the
  object-change event for a governed action (#886). Mismatched header and
  request id fail closed.
- Add `SekaiService.ReadObjectChangeSubscription` for plane-owned
  create/update/delete pages over `sekai.event-subscription/v1` cursors
  (#838). Clients snapshot, then stream. Caller-supplied pages are not
  object authority; a gap, expiry, or authorization change requires
  resnapshot. Slow consumers disconnect explicitly.
- Add `SekaiService.ReportDefinitionConsumerImpact` for authorized
  consumer paths joined to `CompareDefinitionRevisions` (#837). Only
  explicit `sekai.definition-consumer-binding/v1` registrations are
  consulted. Completeness is explicit; zero visible dependents is not
  proof of zero impact.
- Add `SekaiService.EvaluateObjectSet` for revision-bound
  `sekai.object-set/v1` descriptors (#835). Evaluation uses existing
  authorized list and one-hop traverse. A descriptor, page, or cursor is
  not authority; stale definition pins and hidden predicates fail closed.
- Persist workflow-action bindings, callbacks, and command replay on
  community PostgreSQL with the same generation-fenced transition as SQLite
  (#823). Concurrent callback and cancel cannot double-advance a binding.
- Persist event-stream projections and subscriptions on community PostgreSQL
  with the same compare-and-swap pins as SQLite (#822). Checkpoint advancement
  and cursor writes share one transaction with their event commitments; a
  concurrent miss is a typed conflict, not last-write-wins.
- Add `SekaiService.DescribeObjectAction` and `PreviewObjectAction` as
  observational projections over object-bound governed Actions (#836). Preview
  is not a permit; submit remains `SubmitActionInstance`. Stale object or
  Action state and hidden objects fail closed.
- Expose `ChiseiService.GetQualityTrend`, an authenticated projection of the
  canonical quality-trend reducer (#821). CLI and RPC share one semantic
  digest; clients must not reimplement reduction. Denied namespaces and
  over-limit windows fail closed.
- Add `sekaictl admin sync inspect-quarantine`, `preview-batch`, and
  `apply-batch` for the latest quarantined source result (#820). Inspection and
  preview are observational; re-admission is existing `ApplySourceBatch`. A
  stale preview cannot overwrite a newer checkpoint or type revision.
- Ship `sekai-mcp`, a stdio MCP projection host over `GetObject`,
  `SubmitActionInstance`, and `GetOperationReceipt` (#839). Discovery is not a
  grant; credentials stay in the host environment; unknown mappings, forged
  reserved metadata, and oversized frames fail closed.
- Isolated SDK consumer staging pins `sekai-proto` as a sibling path, rewrites
  TypeScript fixtures like Python, re-hashes protocol/source/package bytes from
  disk, and includes `chisei.proto` in the protocol digest (#844). cargo, npm,
  and pip registry installs are still not claimed.
- Isolated SDK consumer proof fails closed without `python3`, `node`, or
  `rustc`, and asserts live core-loop identity from those processes in a
  tempfile (#843). Static fixture `include_str` is not the parity proof.
  cargo/npm/pip install graphs remain #844.
- Clarify the object-sync Batch contract admits the code-owned GitHub digest
  or a live registered descriptor (#832). A digest that is neither the GitHub
  profile nor a live catalog entry still fails as `unbound_type_revision`.
  GitHub identity stays unchanged. ADR 0021 is not superseded.
- Document both admitted object-sync identity grammars in
  [docs/object-sync.md](docs/object-sync.md) Identity (#831). GitHub
  Issue/PullRequest stays `github:{owner}/{repo}#{number}`. Live registered
  descriptors use `{source}:{instance}#{record_kind}/{immutable_key}`.
  `source=github` cannot be registered; registered kinds cannot be Issue or
  PullRequest. ADR 0021 is not superseded.
- Re-validate live registered source-type catalog status inside the Immediate
  write transactions that open and commit `ApplySourceBatch` (#830). A
  concurrent retire after the pre-transaction catalog read fails closed as
  `unbound_type_revision` before durable advance. Exact committed or
  quarantined replay is unchanged after retirement. PostgreSQL registered-type
  apply stays unavailable.
- Prove isolated Rust, TypeScript, and Python consumers can install pinned
  local SDK artifacts and share the native core-loop identity (#840). Tampered
  or incompatible protocol/source/package digests fail closed. Registry
  publication is not claimed.
- Publish one object and Action integration contract map
  ([docs/integration-contract.md](docs/integration-contract.md), #834).
  Supported rows name the owning service, RPC, maintained guide, and
  executable proof. ObjectSet, application preview, subscriptions, MCP, and
  registry packages are recorded as gaps.
- Measure concurrent source refresh and authorized object pagination over
  deterministic small, medium, and large synthetic graphs (#824). Hidden
  records stay omitted; foreign source cursors and changed query/policy
  digests fail closed. The additive
  `benchmarks/manifest-source-ingestion-v1.json` suite records throughput,
  checkpoint lag, query latency, and memory observations without adopting
  regression thresholds.
- Apply snapshot and ordered-change batches for a live registered source-type
  descriptor with the same transactional identity, checkpoint, and quarantine
  lifecycle as GitHub ([ADR 0060](docs/decisions/0060-additive-source-type-descriptors.md),
  #819). Identity is `{source}:{instance}#{record_kind}/{immutable_key}`.
  Unknown, retired, or unadmitted descriptors fail closed. PostgreSQL
  registered-type apply stays unavailable. GitHub Issue/PullRequest identity
  and dual-backend apply stay unchanged.
- Register, inspect, and retire one admitted source-type descriptor on SQLite
  (`sekai.source-type-descriptor/v1`,
  [ADR 0060](docs/decisions/0060-additive-source-type-descriptors.md)).
  `RegisterSourceTypeDescriptor`, `InspectSourceTypeDescriptor`, and
  `RetireSourceTypeDescriptor` require authenticated namespace administration.
  Inspection returns bounded identity fields only. Unknown or unadmitted
  descriptors cannot authorize `ApplySourceBatch`. PostgreSQL stays unavailable.
  GitHub Issue/PullRequest identity stays `github:{owner}/{repo}#{number}`.
  `sekaictl admin sync register-descriptor|inspect-descriptor|retire-descriptor`
  is the operator surface. ADR 0021 is not superseded.
- Accept additive registered source-type descriptors
  ([ADR 0060](docs/decisions/0060-additive-source-type-descriptors.md)).
  Later kinds use `{source}:{instance}#{record_kind}/{immutable_key}`.
  GitHub Issue/PullRequest identity stays `github:{owner}/{repo}#{number}`.
  ADR 0021 is not superseded. #818 implements registration.
- Recommend additive registered source-type descriptors with immutable
  namespaced keys, proven by two local synthetic kinds. The research
  spike does not admit a second production source, change
  `ApplySourceBatch`, or supersede ADR 0021. GitHub Issue/PullRequest
  remains the only catalog-advertised object-sync profile. Free-form
  record names cannot infer a descriptor.
- Run one GitHub Issue through inbound object sync, a governed Action,
  permit-backed loopback write-back, source readback, and receipt
  inspection with `cargo run --locked --example source_writeback`. The
  loopback fixture keeps its record version and applied-effect counter
  outside the control-plane database. Stale source versions, revoked
  authorization, identical-intent replay, lost executor responses, and
  control-plane restart are asserted. The fixture Issue may describe a
  service incident; it does not add an Incident source type or a
  production connector.
- Admit autonomous Actions only inside a signed
  `sekai.autonomous-envelope/v1` whose state, policy, model, prompt,
  evidence, simulation, budget, and lease pins are current. Two
  domain-neutral adapters (`adapter.autonomy.simulate`,
  `adapter.autonomy.evaluate`) admit the envelope. Exact digest replay
  is idempotent. Stop is idempotent. Rollback supersedes history. Lease
  loss and receipt invalidation block further live admission. Stale
  pins fail closed. The envelope is not a grant.
  `sekaictl admin autonomy` admits, inspects, stops, rolls back, notes
  lease loss, and invalidates receipts. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Certify model-platform adapters as `sekai.model-platform-certification/v1`
  records that pin `sekai.evaluation-evidence/v1`. Two domain-neutral
  adapters (`adapter.model.responses`, `adapter.model.messages`) pass
  capability, streaming, usage, fallback, and receipt protocol fixtures.
  Unsupported capability and ambiguous usage fail closed. Exact digest
  replay is idempotent. Revocation is terminal. Certification is not a
  runtime grant. `sekaictl admin providers` certifies, retrieves,
  verifies, and revokes. SQLite is the reference store; PostgreSQL stays
  unavailable.
- Export governed lakehouse snapshots as `sekai.lakehouse-snapshot/v1`
  records. Each snapshot pins partitions, additive schema versions, and
  `sekai.security-metadata/v1` classification, purpose, residency, and
  trust. Two domain-neutral adapters (`adapter.lakehouse.events`,
  `adapter.lakehouse.metrics`) register a partitioned snapshot. Schema
  upgrade is additive. Redaction and partition deletion are explicit
  markers. Exact digest re-import is idempotent. Revocation is terminal.
  Security metadata constrains visibility; it is not a grant. Hidden
  columns, foreign tenants, and unknown versions fail closed.
  `sekaictl admin lakehouse` registers, reimports, upgrades, redacts,
  deletes, retrieves, and revokes. SQLite is the reference store;
  PostgreSQL stays unavailable.
- Export governed warehouse projections as `sekai.warehouse-projection/v1`
  records. Each projection pins authorized columns and
  `sekai.security-metadata/v1` classification, purpose, residency, and
  trust. Two domain-neutral adapters (`adapter.warehouse.orders`,
  `adapter.warehouse.inventory`) register a projection, export a
  snapshot, then contiguous incremental pages that may tombstone rows.
  Exact last-page replay is idempotent. Revocation is terminal. Security
  metadata constrains visibility; it is not a grant. Hidden columns,
  stale cursors, foreign tenants, and unknown versions fail closed.
  `sekaictl admin warehouse` registers, exports, retrieves, and revokes.
  SQLite is the reference store; PostgreSQL stays unavailable.
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
