# Documentation reference

This catalog lists the maintained documentation by reader task. Start with the
[documentation guide](README.md) if you are new to the project. Design history
lives in the separate [research index](research/README.md).

## Run and integrate

- [Ontology definitions](ontology.md) — define a domain, seed governed facts,
  run an operation, and inspect its receipt.
- [Capability catalogs](capability-catalog.md) — native `DiscoverCapabilities`
  contract `1.0` for agents and SDKs, and HTTP
  `chisei.provider-capabilities/v1` for the gateway provider-profile matrix.
- [Native gRPC protocol](../proto/) — service and message definitions.
- [Bounded content execution](content-execution.md) — separate native
  text/image/audio/document descriptors, transient payload verification, and
  provider capability behavior.
- [Sample observation readback](sample-observation-readback.md) — authenticated,
  redacted telemetry admission projection.
- [SDK facade](../sdk/README.md) — generated-client layering and capability
  code generation.
- [Available models](available-models.md) — enumerate the governed routable
  model set through the CLI, gRPC, or HTTP.
- [Responses harness profile](responses-harness-profile.md) — supported
  request, streaming, and error behavior.
- [Examples](../examples/README.md) — runnable, domain-neutral integrations.
- [External reference adapters](../adapters/README.md) — separate versioned
  evidence and source-sync contracts, durable outboxes, and offline fixtures.
- [Social observation evidence adapters](social-evidence-adapters.md) —
  stdin funnel for `social.post_snapshot` and `social.reply`.
- [Evidence adapter catalog](evidence-adapter-catalog.md) —
  `ListEvidenceAdapters` discovery of built-in adapter families.
- [Compatibility gateway](gateway.md) — optional integration for Codex, Claude
  Code, OpenAI-compatible, and Anthropic-compatible clients.

## Configure and operate

- [Configuration](configuration.md) — environment variables, defaults, and
  precedence.
- [Operations and security](operations.md) — transport, credentials, TLS,
  observability, backups, and deployment checks.
- [Docker](docker.md) — container quick start and transport choices.
- [Operator console](operator-console.md) — authenticated browser shell and
  namespace context.
- [Evaluation-plan operator CLI](evaluation-operator-cli.md) — safe plan
  authoring, publication, inspection, dry-run resolution, and execution.
- [Evaluation quality trends](evaluation-quality-trends.md) — authorized,
  receipt-reconciled quality, variance, regression, and baseline reporting.
- [Lookup-first promotion gate](lookup-first-promotion-gate.md) — deterministic
  structured golden checks with audited, explicit-only promotion evidence.
- [Inspectable reversible learning changes](learning-changes.md) — evidence-bound
  proposal, approval, activation, and rollback without rewriting source
  learning.
- [Governed geospatial queries](geospatial-queries.md) — authorized spatial
  comparison of named property claims after property grants.
- [Team operations](team-operations.md) — namespace bootstrap and operator
  workflows.
- [Performance benchmarks](performance-benchmarks.md) — reproduce the
  sanitized workload and interpret regression budgets.
- [Replica safety](replica-safety.md) — durable-authority inventory and the
  two-replica test harness.
- [Replica conformance adapter](replica-conformance.md) — bounded callable
  shared-state checks for composed local test harnesses.
- [PostgreSQL parity: Sekai](postgres-sekai-parity.md) and
  [Chisei](postgres-chisei-parity.md) — supported dual-backend surfaces and
  SQLite-only exceptions.

## Graph, ontology, and retrieval

- [Ontology definitions](ontology.md) — classes, relations, schemas,
  provenance, and validation boundaries.
- [Governed definition branches](definition-branches.md) — namespace-scoped
  content-addressed revisions, compare-and-swap branch edits, and proposal
  merge onto the published head.
- [Standalone ontology crate](../crates/sekai-ontology/README.md) — embedded
  library and local `sekai` CLI.
- [Capability catalogs](capability-catalog.md) — native discovery and the HTTP
  provider-profile matrix, including invocation and decide-input boundaries.
- [Capability code generation](capability-codegen.md) — namespace-scoped
  generated client surfaces.
- [Ontology TypeScript and Python clients](ontology-codegen.md) —
  revision-pinned selected object, link, action, and function types.

## Policy, actions, and evidence

- [Policy dry-run](policy-dry-run.md) — side-effect-free policy
  counterfactuals over receipts.
- [Governed action types](governed-action-types.md) — namespace-scoped,
  versioned decision types.
- [ActionInstance admission](governed-action-instances.md) — idempotent submit
  and admit lifecycle.
- [Typed ActionInstance effects](governed-action-effects.md) —
  `runtime_dispatch` and `notify` effects.
- [Runtime claim API](runtime-claim.md) — claim, heartbeat, and terminal
  acknowledgement.
- [Action harvest binding](action-harvest-binding.md) — instance, effect, and
  operation correlation.
- [Evidence producer contract](action-evidence-producer-contract.md) —
  evidence submission with optional ActionInstance creation.
- [Inbound object sync](object-sync.md) — authenticated source batches,
  plane-owned checkpoints, GitHub Issue/PullRequest identity, replay, recovery,
  tombstones, retention, and rollback.
- [Registered Iceberg and Parquet projections](open-tables.md) — digest-pinned
  authorized queries over registered Iceberg and Parquet snapshots.
- [Event-stream projections](event-streams.md) — ordered event batches with
  durable checkpoints.
- [Governed documents and renditions](documents.md) — digest-bound document
  objects with renditions, hold, expiry, and deletion.
- [External-action execution](external-action-execution.md) — host lifecycle
  observations and missing-evidence reconciliation.
- [Governed subject evaluation](governed-subjects.md) — payload-free,
  content-bound evaluation through registered profiles.
- [Resolved evaluation manifests](evaluation-manifests.md) — authorized,
  content-bound evaluation-plan resolution without evaluator execution.
- [Evaluation execution](evaluation-execution.md) — exact-digest compiled or
  external deterministic and bounded stochastic evaluators, receipts, and
  fixed gates.
- [Evaluation gate evidence](evaluation-gate-evidence.md) — bounded,
  digest-bound evidence projection for release gates.
- [External evaluator adapters](evaluator-adapters.md) — authenticated,
  bounded operator-deployed evaluator contract.
- [Governed requirement and invariant facts](governed-facts.md) — versioned
  normative facts, exact supersession, governed waivers, and set resolution.
- [Host-executor permit conformance](host-executor-permit-conformance.md) —
  enforcement requirements for permit-consuming hosts.
- [Generation-fenced leases](leases.md) — object-bound coordination.
- [Gunshi auto-allocation](gunshi-auto-allocation.md) — evaluation-gated
  promotion and bounded automatic dispatch.

## Security, classification, and federation

- [Object security policy](object-security.md) — immutable policy revisions,
  atomic namespace activation, storage-enforced reads, writes, remaining object
  consumers, authority-bound list cursors, and purpose-bound reads.
- [Classification markings](classification-markings.md) — default ordinal
  markings, optional namespace lattices, and purpose constraints.
- [Compliance export](compliance-export.md) — governed audit and residency
  export packages.
- [Provider residency](residency-policy.md) — provider and data-class policy
  for a single control plane.
- [Context admission policy](context-admission-policy.md) — bounded,
  namespace-scoped context use rules. Gateway fat-decide fails closed when the
  policy is missing or unavailable.
- [Federation profile](federation-profile.md) — multi-control-plane trust,
  signed namespace snapshots, and imported assertion provenance.
- [Region/site pins](region-pins.md) — single-writer pins for leases and online
  permit redemption.
- [Budget topology](budget-topology.md) — supported multi-region budget modes.

## Enterprise extension contracts

The community runtime is tenant-free. These pages define extension seams and
conformance expectations; they do not imply that tenant or OIDC behavior is
enabled in the default build.

- [Enterprise identity extension](enterprise-identity-extension.md)
- [Tenant isolation conformance](tenant-isolation-conformance.md)
- [Tenant provider credentials](tenant-provider-credentials.md)
- [Tenant quotas](tenant-quotas.md)
- [Tenant invitations](tenant-invitations.md)
- [Tenant usage ledger](tenant-usage-ledger.md)
- [Tenant entitlements](tenant-entitlements.md)
- [Domain administration](domain-admin.md)
- [Billing adapter](billing-adapter.md)
- [Tenant lifecycle](tenant-lifecycle.md)
- [Legacy tenant-state migration](tenant-migration.md)

## Project internals

- [Architecture](architecture.md) — component and trust boundaries.
- [Architecture decisions](decisions/README.md) — accepted decisions and ADR
  template.
- [Project operating system](project-operating-system.md) — contribution and
  artifact lifecycle.
- [Research index](research/README.md) — investigations and design freezes that
  explain why current contracts look the way they do.
