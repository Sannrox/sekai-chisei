# Documentation reference

This catalog lists the maintained documentation by reader task. Start with the
[documentation guide](README.md) if you are new to the project. Design history
lives in the separate [research index](research/README.md).

## Run and integrate

- [Ontology definitions](ontology.md) — define a domain, seed governed facts,
  run an operation, and inspect its receipt.
- [Capability catalog](capability-catalog.md) — discover core governed
  capabilities for agents and SDKs.
- [Native gRPC protocol](../proto/) — service and message definitions.
- [SDK facade](../sdk/README.md) — generated-client layering and capability
  code generation.
- [Available models](available-models.md) — enumerate the governed routable
  model set through the CLI, gRPC, or HTTP.
- [Responses harness profile](responses-harness-profile.md) — supported
  request, streaming, and error behavior.
- [Examples](../examples/README.md) — runnable, domain-neutral integrations.
- [External evidence adapters](../adapters/README.md) — versioned evidence
  submission contract and reference adapters.
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
- [Standalone ontology crate](../crates/sekai-ontology/README.md) — embedded
  library and local `sekai` CLI.
- [Capability catalog](capability-catalog.md) — capability discovery and
  invocation boundaries.
- [Capability code generation](capability-codegen.md) — namespace-scoped
  generated client surfaces.
- [Capability package trust](capability-package-trust.md) — Ed25519 trust roots
  and fail-closed verification.
- [SQLite FTS](text-fts.md) — rebuildable lexical projection and the
  `HybridCandidate` envelope.
- [Hybrid retrieval](hybrid-retrieval.md) — explicit graph and FTS late-fusion
  plans.
- [Pattern plan](pattern-plan.md) — structured multi-hop execute and explain
  contract.
- [Scenario overlay](scenario-overlay.md) — request-scoped, non-authoritative
  hypothetical graph changes.
- [Temporal history](temporal-history-storage.md) — selective bitemporal
  storage, correction, and as-of queries.

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
- [External-action execution](external-action-execution.md) — host lifecycle
  observations and missing-evidence reconciliation.
- [Governed subject evaluation](governed-subjects.md) — payload-free,
  content-bound evaluation through registered profiles.
- [Governed requirement and invariant facts](governed-facts.md) — versioned
  normative facts, exact supersession, governed waivers, and set resolution.
- [Host-executor permit conformance](host-executor-permit-conformance.md) —
  enforcement requirements for permit-consuming hosts.
- [Generation-fenced leases](leases.md) — object-bound coordination.
- [Gunshi auto-allocation](gunshi-auto-allocation.md) — evaluation-gated
  promotion and bounded automatic dispatch.

## Security, classification, and federation

- [Classification markings](classification-markings.md) — provisional
  markings and purpose constraints.
- [Compliance export](compliance-export.md) — governed audit and residency
  export packages.
- [Provider residency](residency-policy.md) — provider and data-class policy
  for a single control plane.
- [Federation profile](federation-profile.md) — multi-control-plane trust and
  exchange contract.
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
