# Documentation

Use this page to choose a path. The [reference catalog](reference.md) lists
every maintained guide and contract; the [research index](research/README.md)
keeps design history separate from current usage.

## Start here

If you want to run the project locally:

1. Complete the [repository quick start](../README.md#quick-start).
2. Read [Ontology definitions](ontology.md) for the full apply, seed, run, and
   receipt workflow.
3. Run a domain-neutral [example](../examples/README.md).

If you want to build an agent or SDK integration:

1. Read the [architecture overview](architecture.md) to understand the Sekai,
   Chisei, interface, and runtime boundaries.
2. Use the [capability catalogs](capability-catalog.md) — native
   `DiscoverCapabilities` contract `1.0` for governed surfaces, and
   `chisei.provider-capabilities/v1` for the HTTP provider-profile matrix —
   together with the native [`proto/`](../proto/) contract.
3. Check the [available-model discovery contract](available-models.md) when the
   integration executes model calls.

To connect an existing Codex, Claude Code, OpenAI-compatible, or
Anthropic-compatible client, use the optional [compatibility gateway](gateway.md).

If you want to deploy or operate the control plane:

1. Review all settings in [Configuration](configuration.md).
2. Apply the safeguards in [Operations and security](operations.md).
3. Use the [Docker guide](docker.md) if you want the supported container
   topology.

## Core concepts

- [Architecture](architecture.md) — ownership, trust boundaries, data model,
  and governed entry paths.
- [Ontology definitions](ontology.md) — semantic classes, relations, schemas,
  provenance, and validation.
- [Capability catalogs](capability-catalog.md) — native governed-surface
  discovery (`DiscoverCapabilities` `1.0`) and the HTTP provider-profile
  matrix (`chisei.provider-capabilities/v1`).
- [Governed actions](governed-action-types.md) — start of the action type,
  instance, effect, runtime claim, and evidence lifecycle.
- [External-action execution](external-action-execution.md) — permits,
  execution observations, and reconciliation.
- [Governed subject evaluation](governed-subjects.md) — payload-free
  evaluation of externally owned immutable subjects.
- [Evaluation plans and evaluator definitions](evaluation-plans.md) —
  situation-specific deterministic and bounded stochastic contracts.
- [Evaluation-plan operator CLI](evaluation-operator-cli.md) — author,
  validate, publish, inspect, dry-run, and explicitly execute exact plans.
- [Resolved evaluation manifests](evaluation-manifests.md) — immutable,
  content-bound pre-execution inputs and historical replay.
- [Evaluation execution](evaluation-execution.md) — bounded,
  receipt-authoritative deterministic and stochastic execution.
- [Evaluation quality trends](evaluation-quality-trends.md) — authorized,
  receipt-reconciled quality, variance, regression, and baseline projections.
- [Evaluation gate evidence](evaluation-gate-evidence.md) — server-owned,
  digest-bound, bounded evidence for release gates.
- [External evaluator adapters](evaluator-adapters.md) — namespace-scoped,
  authenticated execution for operator-deployed domain evaluators.
- [Epistemic Kioku context evaluation](epistemic-context-evaluation.md) —
  matched claim-only/framed comparison with digest-bound metrics and gates.
- [Kioku evidence reassessment](kioku-evidence-reassessment.md) — explicit,
  review-gated successor candidates when admitted evidence changes.
- [Epistemic descriptor](epistemic-descriptor.md) — additive, bounded
  origin/evidence/lifecycle metadata on existing context references.
- [Epistemic metadata conformance](epistemic-metadata-conformance.md) —
  black-box non-disclosure evidence across graph, receipt, and
  descriptor projections.
- [Context admission policy](context-admission-policy.md) — versioned rules
  for using or holding out epistemically qualified context. Gateway fat-decide
  requires a policy and fails closed when it is missing or unavailable.
- [Governed requirement and invariant facts](governed-facts.md) — immutable,
  domain-neutral normative facts, waivers, and authorized invariant sets.

## Project and community

- [Vision](../VISION.md) — product direction and explicit non-goals.
- [Contributing](../CONTRIBUTING.md) — setup, tests, design expectations, and
  pull-request requirements.
- [Support](../SUPPORT.md) — where to ask questions, report bugs, and disclose
  vulnerabilities.
- [Project operating system](project-operating-system.md) — how Issues,
  Discussions, pull requests, decisions, and project Skills fit together.
- [Architecture decisions](decisions/README.md) — accepted durable decisions.
- [Code of conduct](../CODE_OF_CONDUCT.md) — community standards.

## Browse all documentation

- [Reference catalog](reference.md) — maintained user, integration, operator,
  extension, and implementation documentation.
- [Research index](research/README.md) — completed investigations and design
  freezes. Research explains decisions but does not override current guides,
  protocol definitions, or implementation.

## Documentation conventions

- Commands are written from the repository root unless a guide says otherwise.
- `cargo run --bin sekaictl -- ...` works without installing the CLI. Examples
  may use the shorter `sekaictl ...` form after installation.
- `.env.example` is the primary local template. The configuration guide
  explains stable operator-facing settings; experimental settings may remain
  documented next to the implementation until they stabilize.
- The protocol files and implementation are authoritative when an experimental
  API and prose documentation disagree. Please report drift as a bug.
- Pages under `docs/research/` are design history. Follow their linked current
  guides for shipped behavior.
