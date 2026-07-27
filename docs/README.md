# Documentation

This index separates the fastest path to a working system from reference and
operator material. If you are new to the project, follow the first three links
in order.

## Get started

1. [Repository quick start](../README.md#quick-start) — build, launch, and
   verify a local instance.
2. [Architecture](architecture.md) — understand what Sekai, Chisei, the
   gateway, and agent runtimes own.
3. [Examples](../examples/README.md) — run a client or inspect a domain-neutral
   integration.

## Integrate

- [Gateway and clients](gateway.md) — use Codex, Claude Code, OpenAI-compatible,
  or Anthropic-compatible clients.
- [Available models](available-models.md) — enumerate the governed routable
  model set through CLI, gRPC, or HTTP.
- [Responses harness profile](responses-harness-profile.md) — implement the
  supported request, streaming, and error contract.
- [`proto/`](../proto/) — inspect the native gRPC APIs.
- [Ontology definitions](ontology.md) — model semantic classes and relations,
  project schemas, and understand current validation boundaries.
- [Standalone ontology](../crates/sekai-ontology/README.md) — use an ontology
  library and SQLite command-line tool in a separate application.
- [External evidence adapters](../adapters/README.md) — submit evidence through
  the versioned adapter contract.
- [External-action execution evidence](external-action-execution.md) — report
  host lifecycle observations and reconcile missing terminal evidence.
- [Tenant isolation conformance](tenant-isolation-conformance.md) — run the
  reusable enterprise extension isolation suite or community negative profile.

## Configure and operate

- [Configuration](configuration.md) — core, provider, gateway, and scoring
  environment variables.
- [Operations and security](operations.md) — credentials, TLS, observability,
  backups, and deployment checks.
- [Operator console](operator-console.md) — authenticated browser shell on the
  ops listener (login, namespace context, fail-closed routes).
- [Docker](docker.md) — run the server and gateway with Docker Compose.
- [Security policy](../SECURITY.md) — supported versions and private
  vulnerability reporting.

## Understand and contribute

- [Vision](../VISION.md) — product boundary, design principles, and non-goals.
- [Contributing](../CONTRIBUTING.md) — local setup, tests, change expectations,
  and pull requests.
- [Project operating system](project-operating-system.md) — artifact decisions,
  Issue lifecycles, Skills, review roles, conventions, automation, and scaling.
- [Performance benchmarks](performance-benchmarks.md) — reproduce the sanitized
  workload baseline and interpret regression budgets.
- [Architecture decisions](decisions/README.md) — accepted, durable design
  choices and the ADR template.
- [Gunshi auto-allocation envelope](research/279-gunshi-auto-allocation-envelope.md)
- [Gunshi eval-gated promotion and bounded auto-dispatch](gunshi-auto-allocation.md)
- [Operator console information architecture](research/283-operator-console-ia.md)
- [Lookup vs model call (defer)](research/175-lookup-vs-model-call.md)
- [Governed hybrid retrieval contract](research/152-hybrid-retrieval.md)
- [Semantic pattern-query surface](research/145-semantic-pattern-query.md)
- [Federation and model-residency architecture](research/288-federation-residency-architecture.md)
- [Multi-region consistency for budgets, leases, and permits](research/292-multi-region-consistency.md)
- [Governed what-if simulation over graph projections](research/148-what-if-simulation.md)
- [Non-authoritative scenario overlay](scenario-overlay.md) — request-scoped
  hypothesis deltas and domain-neutral impact projection (#362).
- [Gateway PEP fat-decide freeze](research/163-gateway-pep-fat-decide.md)
- [Provider and data-class residency](residency-policy.md)
  — research recommendation for bounded automatic dispatch (#279 → #280).
- [Reusable Sekai PostgreSQL parity](postgres-sekai-parity.md) — complete
  tenant-free Sekai surface set, inventory evidence, and remaining runtime
  activation gates.
- [Chisei PostgreSQL parity](postgres-chisei-parity.md) — in-progress Chisei
  decision/execution inventory, proven budget/receipt surfaces, and remaining
  learning/approval/gateway work.
- [Code of conduct](../CODE_OF_CONDUCT.md) — participation standards and
  enforcement.

## Documentation conventions

- Commands are written from the repository root unless a guide says otherwise.
- `cargo run --bin sekaictl -- ...` works without installing the CLI. Examples
  may use the shorter `sekaictl ...` form after installation.
- `.env.example` is the primary local template. The configuration guide
  explains stable operator-facing settings; experimental settings may remain
  documented next to the implementation until they stabilize.
- The protocol files and implementation are authoritative when an early-stage
  API and prose documentation disagree. Please report drift as a bug.
