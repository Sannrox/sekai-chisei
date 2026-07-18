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
- [Responses harness profile](responses-harness-profile.md) — implement the
  supported request, streaming, and error contract.
- [`proto/`](../proto/) — inspect the native gRPC APIs.
- [External evidence adapters](../adapters/README.md) — submit evidence through
  the versioned adapter contract.

## Configure and operate

- [Configuration](configuration.md) — core, provider, gateway, and scoring
  environment variables.
- [Operations and security](operations.md) — credentials, TLS, observability,
  backups, and deployment checks.
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
