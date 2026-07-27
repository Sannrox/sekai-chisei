# sekai-chisei

`sekai-chisei` is a local-first Rust control plane for governed agent
operations. It puts policy, budgets, audit, evaluation, and durable operational
context around model calls and agent actions without replacing the agent
runtime.

> **Project status:** early-stage (`v0.1.0`). The core server, local graph,
> policy pipeline, compatible gateway, and native execution APIs work today.
> Public APIs may change before v1.0.

## Why sekai-chisei?

Most agent systems treat model calls as isolated events. `sekai-chisei` treats
them as governed operations that can answer:

- which actor, policy, model, runtime, and budget applied;
- what context crossed a provider boundary;
- which actions required approval or were denied;
- what usage, verification, and outcome evidence was recorded; and
- what the system may safely learn for the next operation.

The project has three implementation layers:

- **Sekai** stores durable facts: typed objects and links, lineage, access
  control, audit history, coordination, and operational memory.
- **Chisei** makes governed decisions about context, policy, budgets,
  approvals, routing, evaluation, and learning.
- **LLM adapters** execute calls against OpenAI, Anthropic, Ollama-compatible,
  and native endpoints. They are not the policy boundary.

Existing OpenAI- and Anthropic-compatible clients enter through the HTTP
gateway. Native integrations use the gRPC `PlanExecution` and `ExecutePlan`
APIs. Both paths use the same control plane.

## Quick start

### Prerequisites

- a recent Rust toolchain with Rust 2024 edition support;
- macOS, Linux, or another platform supported by Rust and SQLite; and
- Codex or Claude Code for the guided client launch, or a provider endpoint for
  direct API use.

`protoc` is supplied by a vendored build dependency.

### Connect an existing agent

```bash
git clone https://github.com/Sannrox/sekai-chisei.git
cd sekai-chisei
cp .env.example .env
cargo run --bin sekaictl -- doctor codex-app
cargo run --bin sekaictl -- launch codex-app
```

The `.env` file is optional. Add `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` when
the gateway should own provider credentials. The launcher can also use a
supported client subscription passthrough path.

`launch` creates local state, runs migrations, generates a private credential,
binds local-only endpoints, validates the client/provider contract, seeds
policy and budget state, and opens the client. It does not require insecure
mode.

For Claude Code, replace `codex-app` with `claude-code`. See the
[gateway and client guide](docs/gateway.md) for upstream modes, model routing,
manual setup, and security boundaries.

### Run the control plane directly

For trusted local development:

```bash
cp .env.example .env
SEKAI_INSECURE=1 cargo run
```

The defaults expose:

- local gRPC over `./data/sekai.sock`;
- local TCP gRPC on `127.0.0.1:50051`; and
- health and Prometheus endpoints on `127.0.0.1:9464`.

Do not use `SEKAI_INSECURE=1` outside a trusted local environment. Read the
[operations and security guide](docs/operations.md) before binding to a
network-accessible interface.

### Verify the installation

```bash
cargo test --locked
curl --fail http://127.0.0.1:9464/healthz
```

With a gateway-owned OpenAI credential, run a deterministic provider check:

```bash
cargo run --bin sekaictl -- smoke gpt-5.5
```

The output includes the operation ID, policy result, normalized usage, receipt
location, and an inspection command:

```bash
cargo run --bin sekaictl -- receipt <operation_id>
```

### Local ontology tool

The `sekai` CLI is a standalone tool for portable ontology databases. It does
not require the control-plane server or network access.

Install it:

```bash
cargo install --path crates/sekai-ontology
```

The database is resolved in this order (first match wins):

1. `--db <path>` (explicit flag)
2. `SEKAI_DB` environment variable
3. User-level default (if the file exists):
   - macOS: `~/Library/Application Support/sekai/knowledge.db`
   - Linux: `${XDG_DATA_HOME:-~/.local/share}/sekai/knowledge.db`
4. `knowledge.db` in the current directory

Create and use an ontology:

```bash
sekai init                          # creates knowledge.db (see resolution order)
sekai import definitions.json       # import classes and relations
sekai validate                      # check structural integrity
sekai --json explain SomeClass      # definition, closure, provenance
sekai --json query SomeClass --direction outbound --depth 2
```

Do not use the control-plane database (`data/sekai.db`) as a portable ontology
database. See the [sekai-ontology crate](crates/sekai-ontology/) for library
usage.

## What is implemented

- SQLite-backed typed-object graph with schemas, links, datasets, and virtual
  tables, plus optional `SEKAI_DB_BACKEND=postgres` for the reusable community
  surface (no tenant/OIDC);
- namespace-first access control, audit, lineage, and retention primitives;
- work-unit admission, heartbeat, completion, and reconciliation;
- policy resolution, context enrichment, budgets, model routing, and
  evaluation gates;
- governed actions with dry runs, approval holds, risk classes, and
  blast-radius limits;
- OpenAI Responses and Chat Completions compatibility;
- Anthropic Messages compatibility;
- native governed execution and streaming gRPC APIs;
- usage receipts, Prometheus metrics, health probes, and gateway reports; and
- external evidence adapters with retained source attribution.

Core contracts are namespace-first and domain-neutral: namespaces, actors,
operations, attempts, actions, artifacts, verification, and outcomes. Domain
objects such as repositories, incidents, campaigns, or support tickets belong
in schemas and adapters rather than the core ontology.

## Documentation

Start with the [documentation index](docs/README.md), or go directly to:

- [Architecture](docs/architecture.md) — boundaries, data model, and governed
  entry paths;
- [Gateway and clients](docs/gateway.md) — Codex, Claude Code, provider routing,
  authentication modes, and smoke checks;
- [Configuration](docs/configuration.md) — environment variables and defaults;
- [Operations and security](docs/operations.md) — transport, credentials,
  observability, backups, and production checks;
- [Docker](docs/docker.md) — container quick start and transport choices;
- [Examples](examples/README.md) — runnable, domain-neutral examples;
- [Vision](VISION.md) — product direction and non-goals; and
- [Contributing](CONTRIBUTING.md) — development workflow and review
  expectations;
- [Project operating system](docs/project-operating-system.md) — how Issues,
  Discussions, pull requests, documentation, and Skills fit together; and
- [Code of conduct](CODE_OF_CONDUCT.md) — community standards and enforcement.

The gRPC contract is defined in [`proto/`](proto/). The
[`responses-harness-profile`](docs/responses-harness-profile.md) documents the
supported Responses harness contract.

## Development

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Run an end-to-end example against a local server:

```bash
SEKAI_INSECURE=1 cargo run
# in another terminal
cargo run --example demo_client
```

The ignored Ollama test requires a local compatible endpoint and model:

```bash
cargo test --test ollama_e2e -- --ignored
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Project layout

| Path | Responsibility |
| --- | --- |
| [`proto/`](proto/) | Public gRPC service definitions |
| [`src/grpc/`](src/grpc/) | Tonic services and transport boundary |
| [`src/sekai/`](src/sekai/) | Graph, audit, lineage, security, coordination, and memory |
| [`src/chisei/`](src/chisei/) | Policy, budgets, routing, evaluation, and learning |
| [`crates/sekai-provider/`](crates/sekai-provider/) | Provider registry, adapters, pricing, and shared receipt contracts |
| [`crates/chisei-gateway/`](crates/chisei-gateway/) | Standalone compatible HTTP gateway |
| [`adapters/`](adapters/) | External evidence reference adapters |
| [`examples/`](examples/) | Runnable integration examples |
| [`tests/`](tests/) | Integration tests and deterministic fixtures |

## Security

Report vulnerabilities privately using the process in
[SECURITY.md](SECURITY.md). Never commit credentials, tokens, local databases,
logs, or private keys.

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE).
