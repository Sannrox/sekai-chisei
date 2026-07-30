# sekai-chisei

> Define the world your agents operate in. Govern what they do. Keep the
> receipt.

`sekai-chisei` is a local-first Rust control plane for governed agent
operations. Define a domain ontology, store governed facts under that model,
run plan and execution inside policy and budget, and inspect the resulting
receipt.

Operators use `sekaictl`; agents and SDKs use the same core gRPC and capability
catalog interfaces. The control plane owns durable facts and the decisions that
constrain an operation. It does not replace the agent runtime.

> **Project status:** early-stage (`v0.2.1`). The core server, local graph,
> ontology-first product loop, policy pipeline, receipts, and native execution
> APIs work today. Public APIs may change before v1.0.

## What it gives you

- **Ontology-first authoring:** define domain classes and relations, then seed
  typed facts and links without adding domain concepts to the core protocol.
- **Governed execution:** apply namespace access, policy, budgets, context
  egress, routing, evaluation, and approvals around plan and execution.
- **Inspectable outcomes:** retain decisions, normalized usage, lineage,
  verification, action outcomes, and provenance under a durable operation.
- **Local-first authority:** keep the graph and governance state in SQLite, or
  use the supported PostgreSQL community surface where shared durability is
  required.

The core product loop is deliberately small:

```text
define ontology
  → seed governed facts
  → plan / execute under policy and budget
  → inspect receipt and provenance
```

## How it fits

- **Sekai** stores durable facts: typed objects and links, lineage, access
  control, audit history, coordination, and operational memory.
- **Chisei** makes governed decisions about context, policy, budgets,
  approvals, routing, evaluation, and learning.
- **Product interfaces** expose the same core loop to operators through
  `sekaictl` and to agents through gRPC and the capability catalog.

Provider adapters, the OpenAI- and Anthropic-compatible gateway, advanced
retrieval, federation administration, and automated allocation extend the
platform. They are useful integration or operational capabilities, not the
product definition.

## Quick start

### Prerequisites

- a recent Rust toolchain with Rust 2024 edition support;
- macOS, Linux, or another platform supported by Rust and SQLite.

`protoc` is supplied by a vendored build dependency.

### Run the ontology-first product loop

```bash
git clone https://github.com/Sannrox/sekai-chisei.git
cd sekai-chisei
cp .env.example .env
```

Start the control plane in one terminal:

```bash
SEKAI_INSECURE=1 cargo run
```

In another terminal, define a small service domain, seed facts, run a governed
lookup, and receive a receipt hint:

```bash
cargo run --bin sekaictl -- ontology first-run \
  --domain tests/fixtures/product_loop/domain-v1.json \
  --seed tests/fixtures/product_loop/seed-v1.json \
  --resolve-object svc-api
```

This lookup-first path requires no external model. The fixture files are
domain-neutral examples; your domain concepts live in your own ontology and
seed documents. Continue with the [ontology guide](docs/ontology.md) for
separate apply, seed, run, and receipt commands.

Verify the service and repository:

```bash
cargo test --locked
curl --fail http://127.0.0.1:9464/healthz
```

`SEKAI_INSECURE=1` is only for trusted local development. Read the
[operations and security guide](docs/operations.md) before binding to a
network-accessible interface.

### Optional: connect an existing client

The compatibility gateway lets Codex, Claude Code, and OpenAI- or
Anthropic-compatible clients use the same control plane:

```bash
cargo run --bin sekaictl -- doctor codex-app
cargo run --bin sekaictl -- launch codex-app
```

For Claude Code, replace `codex-app` with `claude-code`. Add
`OPENAI_API_KEY` or `ANTHROPIC_API_KEY` when the gateway should own provider
credentials; supported client-subscription passthrough paths are also
available.

See [Gateway and clients](docs/gateway.md) for routing, upstream modes, manual
setup, smoke checks, and security boundaries.

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

## What works today

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

- [Ontology](docs/ontology.md) — define a domain, seed governed facts, run an
  operation, and inspect its receipt;
- [Architecture](docs/architecture.md) — control-plane boundaries, data model,
  and governed entry paths;
- [Configuration](docs/configuration.md) — environment variables and defaults;
- [Operations and security](docs/operations.md) — transport, credentials,
  observability, backups, and production checks;
- [Examples](examples/README.md) — runnable, domain-neutral examples;
- [Gateway and clients](docs/gateway.md) — optional compatibility integration
  for Codex, Claude Code, and provider-compatible clients;
- [Docker](docs/docker.md) — container quick start and transport choices;
- [Vision](VISION.md) — product direction and non-goals; and
- [Changelog](CHANGELOG.md) — release changes and required migrations;
- [Contributing](CONTRIBUTING.md) — development workflow and review
  expectations;
- [Support](SUPPORT.md) — questions, bug reports, design proposals, and private
  security reporting;
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

For usage questions, reproducible bugs, and feature proposals, follow
[SUPPORT.md](SUPPORT.md).

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE).
