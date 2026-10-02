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

> **Project status:** `v1.0.0`. The ontology-first loop, SQLite persistence,
> principal credentials, policy pipeline, receipts, `sekaictl`, and core gRPC
> catalog form the stable 1.x contract. Advanced and experimental capabilities
> remain explicitly classified and require opt-in discovery.

## What it gives you

- **Ontology-first authoring:** define domain classes and relations, then seed
  typed facts and links without adding domain concepts to the core protocol.
- **Governed execution:** apply namespace access, policy, budgets, context
  egress, routing, evaluation, and approvals around plan and execution.
- **Inspectable outcomes:** retain decisions, normalized usage, lineage,
  verification, action outcomes, and provenance under a durable operation.
- **Local-first authority:** keep the stable 1.x graph and governance state in
  SQLite. PostgreSQL is a partial community backend whose supported surfaces
  are advertised at runtime and fail closed elsewhere.

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

Provider adapters, the OpenAI- and Anthropic-compatible gateway, evaluation
plans, advanced retrieval, federation administration, and automated allocation
extend the platform. They are advanced or experimental capabilities, not the
stable product definition.

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

Start Combined in one terminal. `cargo run` reads the process environment
only; it does not load `.env` (`sekaictl launch` does). Export the dest-pair
from [`.env.example`](.env.example):

```bash
SEKAI_INSECURE=1 SEKAI_DB_PATH=./data/sekai.db CHISEI_DB_PATH=./data/chisei.db cargo run
```

A single `DB_PATH` is refused unless `SEKAI_SHARED_STORE=1`. To run the planes
as separate processes, see
[two-plane processes](docs/two-plane-processes.md).

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

## What works today

- SQLite-backed typed-object graph with schemas, links, and datasets, plus
  optional `SEKAI_DB_BACKEND=postgres` for the reusable community surface (no
  tenant/OIDC). Virtual-table RPCs are experimental (`SEKAI_EXPERIMENTAL_RPCS=1`);
- namespace-first access control, audit, lineage, and retention primitives;
- work-unit admission, heartbeat, completion, and reconciliation (experimental
  RPCs; `SEKAI_EXPERIMENTAL_RPCS=1`);
- policy resolution, context enrichment, budgets, model routing, and
  evaluation gates;
- governed actions with dry runs, risk classes, and blast-radius limits (no
  public Action approval RPC);
- OpenAI Responses and Chat Completions compatibility;
- Anthropic Messages compatibility;
- native governed execution and streaming gRPC APIs;
- usage receipts, Prometheus metrics, health probes, and gateway reports; and
- external evidence adapters with retained source attribution.

The capability catalog returns only `core` entries by default; request
`product_tier_filter=all`, `advanced`, or `experimental` explicitly to expand
it. Core contracts are namespace-first and domain-neutral: namespaces, actors,
operations, attempts, actions, artifacts, verification, and outcomes. Domain
objects such as repositories, incidents, campaigns, or support tickets belong
in schemas and adapters rather than the core ontology.

For feature tiers and discovery details, see [Public RPC maturity](docs/rpc-maturity.md)
and the [capability catalogs](docs/capability-catalog.md).

## Next steps

Use the [documentation index](docs/README.md) to choose a guide by task.

- Try the [reference lookup-first domain pack](docs/ontology.md#reference-lookup-first-domain-pack).
- Connect Codex, Claude Code, or another supported client through the
  [compatibility gateway](docs/gateway.md#guided-launch).
- Use the standalone [local `sekai` ontology tool](crates/sekai-ontology/README.md)
  for portable ontology databases.
- Run a [domain-neutral example](examples/README.md) or read
  [CONTRIBUTING.md](CONTRIBUTING.md) to develop and test the project.

## Security

Report vulnerabilities privately using the process in
[SECURITY.md](SECURITY.md). Never commit credentials, tokens, local databases,
logs, or private keys.

For usage questions, reproducible bugs, and feature proposals, follow
[SUPPORT.md](SUPPORT.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
