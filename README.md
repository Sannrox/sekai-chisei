# sekai-chisei

`sekai-chisei` is a local-first Rust control plane for AI-assisted software delivery.

Most agent systems treat LLM calls as isolated events. `sekai-chisei` treats them as
governed operations: context-aware, policy-constrained, budget-tracked, auditable, and
measurable against a baseline.

It combines:

- `sekai`: a durable graph and dataset layer for typed objects and links, lineage, access control, audit history, coordination, and operational memory
- `chisei`: a policy and decision layer for budget checks, model/runtime selection, request enrichment, evaluation gates, and learning loops
- `llm`: provider adapters for OpenAI, Anthropic, Ollama-compatible endpoints, and native local LLM services

## Quickstart

```bash
git clone https://github.com/Sannrox/sekai-chisei.git
cd sekai-chisei
SEKAI_INSECURE=1 cargo run
```

The server starts on `127.0.0.1:50051` with SQLite at `./data/sekai.db`.

In a second terminal, run the end-to-end demo — it creates a typed-object graph in
`sekai` and drives the `chisei` budget and decision pipeline:

```bash
cargo run --example demo_client
```

To connect a real LLM provider, copy `.env.example` to `.env` and add your key:

```bash
cp .env.example .env
# set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env
SEKAI_INSECURE=1 cargo run
```

See [examples/README.md](examples/README.md) for what the demo exercises.

## Status

Early-stage (`v0.1.0`). The gRPC server, SQLite-backed graph, and chisei policy
pipeline are working. APIs will evolve before v1.0.

## Features

- SQLite-backed typed-object graph with generic objects, links, and schema definitions
- gRPC APIs for `sekai` and `chisei`
- Dataset, lineage, audit, access control, action, and coordination primitives
- Work-unit coordination with admission, heartbeat, completion, and reconciliation
- Chisei pipeline for policy resolution, request enrichment, budget checks, model routing, and eval regression checks
- Provider routing for OpenAI, Anthropic, Ollama-compatible, and native endpoints
- Local-first operation with explicit insecure mode for development

## Requirements

- Rust toolchain with edition 2024 support
- macOS, Linux, or another platform supported by Rust and SQLite
- Optional: local Ollama or compatible endpoint at `http://localhost:11434`

`protoc` is provided through the vendored build dependency.

## Configuration

Configuration is read from environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `GRPC_PORT` | `50051` | gRPC listen port |
| `DB_PATH` | `./data/sekai.db` | SQLite database path |
| `SEKAI_AUTH_TOKEN` | unset | Enables authenticated mode — binds to `0.0.0.0`, requires `authorization: Bearer <token>` |
| `SEKAI_INSECURE` | unset | Set to `1` for local unauthenticated development |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama-compatible endpoint |
| `NATIVE_LLM_URL` | unset | Native local LLM endpoint |
| `OPENAI_API_KEY` | unset | OpenAI API key |
| `ANTHROPIC_API_KEY` | unset | Anthropic API key |

See [.env.example](.env.example) for a local template.

## Development

```bash
cargo test                        # run all tests
cargo build --release             # optimized binary
cargo run --example demo_client   # end-to-end demo
```

Run the Ollama end-to-end test only when a local Ollama server and model are available:

```bash
cargo test --test ollama_e2e -- --ignored
```

## Project Layout

- [proto/](proto/) — gRPC service definitions
- [src/grpc/](src/grpc/) — tonic service implementations
- [src/sekai/](src/sekai/) — graph, dataset, audit, lineage, coordination, security, work-unit primitives
- [src/chisei/](src/chisei/) — policy, budget, pipeline, evaluation, evolution, model-routing
- [src/llm/](src/llm/) — LLM provider adapters
- [VISION.md](VISION.md) — long-term product direction

## Security

Do not expose `SEKAI_INSECURE=1` outside a trusted local development environment.

Report security issues using the process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
