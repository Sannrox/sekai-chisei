# sekai-chisei

`sekai-chisei` is a local-first Rust control plane for AI-assisted software delivery.

It combines:

- `sekai`: a durable graph and dataset layer for typed objects and links, lineage, access control, audit history, coordination, and operational memory
- `chisei`: a policy and decision layer for budget checks, model/runtime selection, request enrichment, evaluation gates, and learning loops
- `llm`: provider adapters for OpenAI, Anthropic, Ollama-compatible endpoints, and native local LLM services

The goal is to make AI execution less like isolated prompt calls and more like an inspectable system for policy-governed engineering work.

## Status

This project is early-stage. The current implementation exposes a gRPC server backed by SQLite and is intended for local development, experimentation, and integration work.

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

## Run Locally

For local development, run the server in localhost-only insecure mode:

```bash
SEKAI_INSECURE=1 cargo run
```

By default the service listens on `127.0.0.1:50051` and stores SQLite data at `./data/sekai.db`.

For authenticated mode, set `SEKAI_AUTH_TOKEN`:

```bash
SEKAI_AUTH_TOKEN=change-me cargo run
```

When `SEKAI_AUTH_TOKEN` is set, the server binds to `0.0.0.0` and requires `authorization: Bearer <token>` metadata on gRPC requests.

## Configuration

Configuration is read from environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `GRPC_PORT` | `50051` | gRPC listen port |
| `DB_PATH` | `./data/sekai.db` | SQLite database path |
| `SEKAI_AUTH_TOKEN` | unset | Enables authenticated mode |
| `SEKAI_INSECURE` | unset | Set to `1` for local unauthenticated development |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama-compatible endpoint |
| `NATIVE_LLM_URL` | unset | Native local LLM endpoint |
| `OPENAI_API_KEY` | unset | OpenAI API key |
| `ANTHROPIC_API_KEY` | unset | Anthropic API key |

See [.env.example](.env.example) for a local template.

## Development

Run tests:

```bash
cargo test
```

Build an optimized binary:

```bash
cargo build --release
```

### Examples

[examples/](examples/) contains runnable demo clients. The `demo_client` example
builds a small typed-object graph in `sekai` and drives the `chisei` budget and
decision pipeline end-to-end:

```bash
cargo run --example demo_client
```

See [examples/README.md](examples/README.md) for details and configuration.

Run the ignored Ollama end-to-end test only when a local Ollama server and model are available:

```bash
cargo test --test ollama_e2e -- --ignored
```

## Project Layout

- [proto/](proto/) contains the gRPC service definitions
- [src/grpc/](src/grpc/) contains the tonic service implementations
- [src/sekai/](src/sekai/) contains graph, dataset, audit, lineage, coordination, security, and work-unit primitives
- [src/chisei/](src/chisei/) contains policy, budget, pipeline, evaluation, evolution, and model-routing logic
- [src/llm/](src/llm/) contains LLM provider adapters
- [VISION.md](VISION.md) describes the long-term product direction

## Security

Do not expose `SEKAI_INSECURE=1` outside a trusted local development environment. Use `SEKAI_AUTH_TOKEN` for any network-accessible deployment.

Report security issues using the process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
