# Repository Guidelines

## Project Structure & Module Organization

`sekai-chisei` is a Rust 2024 crate for a local-first gRPC control plane. Source code lives in `src/`: `src/main.rs` starts the server, `src/lib.rs` exports modules, `src/grpc/` implements tonic services, `src/db/` handles SQLite access, `src/sekai/` contains durable graph, audit, lineage, security, and coordination primitives, `src/chisei/` contains policy, budget, routing, evaluation, and pipeline logic, and `src/llm/` contains provider adapters. Protocol definitions are in `proto/`. Integration tests live in `tests/`. Runtime SQLite data defaults to `data/sekai.db`; do not commit local databases or generated runtime state.

## Build, Test, and Development Commands

- `cargo fmt` formats Rust code before review.
- `cargo test` runs the normal unit and integration test suite.
- `SEKAI_INSECURE=1 cargo run` starts the local development server on `127.0.0.1:50051`.
- `cargo build --release` builds an optimized binary.
- `cargo test --test ollama_e2e -- --ignored` runs the ignored Ollama end-to-end test when a local compatible endpoint is available.

Use `.env.example` as the configuration reference. Important variables include `GRPC_PORT`, `DB_PATH`, `SEKAI_INSECURE`, `SEKAI_AUTH_TOKEN`, `OLLAMA_URL`, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY`.

## Coding Style & Naming Conventions

Follow standard Rust formatting with `cargo fmt` and keep modules aligned with the existing domain boundaries. Use `snake_case` for files, modules, functions, and variables; use `PascalCase` for types and traits; use `SCREAMING_SNAKE_CASE` for constants. Keep provider-specific behavior behind `src/llm/` abstractions. Prefer explicit policy, audit, and authorization behavior over hidden side effects.

## Testing Guidelines

Add focused tests for changes touching provider routing, LLM calls, authentication, persistence, migrations, or coordination behavior. Prefer deterministic tests that do not require external services. Mark service-dependent tests ignored, following `tests/ollama_e2e.rs`, and document required local services in the test or related docs.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects, often Conventional Commit style: `fix(sekai): preserve reconcile filters`, `docs: clean up OSS-readiness language`, `chore: remove .agents from git tracking`. Keep commits narrow and describe the affected subsystem when useful. Pull requests should include a concise behavior summary, tests run, linked issue or context, and any configuration or security implications.

## Security & Configuration Tips

Never commit secrets, tokens, provider credentials, logs, or local SQLite databases. Use `SEKAI_INSECURE=1` only for trusted local development. For network-accessible runs, set `SEKAI_AUTH_TOKEN` and require `authorization: Bearer <token>` metadata on gRPC requests. Report vulnerabilities through `SECURITY.md`.
