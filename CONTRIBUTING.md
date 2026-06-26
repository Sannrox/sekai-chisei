# Contributing

Thanks for your interest in `sekai-chisei`.

## Development Setup

1. Install a recent Rust toolchain with edition 2024 support.
2. Clone the repository.
3. Run `cargo test`.
4. Run `SEKAI_INSECURE=1 cargo run` for local development.

## Before Opening A Change

Please run:

```bash
cargo fmt
cargo test
```

If your change touches provider routing, LLM calls, auth, persistence, or coordination behavior, include focused tests for the affected path.

## Design Expectations

- Keep the service local-first and inspectable.
- Prefer explicit policy and audit behavior over hidden side effects.
- Keep provider-specific code behind the provider abstraction.
- Treat `sekai` as durable operational memory and `chisei` as the decision layer above it.

## Security

Do not commit secrets, local databases, logs, tokens, or provider credentials. Use environment variables and `.env.example` for documented configuration only.
