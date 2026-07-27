# Contributing

Thanks for helping improve `sekai-chisei`. The project is pre-1.0, so focused
changes with clear behavior, tests, and migration impact are easier to review
than broad rewrites.

All participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Before you start

- Search existing issues and pull requests before proposing overlapping work.
- Open an Issue for features, public APIs, persistence, security policy, and
  architecture changes before investing in implementation.
- Start a GitHub Design Discussion when a choice crosses the Sekai/Chisei
  boundary, changes the namespace or trust model, alters a difficult-to-reverse
  public contract, or has multiple credible approaches.
- Report exploitable vulnerabilities privately through [SECURITY.md](SECURITY.md),
  not in a public issue or pull request.

Use the Bug, Feature, Refactoring, or Research form. Issues are the planning
artifact; do not add plan documents to the repository. The
[project operating system](docs/project-operating-system.md) defines the full
lifecycle, label taxonomy, artifact decision rules, and repository Skills.

## Development setup

1. Install a recent stable Rust toolchain with Rust 2024 edition support.
2. Clone the repository.
3. Copy `.env.example` to `.env` if you need local overrides.
4. Run the standard checks:

```bash
cargo build --locked
cargo test --locked
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Start a trusted local server with:

```bash
SEKAI_INSECURE=1 cargo run
```

The build vendors `protoc`; a system installation is not required.

## Choosing the right test

- Add deterministic unit tests beside the module for pure policy, parsing,
  validation, and persistence behavior.
- Add integration tests under `tests/` for public service or multi-component
  behavior.
- Use deterministic fixtures for provider wire formats and streaming events.
- Keep tests that require real provider services ignored, following
  `tests/ollama_e2e.rs`, and document their prerequisites.
- Run `scripts/chisei_gateway_smoke.sh` for gateway changes. It uses fake
  upstreams and does not require provider credentials.

Changes to provider routing, LLM calls, authentication, authorization,
persistence, migrations, evidence, retention, or coordination require focused
tests for the affected path.

## Design expectations

- Keep the control plane local-first and inspectable.
- Use namespace as the isolation and policy boundary; do not introduce a
  separate application scope.
- Keep domain concepts in schemas and adapters rather than the core ontology.
- Put provider-specific behavior behind `crates/sekai-provider/` abstractions
  (re-exported as `sekai_chisei::llm`).
- Prefer explicit policy, audit, approval, and authorization behavior over
  hidden side effects.
- Preserve transaction boundaries when a mutation and its audit record must
  succeed or fail together.
- Never log or persist raw credentials, tokens, cookies, or private keys.

Read [docs/architecture.md](docs/architecture.md) and [VISION.md](VISION.md)
before changing a core boundary.

## Protocol and persistence changes

For a public gRPC change:

- update the relevant file under `proto/`;
- update the service implementation and client/example call sites;
- add backward-compatibility or migration notes when behavior changes; and
- test authorization, validation, and error semantics, not only the happy path.

For a database change:

- make migrations safe for existing data;
- keep SQLite and PostgreSQL behavior aligned where both backends implement the
  feature;
- test a fresh database and an upgraded database; and
- document backup, retention, or operator impact when applicable.

## Documentation changes

- Keep the root README focused on orientation and first success.
- Put task guides and stable reference material under `docs/` and link them
  from `docs/README.md`.
- Verify commands from the repository root.
- Use relative links so documentation works on GitHub and in local clones.
- Update `.env.example` and `docs/configuration.md` together for stable,
  operator-facing configuration.

## Pull requests

Keep commits narrow and use short imperative subjects, optionally in
Conventional Commit style, for example `fix(sekai): preserve reconcile filters`.

A pull request should include:

- the behavior or problem being changed;
- the approach and important tradeoffs;
- tests and checks run;
- configuration, migration, compatibility, and security implications; and
- a linked issue or context when one exists.

Close the primary Issue with a GitHub closing keyword when applicable. Disclose
AI assistance, confirm that the submitting author understands the change, and
state the actual testing level. AI-assisted changes are reviewed by the same
behavioral, security, and maintainability standards as human-only changes.

Before requesting review, run:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Maintainers normally squash-merge PRs (`gh pr merge --squash --delete-branch`)
so the land commit on `main` is GitHub-signed/Verified and history stays linear.
Use a merge commit only when multi-commit history must be preserved. Avoid
GitHub rebase-merge when Verified history matters: rebase rewrites commits and
drops signatures. See `AGENTS.md` for the verified-push workflow.

## License

By contributing, you agree that your contribution is licensed under the
project's [AGPL-3.0-only license](LICENSE).
