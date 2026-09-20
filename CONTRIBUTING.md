# Contributing

Thanks for helping improve `sekai-chisei`. The 1.x core contract is stable, so
focused changes with clear behavior, tests, and migration impact are easier to
review than broad rewrites. Experimental surfaces must remain explicitly
classified and opt-in.

All participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).
For usage questions that do not yet require a code change, use the channels in
[SUPPORT.md](SUPPORT.md).

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

1. Install the compiler pinned in `rust-toolchain.toml` (Rust 2024 edition).
2. Clone the repository.
3. Copy `.env.example` to `.env` if you need local overrides. Combined
   `cargo run` does not load `.env`; export `SEKAI_DB_PATH` and
   `CHISEI_DB_PATH` (or `SEKAI_SHARED_STORE=1` for a single file). See
   [configuration](docs/configuration.md).
4. Run the standard checks:

```bash
cargo fmt-check
cargo clippy-all
cargo test-all
```

Those aliases in `.cargo/config.toml` are what CI runs: `fmt --all -- --check`,
`clippy --workspace --all-targets --locked -- -D warnings`, and
`test --workspace --locked`.

Start a trusted local Combined server with the dest-pair:

```bash
SEKAI_INSECURE=1 SEKAI_DB_PATH=./data/sekai.db CHISEI_DB_PATH=./data/chisei.db cargo run
```

Separate `sekai-plane` and `chisei-plane` processes are documented in
[two-plane processes](docs/two-plane-processes.md).

Each delivered Issue is one lane: claim with
`bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh claim <issue>`
before implementing, then work in `.worktrees/issue-<issue>`. See
[Parallel delivery lanes](docs/project-operating-system.md#parallel-delivery-lanes).

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
- Run `cargo test --test native_server_smoke --locked` for native control-plane
  process smoke. It spawns the compiled `sekai-chisei` binary, a loopback
  OpenAI-compatible fake for Ollama, and drives `sekaictl` plus public gRPC
  over a temp Unix socket. It does not require live provider credentials.
- Run `cargo test --test gateway_http_smoke --locked` for gateway HTTP process
  smoke. It spawns `sekai-chisei`, `chisei-gateway`, and a loopback OpenAI/
  Anthropic fake, then hits health/readiness, missing and wrong keys,
  disallowed models, `/v1/responses`, `/v1/chat/completions`, `/v1/messages`
  (including streams), `/v1/models`, and fail-closed when the control plane is
  down. It does not require live provider credentials.

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

- update the relevant file under `proto/` and keep
  `crates/sekai-proto/proto/` in byte-for-byte sync (the crate build fails if
  they differ);
- update the service implementation and client/example call sites;
- add compatibility or migration notes when behavior changes; and
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

Do not put hostnames, home directories, absolute worktree paths, or other
private environment details in public pull request or issue text. Delivery
briefs on GitHub may list only claim branch, repo-relative worktree (for
example `.worktrees/issue-N`), base SHA, and published SHA.

Close the primary Issue with a GitHub closing keyword when applicable. Disclose
AI assistance, confirm that the submitting author understands the change, and
state the actual testing level. AI-assisted changes are reviewed by the same
behavioral, security, and maintainability standards as human-only changes.

Before requesting review, run:

```bash
cargo fmt-check
cargo clippy-all
cargo test-all
```

Maintainers normally squash-merge PRs (`gh pr merge --squash --delete-branch`)
so the land commit on `main` is GitHub-signed/Verified and history stays linear.
Use a merge commit only when multi-commit history must be preserved. Avoid
GitHub rebase-merge when Verified history matters: rebase rewrites commits and
drops signatures. See `AGENTS.md` for the verified-push workflow.

## License

By contributing, you agree that your contribution is licensed under the
project's [Apache-2.0 license](LICENSE).
