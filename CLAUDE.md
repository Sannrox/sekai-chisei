# Repository Guidelines

## Project Structure & Module Organization

`sekai-chisei` is a Rust 2024 crate for a local-first gRPC control plane. Source code lives in `src/`: `src/main.rs` starts the combined server, `src/bin/sekai.rs` and `src/bin/chisei.rs` start the `sekai-plane` and `chisei-plane` processes, `src/bin/sekaictl.rs` starts the operator CLI, `src/lib.rs` exports modules, `src/grpc/` implements tonic services, and `src/composition/` holds code that needs both planes. Policy, budget, routing, evaluation, pipeline, and Chisei persistence live in `crates/chisei-core` and are re-exported as `sekai_chisei::{chisei, chisei_store}`. Durable graph, audit, lineage, security, coordination, and Sekai persistence live in `crates/sekai-core` and are re-exported as `sekai_chisei::{sekai, db}`. Workspace crates include `chisei-gateway`, `chisei-core`, `chisei-provider` (re-exported as `sekai_chisei::llm`), `sekai-admin-client`, `sekai-client`, `sekai-connector-template`, `sekai-core`, `sekai-domain`, `sekai-keys`, `sekai-obs`, `sekai-ontology`, `sekai-proto`, `sekai-source-sdk`, and `sekai-types`. Protocol files live only in `proto/`; `crates/sekai-proto` compiles them from there. Integration tests live in `tests/`. Combined-mode SQLite uses dest-pair `SEKAI_DB_PATH`/`CHISEI_DB_PATH` when both are set, otherwise with no store variable `sekai.db`/`chisei.db` under `SEKAI_DATA_DIR` (default `./data`); `DB_PATH`, `DATABASE_URL`, and `SEKAI_SHARED_STORE` are retired and refuse boot with guidance toward `sekaictl admin store relocate`. Do not commit local databases or generated runtime state. `CLAUDE.md` is a compatibility copy of this file for Claude Code; keep them identical. Domain lifecycle maps live in `CONTEXT.md`.

## Build, Test, and Development Commands

Cargo is the workflow. The compiler is pinned in `rust-toolchain.toml`. Local and CI run the same commands:

```sh
cargo fmt-check
cargo clippy-all
cargo test-all
```

Aliases in `.cargo/config.toml`: `fmt-check` is `fmt --all -- --check`; `clippy-all` is `clippy --workspace --all-targets --locked -- -D warnings`; `test-all` is `test --workspace --locked`. Plain `cargo check` / `cargo test` stay the short developer loop.

`SEKAI_INSECURE=1 cargo run` reads process environment only and does not load `.env` (`sekaictl launch` does). With no store variable it opens split `sekai.db`/`chisei.db` under `SEKAI_DATA_DIR` (default `./data`); dest-pair `SEKAI_DB_PATH`/`CHISEI_DB_PATH` overrides. It binds `127.0.0.1:50051` unless `SEKAI_BIND` explicitly overrides the loopback default. Do not combine insecure mode with a non-loopback bind; the server does not reject that combination. `cargo test --test it -- --ignored ollama_e2e` runs the ignored Ollama end-to-end test when a local compatible endpoint is available.

Linux images: `./build/release-images.sh`. Push: `./build/release.sh` with
`DOCKER_REGISTRY` set.

Use `.env.example` as the configuration reference. Important variables include `GRPC_PORT`, `SEKAI_BIND`, `SEKAI_SOCKET`, `SEKAI_DATA_DIR`, `SEKAI_DB_PATH`, `CHISEI_DB_PATH`, `SEKAI_DB_BACKEND`, `SEKAI_DATABASE_URL`, `CHISEI_DATABASE_URL`, `SEKAI_INSECURE`, `SEKAI_CREDENTIAL`, `OLLAMA_URL`, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY`.

GitHub Issues are the planning source of truth. Read `docs/project-operating-system.md` for artifact routing, contribution lifecycles, review roles, and the Skills under `.agents/skills/`.

## Parallel delivery lanes

Each delivered Issue is one lane: one claim branch `<type>/<issue>` on GitHub,
one worktree at `.worktrees/issue-<issue>` (or a dedicated clone on another
machine), one Pull Request, one owner. Claims live on GitHub because lanes run
on several machines; claim with
`bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}"/skills/deliver-ready-issue/scripts/issue-lane.sh claim <issue>`
before implementing. Agents never switch, reset, or stash the primary checkout;
inspect `git status -sb` and `git worktree list` before Git or GitHub work and
preserve other lanes. Collision surfaces are `proto/`, SQLite versus
PostgreSQL migrations, gateway versus native gRPC, and the same crate or
ownership boundary; lanes that would both change one run in sequence. The
"Parallel delivery lanes" section of `docs/project-operating-system.md` defines
claims, the lane limit, release-owned shared files, and serialized Git
mutations. Each lane builds into its own worktree's
`target/` (the default; never point two lanes at one `CARGO_TARGET_DIR`), binds
test ports at `:0`, and gives PostgreSQL conformance its own database through
`scripts/postgres-conformance.sh`. `--test-threads=1` serializes tests inside one
process; it does not isolate two agents.

## Ontology Policy

For work involving portable ontology definitions, classes, relations, provenance, validation, import, export, or structural queries, always use the `sekai-ontology` Skill (`.agents/skills/sekai-ontology/` is its shared agent-kit stub).

Create or refresh a scoped portable database with `sekai setup` (or
`sekai setup --scope workspace|project|user`). Select a database explicitly
with `--db <path>` or `SEKAI_DB` when the resolved default is not the intended
file, then run `sekai --json validate` before relying on its contents. Treat
successful ontology output as structured repository evidence, preserve its
provenance in answers, and state when validation fails or the requested fact is
absent rather than inferring it. Do not use the control-plane database at
`data/sekai.db` as a portable ontology database.

Ontology classes and relations describe meaning. Directory commands record local filesystem facts (`directory init` / `directory index`) in the same portable database; those facts are not ontology classes. This repository's contributor vocabulary pack is `crates/sekai-ontology/ontologies/sekai-chisei-product-v1.json`. Import it into a throwaway `--db` when answering product-term questions; do not treat it as a built-in server ontology or as `directory init` vocabulary.

### Product vocabulary

When the pack is present, answer these from the pack, not from memory: what
Sekai and Chisei are; what the portable ontology database is and how it differs
from `data/sekai.db`; what a Receipt records; what a governed Action relates to;
and how a directory fact differs from an ontology class. Use shipping commands
only:

1. `sekai --db <tmp> init`, then
   `sekai --db <tmp> import crates/sekai-ontology/ontologies/sekai-chisei-product-v1.json`
   (a throwaway file, never `data/sekai.db`).
2. `sekai --db <tmp> --json validate`; stop if `data.valid` is not true.
3. Answer with `explain`, `query`, or `ask` and keep every provenance `source`
   and `locator`: `explain Sekai`, `explain Chisei`,
   `explain "Portable Ontology Database"`,
   `query "Portable Ontology Database" --relation distinct_from`,
   `explain Receipt`, `ask "what does Receipt record"`,
   `explain "Governed Action"`, `ask "what is related to Governed Action"`,
   `explain "Directory Fact"`, `explain "Ontology Class"`.
4. Report a missing class, relation, or provenance record as absent; do not
   infer it. The query result is the evidence; prose in `VISION.md` is not a
   substitute when the pack imported cleanly.

## Coding Style & Naming Conventions

Follow standard Rust formatting with `cargo fmt` and keep modules aligned with the existing domain boundaries. Use `snake_case` for files, modules, functions, and variables; use `PascalCase` for types and traits; use `SCREAMING_SNAKE_CASE` for constants. Keep provider-specific behavior behind `crates/chisei-provider/` abstractions (re-exported as `sekai_chisei::llm`). Prefer explicit policy, audit, and authorization behavior over hidden side effects.

## Testing Guidelines

Add focused tests for changes touching provider routing, LLM calls, authentication, persistence, migrations, or coordination behavior. Prefer deterministic tests that do not require external services. Mark service-dependent tests ignored, following `tests/ollama_e2e.rs`, and document required local services in the test or related docs.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects, often Conventional Commit style: `fix(sekai): preserve reconcile filters`, `docs: clean up OSS-readiness language`, `chore: sync proto copies`. Keep commits narrow and describe the affected subsystem when useful. Pull requests should include a concise behavior summary, tests run, linked issue or context, and any configuration or security implications. Pull requests do not edit `CHANGELOG.md`: the Conventional Commit title and the body carry the change note, with a `### Breaking` or `### Upgrade` heading and the `risk:breaking` or `risk:migration` label when needed; release prep drafts the section with `bash scripts/changelog-draft.sh <version>`. Do not put hostnames, FQDNs, home directories, absolute worktree paths, LAN or employer network names, or other private environment inventory on public Issues, Pull Requests, comments, or commit messages. Delivery and lane briefs on GitHub may list only claim branch, repo-relative worktree (for example `.worktrees/issue-N`), base SHA, and published SHA. `.agents/skills/` is tracked; do not treat it as gitignored.

### Verified commits on GitHub

Publish and land lanes with the shared agent-kit lane script so hosted commits
are GitHub-signed (**Verified**) and `main` stays linear:

1. Commit locally as usual. Never pass `--no-gpg-sign`; if GPG fails, stop and
   fix it.
2. Publish the claim branch from the lane worktree with
   `bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}/skills/deliver-ready-issue/scripts/issue-lane.sh" push <issue>`.
   It prints the Verified commit and resets the worktree to it, so local `HEAD`
   is the Pull Request head.
3. Land with
   `bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}/skills/deliver-ready-issue/scripts/issue-lane.sh" land <issue> --pr <pr>`.
   It squash-merges the reviewed head once the required checks pass.

Avoid GitHub **rebase** merges when Verified history matters: rebase-merge
rewrites commits and drops signatures. Do not rewrite protected `main` after
merging unless the user explicitly approves; if protection is temporarily
relaxed, restore force-push and status-check settings immediately after the
correction.

## Security & Configuration Tips

Never commit secrets, tokens, provider credentials, logs, or local SQLite databases. Never put hostnames, FQDNs, home directories, absolute worktree paths, LAN or employer network names, or other private environment inventory on public Issues, Pull Requests, comments, or commit messages. Use `SEKAI_INSECURE=1` only for trusted local development. For network-accessible runs, create principal-scoped credentials with `sekaictl admin access credential create <principal>` and require `authorization: Bearer <token>` on gRPC requests. `SEKAI_CREDENTIAL` is a client-side bearer input and never bootstraps server authority. Report vulnerabilities through `SECURITY.md`.

## Shared agent skills

The workflow Skills (`advance-issue-frontier`, `assess-change-impact`,
`capture-project-decision`, `deliver-ready-issue`, `prepare-release`,
`refactor-docs`, `shape-work-item`, `technical-documentation`, `verify-change`)
and the opt-in `sekai-ontology` Skill are canonical in
[Sannrox/agent-kit](https://github.com/Sannrox/agent-kit). There is no pin:
this repository always uses the latest `main`. `.agents/skills/<name>/` holds
only a generated stub that points to the shared skill; read the installed skill
under `~/.agents/agent-kit/` (or `$AGENT_KIT_HOME`). Run
`bash scripts/validate-workflow-skills.sh` to clone or update it; CI runs the
same check.

- Repository-specific facts the shared Skills need come from this file: the
  structure, parallel-lane, ontology, and testing sections, plus
  `## Agent skill profile` below for anything they do not already say. Edit
  this file, not the stubs.
- Never edit stubs or the vendored `scripts/validate-workflow-skills.sh` here;
  change them upstream in agent-kit, then run
  `bash scripts/validate-workflow-skills.sh --render` here when CI reports
  drift.
- Repository-only Skills live next to the stubs as full folders and stay local.

## Agent skill profile

Facts the shared agent-kit skills read that the sections above do not already
state. Frame work against `VISION.md` and `docs/architecture.md` as well as
`README.md`.

Feature: a new observable operator or integration outcome.

### Compatibility and failure obligations

Fresh and upgraded databases; transactional audit coupling; old clients and
configuration; error semantics; rollback and backup impact; public `proto/`,
gateway, and client compatibility.

### Additional impact boundaries

- Sekai durable facts versus Chisei governed decisions;
- gateway-compatible requests versus native gRPC execution;
- SQLite versus implemented PostgreSQL interfaces;
- provider-neutral behavior versus `crates/chisei-provider/` adapters;
- namespace authorization, egress, approval, budget, audit, lineage,
  retention, and secrets;
- public `proto/`, configuration (`.env.example`), CLI, receipt, metrics, and
  operator behavior.

### Verification matrix

Rows beyond `## Testing Guidelines`:

| Surface | Required evidence |
| --- | --- |
| gateway | deterministic `scripts/chisei_gateway_smoke.sh` |
| protocol | generated build, service/client/example coverage, compatibility review |
| persistence | fresh and upgrade behavior; SQLite/PostgreSQL alignment where implemented, PostgreSQL through `scripts/postgres-conformance.sh` |
| configuration | parsing/default tests, `.env.example`, configuration docs |
| ADRs | `sh scripts/adr-index.sh --check` |
| Skills / `AGENTS.md` | `bash scripts/validate-workflow-skills.sh`; keep `CLAUDE.md` identical to `AGENTS.md` |

Unit or mocked tests do not establish live provider, gateway transport,
persistence-upgrade, packaging, or soak behavior; use the real boundary with
isolated state, ports, and credentials, or report the check as skipped.

### Release audit

- `Cargo.toml` version, `Cargo.lock`, and `.github/workflows/release.yml`;
- public gRPC, gateway, and client compatibility (`compatibility.json` is
  generated by the release workflow);
- SQLite migrations and implemented PostgreSQL alignment;
- configuration additions, removals, defaults, and `.env.example`;
- security, backup, rollback, retention, and operator actions;
- container (`./build/release-images.sh`) and binary packaging;
- release notes drafted with `bash scripts/changelog-draft.sh <version>`,
  edited into `CHANGELOG.md`, and committed with the version bump; upgrade and
  migration actions first; contributors credited through GitHub's generated
  notes;
- no live-provider tests without intentional prerequisites.
