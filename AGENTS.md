# Repository Guidelines

## Project Structure & Module Organization

`sekai-chisei` is a Rust 2024 crate for a local-first gRPC control plane. Source code lives in `src/`: `src/main.rs` starts the server, `src/lib.rs` exports modules, `src/grpc/` implements tonic services, `src/db/` handles SQLite and PostgreSQL community backends (`SEKAI_DB_BACKEND`), `src/sekai/` contains durable graph, audit, lineage, security, and coordination primitives, and `src/chisei/` contains policy, budget, routing, evaluation, and pipeline logic. Workspace crates include `chisei-gateway`, `sekai-proto`, `sekai-provider` (re-exported as `sekai_chisei::llm`), `sekai-admin-client`, `sekai-client`, and `sekai-ontology`. Canonical protocol files are in `proto/`; keep `crates/sekai-proto/proto/` in byte-for-byte sync. Integration tests live in `tests/`. Runtime SQLite data defaults to `data/sekai.db`; do not commit local databases or generated runtime state. `CLAUDE.md` is a symlink to this file. Domain lifecycle maps live in `CONTEXT.md`.

## Build, Test, and Development Commands

- `cargo fmt` formats Rust code before review.
- `cargo test` runs the normal unit and integration test suite.
- `SEKAI_INSECURE=1 cargo run` starts the local development server on `127.0.0.1:50051` unless `SEKAI_BIND` explicitly overrides the loopback default. Do not combine insecure mode with a non-loopback bind; the server does not reject that combination.
- `cargo build --release` builds an optimized binary.
- `cargo test --test ollama_e2e -- --ignored` runs the ignored Ollama end-to-end test when a local compatible endpoint is available.

Use `.env.example` as the configuration reference. Important variables include `GRPC_PORT`, `SEKAI_BIND`, `SEKAI_SOCKET`, `DB_PATH`, `SEKAI_DB_BACKEND`, `DATABASE_URL`, `SEKAI_INSECURE`, `SEKAI_CREDENTIAL`, `OLLAMA_URL`, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY`.

GitHub Issues are the planning source of truth. Read `docs/project-operating-system.md` for artifact routing, contribution lifecycles, review roles, and project-specific Skills under `.agents/skills/`.

Each delivered Issue is one lane: one claim branch `<type>/<issue>` on GitHub,
one worktree at `.worktrees/issue-<issue>` (or a dedicated clone on another
machine), one Pull Request, one owner. Claims live on GitHub because lanes run
on several machines; claim with
`bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh claim <issue>` before
implementing. Agents never switch, reset, or stash the primary checkout;
inspect `git status -sb` and `git worktree list` before Git or GitHub work and
preserve other lanes. The "Parallel delivery lanes" section of
`docs/project-operating-system.md` defines claims, the lane limit, collision
surfaces, and serialized Git mutations.

## Ontology Policy

For work involving portable ontology definitions, classes, relations, provenance, validation, import, export, or structural queries, always use the project-local `sekai-ontology` Skill in `.agents/skills/sekai-ontology/`.

Create or refresh a scoped portable database with `sekai setup` (or
`sekai setup --scope workspace|project|user`). Select a database explicitly
with `--db <path>` or `SEKAI_DB` when the resolved default is not the intended
file, then run `sekai --json validate` before relying on its contents. Treat
successful ontology output as structured repository evidence, preserve its
provenance in answers, and state when validation fails or the requested fact is
absent rather than inferring it. Do not use the control-plane database at
`data/sekai.db` as a portable ontology database.

Ontology classes and relations describe meaning. Directory commands record local filesystem facts (`directory init` / `directory index`) in the same portable database; those facts are not ontology classes. This repository's contributor vocabulary pack is `crates/sekai-ontology/ontologies/sekai-chisei-product-v1.json`. Import it into a throwaway `--db` when answering product-term questions; do not treat it as a built-in server ontology or as `directory init` vocabulary.

## Coding Style & Naming Conventions

Follow standard Rust formatting with `cargo fmt` and keep modules aligned with the existing domain boundaries. Use `snake_case` for files, modules, functions, and variables; use `PascalCase` for types and traits; use `SCREAMING_SNAKE_CASE` for constants. Keep provider-specific behavior behind `crates/sekai-provider/` abstractions (re-exported as `sekai_chisei::llm`). Prefer explicit policy, audit, and authorization behavior over hidden side effects.

## Testing Guidelines

Add focused tests for changes touching provider routing, LLM calls, authentication, persistence, migrations, or coordination behavior. Prefer deterministic tests that do not require external services. Mark service-dependent tests ignored, following `tests/ollama_e2e.rs`, and document required local services in the test or related docs.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects, often Conventional Commit style: `fix(sekai): preserve reconcile filters`, `docs: clean up OSS-readiness language`, `chore: sync proto copies`. Keep commits narrow and describe the affected subsystem when useful. Pull requests should include a concise behavior summary, tests run, linked issue or context, and any configuration or security implications. `.agents/skills/` is tracked; do not treat it as gitignored.

### Verified commits on GitHub

Prefer publishing PR branch tips with GitHub-signed commits so GitHub shows
**Verified**:

1. Implement and commit locally as usual (`commit.gpgsign` may still apply).
2. Publish the branch tip with `scripts/gh-verified-push.sh` instead of a plain
   `git push` when you want the hosted commit Verified (OpenClaw-style GraphQL
   `createCommitOnBranch`). That path creates one server-side commit with the
   local `HEAD` tree; committer is typically **GitHub**.
3. New branch:  
   `scripts/gh-verified-push.sh --create-branch-from origin/main --branch <topic> --sync-local`
4. Existing PR branch:  
   `scripts/gh-verified-push.sh --branch <topic> --sync-local`  
   (uses the current remote tip as `expectedHeadOid`).
5. Never pass `--no-gpg-sign` for local commits; if GPG fails, stop and fix it.
6. After publish, confirm `verification.verified=true` (the script prints this).

When merging PRs, prefer **squash** (`gh pr merge --squash --delete-branch`) so
the land commit on `main` is also GitHub-signed/Verified and history stays
linear. Use `gh pr merge --merge` only when multi-commit history must be kept
(original SHAs preserved). Avoid GitHub **rebase** merges when Verified history
matters: rebase-merge rewrites commits and drops signatures. Do not rewrite
protected `main` after merging unless the user explicitly approves; if
protection is temporarily relaxed, restore force-push and status-check settings
immediately after the correction.

## Security & Configuration Tips

Never commit secrets, tokens, provider credentials, logs, or local SQLite databases. Use `SEKAI_INSECURE=1` only for trusted local development. For network-accessible runs, create principal-scoped credentials with `sekaictl admin access credential create <principal>` and require `authorization: Bearer <token>` on gRPC requests. `SEKAI_CREDENTIAL` is a client-side bearer input and never bootstraps server authority. Report vulnerabilities through `SECURITY.md`.
