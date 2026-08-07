---
name: verify-change
description: Verify a sekai-chisei Rust, protocol, documentation, configuration, or workflow change with proportionate deterministic checks. Use after implementation, before review, or when a contributor needs an exact evidence report without overstating unrun tests.
---

# Verify Change

Run the narrowest useful checks first, then expand according to change risk.
Verification produces an evidence record, not only a list of commands. Every
claim must identify the source revision, the behavior covered, and any limits
that remain.

## Procedure

1. Inspect `git status`, the diff, and the stated outcome. Preserve unrelated
   worktree changes. Record the full `git rev-parse HEAD`, the checkout path,
   and `git status --porcelain=v1 --untracked-files=all --ignore-submodules=none`
   before checking behavior. Use `assess-change-impact` when risk is unclear.
   A dirty implementation worktree is allowed, but record which paths are
   intentional; identify an uncommitted candidate as `HEAD` plus that
   intentional diff rather than as an immutable revision. Use a clean checkout
   or immutable revision for independent review evidence. Complete when every
   changed path is classified.
2. Record three independent statuses rather than collapsing proof and
   authority into one state:

   **Evidence state**

   - `hypothesis` — a report or reviewer observation without an independent
     reproduction.
   - `reproduced` — the current baseline fails on the affected user path or
     a focused regression establishes the defect.
   - `validated` — the responsible boundary is repaired, relevant sibling
     paths were checked, and proof ran on exact candidate content and relevant
     generated inputs. Establish this with an immutable candidate revision in
     a clean/separate checkout or a repository-approved fingerprint covering
     candidate paths and inputs. Unrelated dirty paths may coexist when they
     are explicitly excluded from the proof.

   **Review disposition**

   - `not-required` — the change is within the authorized low-risk path.
   - `review-required` — the change is sensitive, compatibility-affecting,
     high-impact, or still depends on maintainer judgment.
   - `review-complete` — the required maintainer review or decision is
     complete. This does not by itself authorize a merge.

   **Delivery status**

   - `unmerged` — no verified canonical merge has occurred.
   - `merged` — hosted checks passed and the canonical branch is verified to
     contain the recorded merge commit. Do not infer this from an open PR.
   - `rejected/duplicate` — record the reason and the governing finding; do
     not count it as completed work.

   Evidence may be `validated` while review disposition is
   `review-required`. Advance each status only when its own evidence supports
   the transition; do not treat local tests as maintainer review or an open PR
   as a canonical merge.

   For documentation, configuration, and Skill changes, use `validated` only
   after the applicable syntax, links, commands, and cross-file references are
   checked. Do not force a defect state where no runtime behavior is claimed.
3. For a defect or behavior change, reproduce the before state on the recorded
   baseline when practical. Identify the canonical owner and root cause, then
   inspect affected callers, callees, sibling implementations, and lifecycle
   cleanup. Fix the smallest responsible boundary; if a shared invariant is
   broken, repair it at its owner rather than adding a symptom-only guard,
   compatibility shim, or test-only exception. Record when current-main or a
   live dependency could not be verified.
4. Run focused tests for the affected module or integration first. Add checks
   based on the surface:

   | Surface | Required evidence |
   | --- | --- |
   | defect or refactor | before/after reproduction, canonical owner and root cause, affected sibling paths, characterization or regression proof |
   | Rust source | focused tests, `cargo fmt --check`, relevant Clippy/build |
   | public or multi-component behavior | affected integration test plus normal suite |
   | gateway | deterministic `scripts/chisei_gateway_smoke.sh` |
   | protocol | generated build, service/client/example coverage, compatibility review |
   | persistence | fresh and upgrade behavior; SQLite/PostgreSQL alignment where implemented |
   | configuration | parsing/default tests, `.env.example`, configuration docs |
   | docs/templates/Skills | syntax, links or commands where practical; Skill validator for Skills |

   Unit or mocked tests do not establish live provider, gateway transport,
   persistence-upgrade, packaging, UI, or soak behavior. For those claims,
   use the real supported boundary with isolated state, ports, and credentials;
   record unavailable prerequisites as skipped checks with residual risk.
5. Immediately before accepting results, repeat the revision and worktree
   guards from step 1. `HEAD` and status output establish provenance but are
   not a content fingerprint: edits inside an already-dirty file can leave
   both unchanged. For candidate paths and relevant generated inputs, use an
   immutable candidate revision in a clean/separate checkout or a
   repository-approved fingerprint covering staged, unstaged, untracked, and
   generated content. Record and exclude unrelated dirty paths explicitly.
   Without one of those proofs, keep the result at `hypothesis` or
   `reproduced`. Attach hosted checks to the exact candidate SHA; queued,
   stale, or earlier-head checks are not proof for the current result.
6. Before ship-level handoff, run the normal repository gates unless the user
   explicitly requested a narrower check:

   ```bash
   cargo fmt --check
   cargo test --locked
   cargo clippy --all-targets -- -D warnings
   ```

   Run `cargo build --locked` when packaging, feature selection, or binaries
   changed independently of tests. Complete when every applicable local gate
   has a result.
7. Keep service-dependent tests ignored unless prerequisites and credentials
   are intentionally available. Never print secrets or persist live provider
   payloads. Complete when skipped checks name both the reason and residual
   risk.
8. Review failures against the changed scope. Report pre-existing failures with
   evidence; do not relabel a failure as pre-existing without comparison.

## Output

Report at least:

- evidence state, review disposition, and delivery status;
- baseline and candidate identity: full commit SHAs or the approved candidate
  fingerprint for accepted evidence; intermediate dirty-worktree evidence must
  identify `HEAD` plus its intentional diff and excluded unrelated paths;
- checkout status and any intentional dirty paths;
- stated outcome and affected user path or documentation surface;
- observed before behavior and expected behavior, when applicable;
- canonical owner and root cause, when applicable;
- callers, sibling paths, and lifecycle behavior checked;
- after behavior and focused proof;
- commands run and pass/fail result;
- focused behavior covered;
- checks skipped with reasons;
- hosted check or merge evidence tied to the exact revision, when applicable;
- risk and required authority;
- failures and whether they block the stated outcome; and
- remaining uncertainty.

Never use “all tests pass” unless all stated tests actually ran and passed.
