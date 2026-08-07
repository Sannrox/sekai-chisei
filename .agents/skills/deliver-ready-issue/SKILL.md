---
name: deliver-ready-issue
description: Deliver a dependency-ready sekai-chisei GitHub Issue through a bounded implementation workflow. Use when asked to implement, publish, or land a specific ready Issue, or to take the next explicitly approved frontier item through verification and review.
---

# Deliver Ready Issue

Take one approved Issue from readiness check to the highest delivery stage the
user authorized. Keep the Issue as planning truth and the Pull Request as
implementation truth.

## Establish the authority ceiling

Infer the ceiling from the user's explicit request. When it is unclear, choose
the lower ceiling and state what remains:

- **Implement**: change the local working tree and verify it.
- **Publish**: implement, commit, push, and open a ready Pull Request.
- **Land**: publish, resolve review and CI, then merge and clean up.

Permission for a higher stage includes its preceding stages. It never includes
unrelated issue creation, prioritization, assignment, release publication,
force-pushing protected branches, or weakening repository protections.

## Deliver the Issue

### 1. Prove readiness

1. Resolve the exact repository and Issue. If the user asks for the "next"
   Issue, require an explicit selection or a recommendation produced by
   `advance-issue-frontier` before starting.
2. Read the repository instructions, the Issue, linked decisions, and the live
   Pull Request and Issue state.
3. Read `## GitHub dependencies` literally. Treat an open predecessor or an
   unresolved non-Issue dependency as blocking.
4. Search for an existing branch, Pull Request, or claimed implementation that
   overlaps the outcome.
5. Confirm that the Issue is open, unblocked, focused enough for one Pull
   Request, and has testable acceptance criteria.

Stop without creating a branch when readiness, ownership, or dependencies are
ambiguous. Report the smallest action that would unblock delivery.

### 2. Isolate the work

1. Inspect the working tree and preserve every unrelated user change.
2. Start from the current default branch. Fetch or fast-forward it when safe.
3. Use an isolated worktree when the current tree is dirty or another task is
   active. Otherwise create a narrow `codex/<issue>-<slug>` branch.
4. Comment, assign, or otherwise claim the Issue only when explicitly
   authorized or required by documented maintainer policy.

Never discard, overwrite, stash, or commit unrelated work merely to obtain a
clean tree.

### 3. Bound the implementation

1. Run `assess-change-impact` against the Issue and affected paths.
2. Translate the Issue acceptance criteria into code, test, documentation,
   migration, configuration, and security obligations.
3. Implement one coherent outcome. Avoid opportunistic cleanup.
4. If the Issue cannot produce one reviewable Pull Request, stop and recommend
   a split. Do not create follow-up Issues without authorization.

### 4. Verify and review

1. Add focused deterministic tests while implementing.
2. Run `verify-change` for intermediate local evidence and retain exact
   commands, results, skips, and remaining uncertainty. Carry its evidence
   state, review disposition, baseline and candidate identities, root-cause/
   sibling analysis, and any freshness limitation forward. Dirty-worktree
   results are not the final PR proof.
   A `review-required` disposition may coexist with `validated` evidence; do
   not mark it `review-complete` or `merged` by assertion.
3. Run `autoreview` before committing. Fix actionable findings and rerun the
   relevant checks until no material finding remains or a documented blocker
   requires maintainer judgment.
4. Inspect the final diff for scope, generated artifacts, secrets, and
   accidental runtime state.

### 5. Publish when authorized

1. Stage only the intended paths and create a narrow imperative commit.
   Never use `--no-gpg-sign`. If signing fails, stop and fix GPG.
2. Run `verify-change` again against the committed candidate before publishing.
   Require the full candidate SHA, clean-content guard, exact proof, and the
   appropriate review disposition. If this final verification or any review
   fix changes content, repeat review, commit, and final verification before
   continuing. The PR must carry this immutable candidate evidence.
3. Publish the topic branch with **GitHub-verified** commits via
   `scripts/gh-verified-push.sh` (GraphQL `createCommitOnBranch`), not a plain
   `git push`, unless the user explicitly asks for git-protocol push:
   - New branch:  
     `scripts/gh-verified-push.sh --create-branch-from origin/main --branch <topic> --sync-local`
   - Update existing branch:  
     `scripts/gh-verified-push.sh --branch <topic> --sync-local`
   - Confirm the script reports `verification.verified=true` and that the
     hosted tree matches local `HEAD`.
4. After `--sync-local` moves the branch to the server-created commit, record
   that new full SHA and run `verify-change` against it. Require a clean
   content guard and exact candidate evidence before opening the PR. If
   post-publish verification fails, do not open or land the PR; fix from the
   synced branch and repeat review, publish, and post-publish verification.
5. Open a ready Pull Request that:
   - links and closes the Issue;
   - summarizes behavior rather than file operations;
   - lists verification evidence and any skipped checks;
   - calls out configuration, compatibility, migration, and security impact;
   - includes an agent transcript when the project workflow requires it.
6. Return the Pull Request URL. Do not publish when the ceiling is Implement.

### 6. Land when authorized

1. Wait for required CI and review. Resolve actionable feedback in the same
   branch and rerun affected checks. Re-publish review fixes with
   `scripts/gh-verified-push.sh` so the PR tip stays Verified.
2. Recheck that dependencies and repository protections still permit landing.
3. Prefer squash merge for Verified linear history on `main`:
   `gh pr merge --squash --delete-branch`.
   Use `--match-head-commit` with the published tip when available. Do not use
   GitHub rebase-merge when Verified commits matter.
4. Confirm the Issue closed, the default branch contains the merge, and the
   local checkout is synchronized when safe.
5. Invoke `advance-issue-frontier` in report-only mode unless the user also
   authorized frontier status updates.

Never enable auto-merge, bypass checks, relax protection, or merge beyond the
authority ceiling.

## Report completion

Return:

- Issue and authority ceiling;
- branch, commit, and Pull Request when created;
- implemented outcome;
- verification evidence state, review disposition, delivery status, exact
  baseline/candidate identities, and remaining uncertainty;
- verification and review evidence;
- merge state and newly available follow-up work when applicable;
- blockers, skipped checks, and remaining uncertainty.

## Boundaries

- Deliver only the selected Issue; do not choose project priority.
- Do not implement blocked work or infer that silence grants ownership.
- Keep secrets, credentials, logs, databases, and runtime state out of Git.
- Do not substitute a successful build for Issue acceptance evidence.
- Do not close an Issue manually when the implementation has not landed.
