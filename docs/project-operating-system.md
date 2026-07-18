# Project operating system

This document defines how `sekai-chisei` turns ideas into durable software.
GitHub is the system of record: Issues describe work, Discussions resolve
meaningful design choices, pull requests contain implementation, and the
repository holds only knowledge that must remain true after the work closes.

The model borrows OpenClaw's useful instincts—focus maintainers on small,
coherent changes, keep the core narrow, prefer extension mechanisms, make AI
assistance transparent, and automate repeatable work—but adapts them to a
pre-1.0 Rust control plane with a small contributor base. There are no PR
quotas, blanket bans on refactoring, or process layers that need a dedicated
program manager.

## 1. Development philosophy

### Core principles

1. **GitHub holds the project state.** If work matters, it has a linked Issue,
   Discussion, pull request, commit, release, or security advisory. Private
   scratch notes are temporary and are never the only record of a decision.
2. **Start with the smallest durable artifact.** A small bug can go directly to
   a PR. A feature starts as an Issue. A contested or cross-boundary choice
   starts in a Discussion. Documentation and ADRs are written only when the
   result must outlive the work item.
3. **One PR, one outcome.** A PR may include code, tests, migrations, and docs
   needed for one observable outcome. Unrelated cleanup becomes another Issue.
4. **Evidence closes work.** Acceptance criteria, deterministic tests, migration
   checks, security reasoning, and operator-visible behavior matter more than
   the amount of implementation.
5. **Keep the control plane narrow.** Sekai owns durable facts; Chisei owns
   governed decisions; provider adapters execute calls. Domain behavior stays
   in schemas, adapters, examples, or external integrations.
6. **Safe defaults, explicit power.** Namespace isolation, authorization,
   egress, budgets, approvals, audit, and secret handling are design inputs,
   not a review afterthought.
7. **Promote repetition into Skills.** When contributors repeat a project-
   specific prompt or checklist, encode the procedure as a small repository
   Skill and review it like code.
8. **Delete process that stops paying rent.** Every recurring artifact has an
   owner, consumer, and review point. If one is missing, remove or consolidate
   it.

### Engineering values

In priority order:

1. Security, privacy, license compliance, and data integrity.
2. Correctness of policy, authorization, audit, lineage, and budget behavior.
3. Compatibility and recoverability for public protocols, configuration, and
   persisted data.
4. Inspectability and deterministic verification.
5. Simplicity of the core and clarity of module boundaries.
6. Contributor and operator usability.
7. Performance supported by measurement.
8. Cleverness or abstraction for its own sake.

### Decision hierarchy

When sources disagree, resolve them in this order:

1. `SECURITY.md`, the AGPL license, and responsible-disclosure obligations.
2. Accepted ADRs and the product boundaries in `VISION.md`.
3. Public contracts in `proto/`, stable configuration documentation, and
   migration guarantees.
4. Executable tests and checked-in fixtures.
5. Current implementation.
6. Contributor and operator documentation.
7. Open Issues, Discussions, and unmerged PRs, which express intent rather than
   shipped behavior.

An inconsistency is a bug. Fix the highest-authority source only through the
decision process appropriate to it; then update all lower sources in the same
change.

### Contribution philosophy

- Bugs and small, low-risk improvements may arrive as a focused PR with a clear
  description; link an Issue when one already exists.
- Features, public contract changes, persistence changes, and security-policy
  changes require an Issue before implementation.
- Changes that alter the Sekai/Chisei boundary, namespace model, trust model,
  extension model, or a difficult-to-reverse public contract require a Design
  Discussion before an Issue is marked `status:ready`.
- Refactoring is welcome when tied to an observable constraint: reduced defect
  risk, removal of duplication blocking active work, measurable performance,
  or a named maintainability problem. Pure aesthetic churn is not planned.
- AI-assisted contributions are first-class. Authors remain accountable for
  understanding the change, protecting secrets, and reporting the verification
  actually performed.

### Planning philosophy

Planning is just enough information to make the next decision:

- Issues are executable briefs, not essays. They state the problem, outcome,
  boundaries, acceptance evidence, and important risks.
- The open Issue list is the backlog. Do not maintain a duplicate roadmap file.
- Milestones group work committed to a release or time-bounded objective; they
  are not permanent theme buckets.
- Maintainers plan by making a small set of Issues `status:ready`. An unlabelled
  open Issue remains a candidate, not a commitment.
- Implementation discoveries go into the linked Issue or PR. Only a durable
  result is promoted to an ADR, guide, reference, example, or Skill.

## 2. Repository structure

Keep the current domain-oriented source layout. Add operating artifacts without
creating a second project-management tree.

| Path | Owner | Purpose |
| --- | --- | --- |
| `src/sekai/` | Sekai maintainers | Durable graph, audit, lineage, security, evidence, coordination, and memory primitives. |
| `src/chisei/` | Chisei maintainers | Policy, budget, routing, approval, evaluation, and learning decisions. |
| `src/llm/` | Provider maintainers | Provider-specific execution behind common abstractions. |
| `src/grpc/`, `proto/` | API maintainers | Transport implementations and public native contracts. |
| `adapters/` | Integration owners | Domain-neutral external evidence adapters; not core ontology. |
| `examples/` | Feature authors | Runnable paths that prove and teach supported integration behavior. |
| `tests/`, `tests/fixtures/` | Change authors | Deterministic contract and regression evidence. |
| `docs/` | Maintainers for the affected surface | Durable operator, integration, architecture, and contribution knowledge. |
| `docs/decisions/` | Decision owner | Accepted or superseded architecture decisions with long-lived consequences. |
| `.agents/skills/` | Maintainers | Small, repository-specific AI procedures. Only project-owned Skills are tracked; personal Skills remain ignored. |
| `.github/ISSUE_TEMPLATE/` | Triage maintainer | Structured inputs for bugs, features, refactors, and research. |
| `.github/DISCUSSION_TEMPLATE/` | Discussion owner | Prompts for significant, multi-option design work. |
| `.github/workflows/` | Maintainers | Required checks, security scanning, packaging, and releases. |
| `deploy/`, `docker-compose.yml`, `.env.example` | Operations owner | Versioned configuration and deployable examples. |
| `scripts/` | Script owner named by Git history/CODEOWNERS | Deterministic automation used by development or operations. |

Do not add `docs/plans/`, standalone status reports, prompt archives, or a
parallel backlog. Plans expire and belong in Issues. Session transcripts may be
linked from a PR when useful, but are supporting evidence rather than canonical
requirements.

## 3. Issue workflow

### Lifecycle

```text
idea or report
    -> Issue: status:triage
    -> clarify, deduplicate, or route to Discussion/security advisory
    -> Issue: status:ready
    -> assignee opens linked PR
    -> review + required evidence
    -> rebase merge
    -> Issue closes; durable knowledge is promoted
```

Use one status label at a time:

- `status:triage` — needs reproduction, scope, decision, or maintainer routing.
- `status:ready` — outcome and acceptance evidence are sufficient to implement.
- `status:blocked` — a named external decision or dependency prevents progress.

GitHub's open/closed state represents backlog versus completed/declined work;
do not add `status:done`. A maintainer closes duplicates, out-of-scope requests,
or stale Issues with a reason and a link to the governing artifact.

Assignment means active ownership. Before coding, comment with the intended
scope if the approach is not already obvious. If no work appears for 14 days,
maintainers may unassign after asking for status; this is coordination, not a
punishment.

### Feature workflow

1. Open a feature Issue describing the operator/integrator problem and
   observable outcome.
2. Route to a Design Discussion when the choice crosses core boundaries,
   changes public compatibility, or has multiple credible approaches.
3. Record the selected direction in the Issue. Create an ADR only if the choice
   will constrain future work after the Issue closes.
4. Mark `status:ready`, implement one vertical outcome, and link the PR with a
   closing keyword.
5. Prove behavior at the appropriate boundary and update durable user-facing
   docs in the PR.

### Bug workflow

1. Capture expected versus actual behavior, the smallest reproduction, affected
   version, environment, and redacted diagnostics.
2. Triage severity. Exploitable or sensitive reports move immediately to the
   private process in `SECURITY.md`.
3. Add a regression test that fails for the reported behavior when practical.
4. Fix the narrowest responsible boundary; avoid unrelated cleanup.
5. Merge when the regression is green and the affected compatibility/security
   paths are checked.

Trivial, well-understood bugs may skip a separate Issue when the PR contains the
same evidence. Regressions, security-adjacent bugs, and user-visible data loss
always get an Issue or private advisory for traceability.

### Refactoring workflow

1. Open a refactor Issue naming the concrete friction and the invariant that
   must not change.
2. Supply evidence: repeated defects, duplication, blocked feature work,
   complexity hotspot, or a measured performance constraint.
3. Define characterization tests or other proof of unchanged behavior.
4. Split enabling refactors from behavior changes when either can be reviewed
   independently.
5. Close with before/after evidence. Do not create an ADR unless a boundary or
   long-term structural rule changed.

### Research workflow

1. Open a time-boxed research Issue with a decision question, hypotheses,
   constraints, and expected evidence.
2. Investigate in comments, a draft PR, benchmark fixture, or minimal spike.
   The spike is disposable unless it meets production standards.
3. End with one of: recommendation plus follow-up Issue, Design Discussion,
   documented finding, or `no action` with rationale.
4. Close the research Issue. Do not leave research permanently `in progress`.

Research produces a decision, not necessarily code.

## 4. Skill system

Repository Skills live under `.agents/skills/<skill-name>/`. Each contains a
concise `SKILL.md` and UI metadata in `agents/openai.yaml`. Add scripts only for
deterministic logic that is otherwise repeatedly rewritten; add references
only when a branch needs substantial project-specific material.

| Skill | Purpose and use | Required inputs | Expected output | Responsibilities and boundaries |
| --- | --- | --- | --- | --- |
| `shape-work-item` | Convert an idea, bug, refactor, or research question into a decision-ready Issue. | Raw request, repository evidence, known constraints. | Issue type, concise draft, acceptance evidence, labels, and routing recommendation. | Search for duplicates and expose uncertainty. It does not invent priority, assign people, or publish without authorization. |
| `assess-change-impact` | Scope a proposed or implemented change across domain and trust boundaries. | Issue/PR/diff and affected paths. | Impact matrix, required tests, migration/docs/security obligations, open risks. | Trace SQLite/PostgreSQL, gateway/native, and policy/audit effects. It does not approve architecture or replace a security audit. |
| `verify-change` | Select and run proportionate deterministic checks for a Rust change. | Diff or paths plus stated outcome. | Commands, results, skipped checks with reasons, and remaining uncertainty. | Start focused, expand by risk, and never claim unrun checks. Live-provider tests stay opt-in and secret-safe. |
| `capture-project-decision` | Promote a resolved choice into the right durable artifact. | Accepted Discussion/Issue/PR outcome and alternatives. | ADR, doc/Skill update, or explicit `no durable artifact` decision with links. | Preserve one source of truth and mark superseded ADRs. It does not turn unresolved debate into policy. |
| `prepare-release` | Assemble release readiness and evidence. | Target version, milestone/merged PRs, current tree and CI. | Version/compatibility checklist, validation report, release-note draft, and blockers. | Verify rather than publish. Tagging, pushing, and releasing require explicit maintainer authorization. |

The Skills are intentionally composable:

```text
shape-work-item -> assess-change-impact -> implementation
    -> verify-change -> capture-project-decision (only when durable)
    -> prepare-release (at a release boundary)
```

Add a Skill only after the same project-specific procedure appears at least
three times, or when missing a step has high security/data-integrity cost.
Before merging a Skill, validate its metadata, run it against one realistic
task, and confirm it changes agent behavior beyond generic instructions. Retire
or combine Skills that overlap, go stale, or lack an owner.

Suggested structure for every Skill:

```text
.agents/skills/<verb-led-name>/
├── SKILL.md
├── agents/
│   └── openai.yaml
├── scripts/       # optional deterministic automation
├── references/    # optional, loaded only when needed
└── assets/        # optional output templates
```

## 5. Documentation strategy

Use this test before creating a document:

| Artifact | Use it when | Do not use it for |
| --- | --- | --- |
| Issue | Work is actionable, scoped, and can close. | Stable operator instructions or broad open-ended debate. |
| Discussion | A consequential choice has multiple credible options or needs community input before commitment. | Bug tracking, implementation checklists, or decisions already made. |
| PR | A concrete, reviewable repository change implements one outcome. | Product-roadmap debate. |
| ADR | An accepted architecture choice constrains future changes and its rationale will matter after links close. | Routine implementation detail, temporary experiments, or merely restating code. |
| Documentation | Users, operators, or contributors will repeatedly need the knowledge after the current work closes. | Status, speculative design, investigation logs, or duplicated API truth. |
| Skill | AI contributors repeatedly need the same project-specific procedure or high-risk checklist. | Product facts better represented in code/docs, one-off prompts, or broad personality guidance. |

Durable documentation includes supported setup, configuration, operations,
security boundaries, architecture vocabulary, public integration contracts,
and maintained examples. Keep rationale in ADRs and task history in Issues.

Documentation stays maintainable when:

- every page has a clear audience and is linked from `docs/README.md`;
- the author of a behavior change updates affected docs in the same PR;
- configuration changes update `.env.example` and `docs/configuration.md`
  together;
- protocol and CLI examples are checked where practical;
- stale content is deleted instead of accumulating compatibility folklore; and
- a release or quarterly maintenance pass checks links, commands, ADR status,
  and ownerless pages.

## 6. Contributor workflow

### Humans

1. Search Issues, Discussions, and PRs.
2. Choose the smallest artifact using the table above.
3. Confirm an Issue is `status:ready` or clarify the intended scope.
4. Create `type/issue-short-description` from current `main`.
5. Implement one outcome with focused tests and any required docs/migrations.
6. Open a PR early when design feedback is useful; mark it draft until the
   acceptance evidence is present.
7. Respond to every actionable review thread and rebase before merge.

### AI contributors

AI follows the same workflow plus four explicit duties:

- read `AGENTS.md`, the linked Issue/Discussion, and affected durable docs;
- use repository Skills for repeated procedures and report actual evidence;
- disclose AI assistance and testing level in the PR; and
- never post secrets, fabricate command results, silently broaden scope, or
  publish external changes without authorization.

The human or service account opening the PR owns the contribution. Session
logs are optional supporting context; concise rationale and reproducible tests
remain mandatory.

### Code reviewers

Review in this order:

1. Does the change solve the linked outcome without expanding the product
   boundary?
2. Are security, namespace isolation, egress, audit, budget, and secret-handling
   effects explicit?
3. Are public API, configuration, persistence, and dual-backend compatibility
   handled?
4. Does evidence cover failure semantics and regressions, not only the happy
   path?
5. Are docs and examples updated only where knowledge became durable?
6. Is the diff focused and understandable enough to own after merge?

Review the code, not the identity of its authoring tool. Request changes for
behavioral or maintainability risk; mark optional preferences as such.

### Maintainers

Maintainers own routing and project coherence:

- keep the `status:ready` queue small and decision-ready;
- close or reroute work that violates product/security boundaries;
- facilitate Discussions and state the final decision with rationale;
- protect required checks and CODEOWNERS surfaces;
- rebase-merge focused PRs and keep `main` releasable;
- promote only durable outcomes, then remove obsolete Issues/docs/Skills; and
- publish releases from verified commits with known compatibility notes.

## 7. Project conventions

### Issue templates

- **Bug:** expected/actual behavior, minimal reproduction, version,
  environment, backend, redacted diagnostics, and regression evidence.
- **Feature:** problem, observable outcome, non-goals, acceptance evidence,
  affected boundary, and compatibility/security impact.
- **Refactor:** friction, evidence, invariants, scope, and proof of unchanged
  behavior.
- **Research:** decision question, hypotheses, constraints, time box, evidence,
  and exit condition.

Significant designs use the Design Discussion form. Security vulnerabilities
use private advisories and never a public template.

### Pull requests

PRs use a closing keyword for their primary Issue when one exists, describe
behavior and approach, list exact validation, declare impact, and disclose AI
assistance. Draft PRs are for active implementation; an abandoned draft should
be closed rather than used as a permanent plan.

### Labels

Use a small, namespaced taxonomy:

| Dimension | Labels |
| --- | --- |
| Type | `type:bug`, `type:feature`, `type:refactor`, `type:research`, `type:design`, `type:docs` |
| Area | `area:sekai`, `area:chisei`, `area:gateway`, `area:grpc`, `area:llm`, `area:persistence`, `area:ops`, `area:docs` |
| Status | `status:triage`, `status:ready`, `status:blocked` |
| Risk | `risk:security`, `risk:breaking`, `risk:migration` |
| Contributor | `good first issue`, `help wanted` |

Apply one type, one status, and only relevant area/risk labels. Labels describe
work; they do not encode priority. Maintainers express priority by the ready
queue and milestones.

### Milestones

Create milestones only for a release (`v0.2.0`) or a short, named objective
with an owner and exit condition. An Issue may remain outside a milestone
without being rejected. Close or move all open items when a milestone ends.

### Releases and versioning

Use SemVer. Before `1.0`, minor releases may include documented breaking
changes; patch releases should remain backward-compatible except for security
or data-integrity corrections. Tag signed or otherwise protected release
commits as `vMAJOR.MINOR.PATCH`. GitHub Releases contain generated change notes
edited into user-facing `Added`, `Changed`, `Fixed`, `Security`, and
`Migration` sections where applicable.

The release owner verifies Cargo/package version, migration and configuration
notes, CI, container build, smoke behavior, and rollback/backup implications.
Use rebase merges by default and do not rewrite protected `main`.

### Branches and commits

Branches use `<type>/<issue>-<slug>`, for example
`fix/142-budget-reconciliation` or `feat/203-evidence-retention`. Agent-created
branches may use the required `codex/` prefix, followed by the same concise
slug.

Commits use short imperative subjects, preferably Conventional Commit form:

```text
feat(chisei): enforce namespace budget ceiling
fix(sekai): preserve evidence source attribution
docs: explain PostgreSQL support boundary
```

Keep commits reviewable and do not mix unrelated formatting or generated state.

## 8. Automation

Automate deterministic gates, not product judgment.

### Keep or add now

- Keep required `fmt`, `clippy`, build, test, CodeQL, dependency audit, Docker,
  and deterministic gateway-smoke checks.
- Make the gateway smoke check required after its flake rate is understood;
  `continue-on-error` should have a tracked removal Issue.
- Enable GitHub Discussions with a `Design` category and create the labels in
  this document as a one-time maintainer setup.
- Protect `main`: require PRs, required checks, resolved conversations, and
  CODEOWNER review for security-sensitive paths as ownership expands.
- Use Dependabot grouping already present to reduce review noise.
- Use GitHub's generated release notes, with label categories, then have the
  release owner edit only user-visible compatibility and migration details.

### Add when volume justifies it

- Path-based area labels when manual triage exceeds a few minutes per week.
- A stale **candidate** report, never automatic closure of reproducible bugs or
  accepted work.
- Issue-form validation and duplicate suggestions when incoming volume makes
  incomplete reports costly.
- Documentation link/command checks when drift becomes recurrent.
- MSRV and protocol-compatibility matrices once those promises are explicit.
- A bot that proposes a Skill when the same checklist recurs; maintainers still
  approve, security-review, and own the Skill.

Do not automate prioritization, acceptance of design choices, security severity,
or merging solely from AI review. These need accountable maintainer judgment.

## 9. Scaling strategy

### Solo developer

Use Issues only for work that will outlive the current session or needs a
decision trail. Keep a weekly ready queue of roughly three to seven items. Use
Discussions sparingly for decisions where outside feedback is genuinely useful.
The maintainer owns all artifacts; the five core Skills supply consistency.

### Small OSS project

Require Issues for features and risky changes, introduce the label taxonomy,
publish contribution opportunities, and add area owners to CODEOWNERS as trust
develops. Use release milestones and a predictable release cadence. Triage at a
fixed weekly interval instead of continuously interrupting implementation.

### Large OSS community

Add component maintainers with explicit CODEOWNERS responsibility, saved Issue
views, response targets for triage, a contributor ladder, and moderated
Discussion categories. Automate path labels and release-note collection. Split
repositories only when release cadence, permissions, or ownership genuinely
diverge—not merely because directories are large.

### AI-assisted development team

Treat agents as accountable contributors operating through Issues and PRs.
Give each agent a bounded Issue, least-privilege credentials, isolated
worktrees, and required verification. Use Skills as reviewed operational code;
track their owner, security surface, and success/failure feedback. Agents may
shape work, implement, test, and review independently, but humans retain
authority for security exceptions, public compatibility, architectural
acceptance, releases, and external side effects.

Scale the evidence before the hierarchy: add better fixtures, evaluations,
policy checks, and provenance before adding manager-of-manager orchestration.

## Adoption checklist

Repository changes in this operating-system baseline are immediately usable.
Maintainers complete these one-time GitHub settings separately because they are
not stored in Git:

- [ ] Enable Discussions and create a `Design` category using the checked-in
      form.
- [ ] Rename the existing `bug`, `enhancement`, and `documentation` labels to
      `type:bug`, `type:feature`, and `type:docs`; create the remaining minimal
      labels listed above with short descriptions.
- [ ] Extend the existing `main` protection to require pull requests, resolved
      conversations, and linear history while retaining stable required checks,
      admin enforcement, and the force-push prohibition.
- [ ] Decide which current open Issues are `status:triage` versus
      `status:ready`; do not bulk-migrate speculative ideas.
- [ ] Create the next release milestone only when its scope is committed.
- [ ] Review this operating system after two releases, then at most twice per
      year or when contribution volume changes materially.

The maintainer is the owner of this document. Changes to it use a normal Issue
and PR; fundamental governance changes begin in a Design Discussion.

## Inspiration

This adaptation is informed by OpenClaw's public
[Vision](https://github.com/openclaw/openclaw/blob/main/VISION.md),
[contribution guide](https://github.com/openclaw/openclaw/blob/main/CONTRIBUTING.md),
and [Skills documentation](https://github.com/openclaw/openclaw/blob/main/docs/tools/skills.md).
The rules above are specific to `sekai-chisei` and are not a copy of OpenClaw's
governance.
