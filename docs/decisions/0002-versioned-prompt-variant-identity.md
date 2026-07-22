# ADR 0002: Identify prompt variants by immutable versioned names

- Status: proposed
- Date: 2026-07-22
- Owners: @Sannrox
- Source: [Issue #178](https://github.com/Sannrox/sekai-chisei/issues/178)
- Supersedes: none
- Superseded by: none

## Context

The Chisei portfolio frontier currently aggregates observations by
`(namespace, task_class, model)`. Prompt construction evolves independently, so
observations from materially different prompts collapse into one running
average and allocation cannot select a model-prompt pair.

Adding prompt identity is difficult to reverse because it changes the
observation primary key in SQLite and PostgreSQL, expands the public gRPC
contract, and increases allocation cardinality. Identity must distinguish
published prompt behavior without minting a new candidate implicitly for every
incidental edit during prompt development.

## Decision

Prompt variants will have an opaque, caller-supplied identity composed of a
stable name and an immutable revision, conventionally `name@revision`. The
control plane will compare the complete identity as an exact string; it will
not parse names, order revisions, infer equivalence, or hash resolved prompt
content.

A variant revision becomes immutable once an observation is recorded. Changing
the published prompt content after that point requires a new revision. Draft
edits made before a revision is observed do not create portfolio identities.
Automatic variant generation and revision allocation remain outside the
portfolio contract.

The implementation owned by Issue
[#174](https://github.com/Sannrox/sekai-chisei/issues/174) will:

- key observations by `(namespace, task_class, model, prompt_variant)`;
- compute dominance and allocation over distinct model-variant pairs;
- include `prompt_variant` in committed and pending route identity so a
  variant-only change uses the existing confirmation and cooldown rules;
- add `prompt_variant` fields to the applicable protobuf messages without
  changing existing field numbers; and
- canonicalize an omitted or empty variant to the reserved identity
  `legacy@1` at the service and persistence boundaries.

Existing rows will be migrated to `legacy@1`. Older clients therefore continue
to record and select the same historical aggregate, while clients that provide
versioned identities opt into variant-aware observations. Stored identities
must always be non-empty; `legacy@1` is reserved and cannot name a new explicit
variant.

## Alternatives considered

- **Resolved-prompt content hash.** This precisely distinguishes content and
  naturally converges identical prompts, but whitespace and other incidental
  edits automatically fragment history and repeatedly restart minimum-sample
  gating.
- **Unversioned template or generation name.** This is stable and simple, but
  editing a published template silently merges observations from materially
  different prompts and reproduces the defect under a new key.
- **Variant side table.** This avoids changing the current primary key, but
  frontier and dominance queries still require variant-qualified identity and
  gain a join without removing the migration or compatibility decision.
- **No variant dimension.** This preserves compatibility but leaves
  model-prompt interaction effects unobservable and quality measurements mixed.

## Consequences

Variant lineage is explicit and observations remain stable across unpublished
editing. Producers must allocate and retain immutable revisions, and operators
must avoid creating unnecessary versions. The public fields are additive at
the protobuf wire level, but variant-aware behavior is opt-in: omission retains
the legacy aggregate rather than guessing a current variant.

The candidate count can grow by the number of observed variants. Allocation
must continue enforcing its existing demand, candidate, and optimizer-state
bounds, and it must fail explicitly rather than truncate candidates silently.
Representative cardinality must be measured before migration; unexpectedly
high cardinality requires revisiting the search strategy, not weakening
identity.

SQLite migration requires an atomic table rebuild because its primary key
changes. PostgreSQL requires an equivalent transactional primary-key change.
Both migrations must backfill `legacy@1` and preserve sample counts, weighted
averages, and timestamps. The frontier index must be checked against the new
query plan on both backends.

Before variant-qualified observations exist, rollback can restore the previous
schema without information loss. Afterward, the old schema cannot represent
distinct variants: downgrade requires a documented backup and an explicit
weighted aggregation by model, or restoration of a pre-migration backup. It
must not silently discard or overwrite variant history.

Issue [#176](https://github.com/Sannrox/sekai-chisei/issues/176) should land
before #174 so the duplicated PostgreSQL route state machine has behavioral
coverage before route identity expands.

## Validation

Issue #174 must provide deterministic evidence that:

- two variants for one model remain distinct and do not average together;
- dominance and budget allocation operate on model-variant pairs;
- omitted fields and migrated rows resolve to `legacy@1`;
- fresh and upgraded SQLite and PostgreSQL databases preserve observations;
- variant-only route changes retain three-confirmation and 15-minute cooldown
  behavior; and
- the frontier query uses an appropriate index and allocation fails explicitly
  at existing complexity limits.

Before migration, recorded or representative observations must be grouped by
`(namespace, task_class)` to measure variant cardinality. The decision should be
revisited if normal workloads approach the 128 candidates-per-demand or
100,000 optimizer-state limits, or if producers cannot maintain immutable
revisions reliably.
