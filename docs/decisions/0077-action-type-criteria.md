# ADR 0077: Action types declare closed criteria and receipt-bound effects

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/904
- Issue: https://github.com/Sannrox/sekai-chisei/issues/883 (#883)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0063](0063-object-action-describe-preview.md)

## Context

`GovernedActionType` already carries a closed parameter schema, allowed
effect kinds, and optional object mutation. It has no submission-criteria
field. Approval is `ActionPolicy::decide` at preview, not a type column.
Hosts re-implement preconditions and post-effects. Issue #883 asked for an
additive type contract.

## Decision

1. Criteria and parameter rules are closed fields on the immutable type
   version. The predicate vocabulary is the shipped object-security v1 set
   plus the existing parameter-schema subset. Preview names failing
   criteria. Submit rechecks live state. A preview digest is not a permit
   ([ADR 0063](0063-object-action-describe-preview.md)).
2. A criterion that names a hidden or ungranted property fails closed as
   unavailable.
3. Declared post-effect work is a subset of `allowed_effect_kinds`
   (`notify`, `runtime_dispatch`, `external_mutate`). Each effect keeps its
   existing receipt. `external_mutate` still requires `permit_id`
   ([ADR 0020](0020-shared-type-revisions-and-object-sync.md)). Effect
   failure does not rewrite the Action instance outcome.
4. This ADR does not invent a webhook document family or a second submit
   RPC. Function-backed validation waits on #882.

## Alternatives considered

- Wait for #882 and ship criteria, guest functions, and a new egress family
  together. Rejected: criteria do not need guest code.
- Leave rules on hosts. Rejected: that is the current drift.

## Consequences

#883 implements the additive fields. Side effects are first-class on the
type that already shipped. A later signed allowlisted egress encoding is
additive.

## Validation

Preview on a failing criterion names that criterion; submit with the same
state is refused with the same code. Hidden-property criteria do not leak
names. An undeclared effect kind is refused at type validation. Submit
remains `SubmitActionInstance`.
