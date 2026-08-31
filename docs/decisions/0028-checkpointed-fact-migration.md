# ADR 0028: Execute approved checkpointed fact migration

- Status: proposed
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/722
- Issue: https://github.com/Sannrox/sekai-chisei/issues/693 (#693)
- Supersedes: none
- Superseded by: none

## Context

ADR 0024 keeps published definition revisions immutable. Compatibility
classification (#686) can name breaking or unknown changes, but runtime objects
remain attached to earlier type identity. Discussion 722 requires a separate
approved, checkpointed fact migration with dry-run, resume, rollback, and
supersession. It must never rewrite a published parent revision.

## Decision

`sekai.fact-migration/v1` migrates runtime objects of `object_type` members from
an ancestor revision to the current published head.

1. Parent and candidate identities are content-bound revision digests. The
   candidate must be the live published head. The parent must be an ancestor.
2. Live classification is rechecked. `unknown` denies. Breaking or conditional
   changes require a merged proposal whose pinned base and candidate match.
3. Dry-run plans affected objects without mutation. Execute applies planned
   property strips and rebinds in one transaction, snapshots prior properties
   for rollback, and records a checkpoint. Interrupted execute leaves no
   partial durable success. Exact replay returns the stored result.
4. Objects already bound to the candidate are skipped. Foreign bindings and
   missing required properties or removed kinds are blocked transforms and
   do not mutate. Rollback restores snapshots and prior bindings, and fails
   closed unless the request names the stored parent and candidate.
5. Published definition rows are never rewritten. Authorization of both
   revisions is rechecked at effect. Hidden revisions stay unavailable.
   Execute rechecks live object-security read rules and property write grants
   in the mutation transaction: hidden objects are omitted, ungranted
   properties are not stripped, and audit plus object lineage share that
   transaction. Get of a migration does not distinguish missing from
   unauthorized revisions.

## Alternatives considered

In-place rewrite of the published parent was rejected because history would
no longer be independently verifiable. Automatic breaking migration without
a merged proposal was rejected because live approval would not be rechecked.

## Consequences

Operators migrate facts after publishing a candidate. Mixed-revision objects
remain visible as skip or blocked records. Value-instance and package grants
stay out of this contract.

## Validation

Domain tests cover strip, missing-required, mixed-revision, unknown, and
ancestor checks. SQLite/PostgreSQL conformance covers dry-run, execute,
idempotent replay, rollback identity, object-security omission, ungranted
property preservation, audit-in-transaction, and blocked transforms without
mutating objects. Get does not distinguish missing from unauthorized
revisions.
