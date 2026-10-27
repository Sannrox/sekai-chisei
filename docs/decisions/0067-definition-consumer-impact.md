# ADR 0067: Report consumer impact from registered declarations only

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/863
- Issue: https://github.com/Sannrox/sekai-chisei/issues/837 (#837)
- Supersedes: none
- Superseded by: none
- Amended by: blocking bindings (#1635), below
- Related: [ADR 0066](0066-object-set-evaluate.md)

## Context

`CompareDefinitionRevisions` already classifies added, removed, and
changed members. It does not know which registered consumers depend on a
removed property. Inferring dependents from repositories was rejected.

## Decision

Accept digest-bound `sekai.definition-consumer-binding/v1` objects and
`ReportDefinitionConsumerImpact`. The report joins the existing
comparison to visible registrations only. Completeness is explicit.
Hidden consumer identities do not leak through counts or errors. The
report is not publication authority.

## Alternatives considered

- Inferring dependents from repository or package scans.
- Treating an empty visible set as proof of no downstream break.
- Replacing `CompareDefinitionRevisions` with a second semantic-diff
  engine.

## Consequences

Authorized callers can see bounded paths for registered dependents of
removed or changed members. Follow-up work may add a dedicated write RPC
only if object mutation is proven insufficient.

## Validation

Removing `Customer.owner` identifies two registered consumers and their
locators. An unrelated optional addition does not mark them broken.
Stale digests produce `stale` without inventing dependents.

## Amendment: blocking bindings (#1635)

Bindings stay advisory by default, and an advisory binding keeps the
non-disclosure above. A consumer may set `blocking: true` on its own
binding; the flag is part of the declaration digest only when set, so
existing advisory digests are unchanged. Opting in discloses the binding to
producers:

- `ReportDefinitionConsumerImpact` lists blocking bindings whatever the
  caller can see, each marked `blocking`.
- `MergeDefinitionProposal` fails with `FAILED_PRECONDITION`
  (`definition_publish_blocked`) when the published revision would remove
  or change a member or property a valid blocking binding depends on, and
  names each such binding. A blocking binding with a stale digest does not
  block.
- A proposal created with `major_revision: true` is approved and merged as
  a new major revision and passes the gate. The flag is part of the approved
  proposal digest, so it cannot be added after approval. A replayed merge
  does not re-run the gate.

The gate reads bindings before the merge's compare-and-swap; a blocking
binding created during a merge applies to the next publish.
