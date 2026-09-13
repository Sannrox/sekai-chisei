# ADR 0067: Report consumer impact from registered declarations only

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/863
- Issue: https://github.com/Sannrox/sekai-chisei/issues/837 (#837)
- Supersedes: none
- Superseded by: none
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
