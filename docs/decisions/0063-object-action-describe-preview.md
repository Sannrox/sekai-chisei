# ADR 0063: Describe and preview object-bound Actions without a second admission plane

- Status: accepted
- Date: 2026-09-12
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/857
- Issue: https://github.com/Sannrox/sekai-chisei/issues/836 (#836)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0061](0061-quarantine-repair-preview.md)

## Context

Immutable `GovernedActionType` rows, closed parameter schemas, and
`SubmitActionInstance` admission already exist. Applications needed an
authorized object-bound description and a dry-run that could not be reused as
execution authority.

## Decision

`DescribeObjectAction` and `PreviewObjectAction` are observational projections
over a live object revision and an enabled update-bound Action version. They
never persist an instance, write an object, redeem a permit, or become a
submit token.

Describe requires object-read authorization, not action-admin. Preview uses
the same submit authorization as admission, then rechecks live state. Submit
remains `SubmitActionInstance`. Receipts remain `GetOperationReceipt`.
Compensation is explicit `unsupported` unless a type already stores a
supported contract. Hidden objects and types share one unavailable shape.

## Alternatives considered

A new preview/submit mutation RPC would invent a second write plane.
Treating a preview digest as execution authority would create a
time-of-check/time-of-use grant. Requiring action-admin for describe would
keep applications on the operator registry RPCs.

## Consequences

Authorized clients can inspect allowed fields and preview one request, then
submit only through existing admission. Follow-up work may add a first-class
approval RPC; preview reports `require_approval` without granting it.

## Validation

Deterministic tests prove two authorized callers see the same describe fields
and preview outcome; preview writes nothing; stale or changed state cannot
reuse a preview; hidden objects stay unavailable.
