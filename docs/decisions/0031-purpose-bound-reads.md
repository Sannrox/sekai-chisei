# ADR 0031: Require a scoped purpose authorization for governed reads

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/755
- Issue: https://github.com/Sannrox/sekai-chisei/issues/678
- Supersedes: none
- Superseded by: none

## Context

ADR 0007 fail-closes marked objects and purpose-gates actions through sealed
principal profiles. It does not require a declared, scoped, expiring purpose
for governed reads.

## Decision

When an activated `sekai.object-security-policy/v1` names `required_purpose`,
public reads of that kind must present a live `sekai.purpose-authorization/v1`
via `x-sekai-purpose`. The authorization is actor-bound, scoped to a namespace
and optional kind, time-bounded, and pinned to the current policy activation
digest. It is not an object grant.

Missing, incompatible, expired, wrong-actor, stale-activation, or out-of-scope
purpose denies before access. Hidden rows stay observationally identical to
absent rows. Applicable allows record value-free `purpose.read` evidence.

Unactivated namespaces and policies that omit `required_purpose` stay as today.
Trusted service principals remain an explicit exception. SQLite is the reference
store; PostgreSQL fails closed as unavailable for purpose authorizations.

## Alternatives considered

Reusing only `allowed_purposes` on principal profiles has no expiry, actor
binding, or policy-revision pin. Per-object purpose properties recreate grant
fan-out. Client-declared purpose without a stored authorization is not
authority.

## Consequences

Operators who want purpose-bound reads install a policy revision that names
`required_purpose` and issue matching authorizations through
`PutPurposeAuthorization` (revocation through `RevokePurposeAuthorization`).
Hierarchical classifications and property-level reads remain separate Issues.

## Validation

Pure tests cover missing, incompatible, expired, actor, policy-revision, and
scope denials. SQLite persists authorizations in normal CI.
