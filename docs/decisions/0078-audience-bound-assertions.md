# ADR 0078: Audience-bound assertions fill existing AuthenticatedContext

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/905
- Issue: https://github.com/Sannrox/sekai-chisei/issues/888 (#888)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0070](0070-compatibility-matrix.md)

## Context

`EnterpriseExtension` is in-process. `AuthenticatedContext`
(`sekai.identity-extension/v1`) already carries principal, credential kind,
tenant, scopes, issuer, resource, and expiry. Request metadata must not
construct it. Issue #888 asked for an out-of-process assertion.

## Decision

1. A configured authority issues a short-lived signed assertion whose claims
   are the fields already on `AuthenticatedContext`, plus a one-use nonce.
   The plane verifies issuer keys, audience/resource, expiry, and replay,
   then fills the same context the in-process extension produces.
2. No authority configured remains today’s community behavior: tenant-free.
3. Caller-selected tenant headers never construct or widen context.
4. This ADR does not pick a browser identity protocol, own identity, or
   manage tenant lifecycle. Encoding details belong in the #888
   implementation change set.
5. The in-process trait stays until the assertion path has documented
   parity.

## Alternatives considered

- Keep in-process only. Rejected: that is the outage coupling the Issue
  names.
- Adopt a general-purpose browser session protocol as plane auth.
  Rejected: out of the community runtime.

## Consequences

#888 implements verification and the replay cache. The compatibility matrix
lists the assertion contract version when the feature ships.

## Validation

A valid assertion produces a context equal to the in-process path for the
same principal. Wrong audience, expired, replayed, or header-selected
identity fail closed with distinct reasons.
