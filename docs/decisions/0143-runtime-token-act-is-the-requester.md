# ADR 0143: Runtime-token `act` is the delegating requester

- Status: accepted
- Date: 2026-11-07
- Owners: @Sannrox
- Discussion: none, resolved in Issue #2026
- Issue: #2026
- Supersedes: [ADR 0142](0142-agent-turn-worker-authority.md) for the turn-token `act` claim only
- Superseded by: none
- Related: [ADR 0099](0099-shared-identity-and-tenancy.md),
  [ADR 0139](0139-site-agent-working-memory.md)

## Context

Action-work tokens and agent-turn tokens share `sekai.runtime-token/v1`.
ADR 0139 defines `act` as the delegating user of the calling token, used
as the requester when an agent reads working memory. ADR 0142 minted turn
tokens with `act` as the claiming worker, so one field in one version had
two meanings. Follow-up checks that bind "agent and requester" then ran
against the worker. A credential-admin worker made the requester check a
no-op.

## Decision

1. **`act` is the delegating user on every runtime token.** On an
   Action-work token it remains the claiming context's `act`. On a turn
   token it is the human requester recorded at turn admission (a manual
   wake's `admitted_by`), or absent for scheduled and change-driven
   turns. It is never the claiming worker.
2. **The claiming worker is a distinct `worker` claim** on turn tokens.
   Action-work tokens omit it, so their encoding is unchanged. Follow-up
   calls run as the instance principal with `act` the requester;
   `requester_principal` keeps reading `act`, else the caller. When `act`
   is absent, the dual-principal check is the agent alone.
3. **Admission is the source of the requester.** A worker's own `act` at
   claim time is not the person the turn acts for and is not copied onto
   the turn token.

## Alternatives considered

- Keep `act` as the worker and add a separate requester claim. Rejected:
  every `act` consumer would keep misattributing turn traffic, and ADR
  0139 would still conflict with ADR 0142.
- Encode the worker as OIDC `azp`. Rejected: `worker` names the role in
  this contract; the token family is not an OIDC access token.

## Consequences

Turn tokens minted after this change include `worker`. Verifiers that
deny unknown fields refuse those tokens until they learn the claim; that
fails closed across a rolling deploy. In-flight tokens that still carry
the worker in `act` expire with the claim, at most 15 minutes.
`RuntimeTokenClaims` gains a public `worker` field.

## Validation

Tests cover: a manual turn token has `act` as the admitter and `worker`
as the claimer; a scheduled turn token has no `act`; a worker's own `act`
is not copied; a working-memory read with the turn token filters as the
admitted requester, not as a credential-admin worker; Action-work tokens
still omit `worker`.
