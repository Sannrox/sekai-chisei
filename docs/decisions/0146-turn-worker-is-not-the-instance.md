# ADR 0146: A turn worker is never the instance principal

- Status: accepted
- Date: 2026-11-08
- Owners: @Sannrox
- Discussion: none, resolved in Issue #2047
- Issue: #2047
- Amends: [ADR 0142](0142-agent-turn-worker-authority.md)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0139](0139-site-agent-working-memory.md),
  [ADR 0143](0143-runtime-token-act-is-the-requester.md), #1982, #2026

## Context

ADR 0142 forbids a static credential that acts as an instance, and mints a
turn token whose subject is the instance `principal_id`. It did not refuse a
worker whose subject *is* that principal. Registering the instance as
`agent_turn_worker` (or claiming as a credential admin that is the instance)
was accepted, and the token then named the same principal as both instance
and worker.

ADR 0142 also left the turn-token read set open: the token admits
`ListSiteAgentWorkingMemory` (#1968) while `GetObject` and
`GetOperationReceipt` stay refused as not claimed work.

## Decision

1. **Worker identity.** A turn worker's subject must not equal the turn's
   instance `principal_id`. Claim (named or next), heartbeat, and ack refuse
   with `turn worker must not be the instance principal`. Credential-admin
   workers are included. `claim_next` skips those turns instead of leasing
   them, so a refusal does not hold the fence until expiry.
2. **Turn-token read set.** A turn token admits `HeartbeatAgentTurnClaim`,
   `AckAgentTurn`, `SubmitActionInstance`, and `ListSiteAgentWorkingMemory`
   for its live claim. `GetObject` and `GetOperationReceipt` stay off the
   token. Object and receipt reads go through the worker's own credential,
   bounded by its registration or by credential-admin scope.

## Alternatives considered

- Admit `GetObject` and `GetOperationReceipt` on the turn token under
  turn-scoped checks. Rejected: the token already acts as the instance;
  widening it to arbitrary object reads is a separate contract, and the
  worker already has a credential for those calls.
- Claim the turn, then refuse. Rejected: the lease would sit until expiry
  and starve other workers.

## Consequences

A site agent instance cannot consume its own turns. Working-memory reads
on the token stay the instance-and-requester intersection (ADR 0139, ADR
0143). Hosts that need `GetObject` or `GetOperationReceipt` keep using the
worker credential alongside the turn token.

## Validation

Tests cover: a registered worker whose principal is the instance is refused
on named claim and skipped by `claim_next` without taking the lease; a
credential-admin worker matching the instance is refused; a turn token
whose `worker` equals the instance is refused on heartbeat; `GetObject` and
`GetOperationReceipt` stay off the token.
