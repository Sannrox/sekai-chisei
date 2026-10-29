# ADR 0142: Agent-turn workers carry the turn's authority, not their own

- Status: accepted
- Date: 2026-10-29
- Owners: @Sannrox
- Discussion: none, resolved in Issue #1982
- Issue: #1982
- Supersedes: none
- Superseded by: none
- Related: [ADR 0099](0099-shared-identity-and-tenancy.md),
  [ADR 0136](0136-site-agent-instances.md),
  [ADR 0137](0137-agent-turns-share-the-scheduling-split.md), #1611, #1950

## Context

A turn acts as its instance's principal, and the worker holds no authority
of its own (ADR 0137). The agent-turn RPCs do not yet make that true:

- a turn worker must be credential admin (root or local) to list, claim,
  heartbeat and ack turns, so it holds far more than one turn needs;
- a claim mints no runtime token, so the worker can act only with a static
  credential, and nothing binds what it submits to the turn it holds;
- an ack is `completed` or `failed`, so a turn whose Action parks for
  approval has no way to stop and resume after the decision.

Action work already has the parts: per-claim runtime tokens (ADR 0099),
service principals with a registered scope, and Actions that park for
approval and apply once when granted.

## Decision

1. **Turn runtime tokens.** A turn claim, and each heartbeat, mints a
   runtime token in the ADR 0099 format and key, bound to the turn: its
   namespace, turn id, runtime id and claim generation. Its subject is the
   instance's `principal_id`; `act` names the worker that claimed it. It
   expires with the claim, after at most 15 minutes, and never after the
   worker's own credential. It is minted where ADR 0099 mints Action-work
   tokens: with a signing key and a tenant context, never for a guest.
   - It admits only `HeartbeatAgentTurnClaim`, `AckAgentTurn` and
     `SubmitActionInstance`. Every use checks the turn's current claim: the
     same generation, still claimed, lease unexpired. A lost fence refuses
     the call.
   - The instance's freeze and the write freeze hold as for any agent
     write: Action admission refuses a frozen instance's principal, and a
     runtime-token caller is an agent actor.
2. **Scoped turn workers.** A service principal whose registration lists
   the capability `agent_turn_worker` may list, claim, heartbeat and ack
   turns in its registered namespaces. Nothing else it holds widens:
   it submits Actions only with a turn's token, as the instance's principal.
   Credential admin keeps working for local and single-operator planes.
3. **Parked turns.** `AckAgentTurn` gains the outcome `parked`, naming the
   Action the turn submitted that parked for approval. The turn becomes
   `parked`, and its claim ends.
   - It becomes claimable again once that Action is decided. Claimability is
     read from the Action at claim time, not pushed by the decision, so a
     crash between the decision and a reclaim loses nothing.
   - The next claim carries a continuation: the parked Action's id and its
     decision, as recorded by the Action. A granted Action has already been
     applied, once, by its grant; the resumed turn reads the outcome and does
     not apply it again, and a resubmission dedupes on its idempotency key.
   - A turn parks at most three times, as runtime work does; a further park
     fails the turn. A frozen instance's parked turn is not reclaimed.

Delivery is in layers, one Pull Request each: turn runtime tokens, scoped
turn workers, then parked turns.

## Alternatives considered

- Static worker credentials scoped per instance. Rejected: a credential per
  instance multiplies secrets, and outlives the claim it is used for.
- A new token family. Rejected: the ADR 0099 format, key and interceptor
  already carry a claim-bound subject; a binding to a turn is a new claim,
  not a new mechanism.
- Pushing turns back to the queue when an Action is decided. Rejected: the
  decision path would gain a second write with its own failure modes; reading
  the Action at claim time is one source of truth.

## Consequences

A turn worker needs a registered service principal, or credential admin, and
no static credential that acts as an instance. A runtime host such as
Shikigami's site-agent profile consumes turns with a scoped credential and
acts only through each turn's token. Planes without a tenant context mint no
turn tokens, as for Action work.

## Validation and reversal

Tests where turns and instances are kept (turns on both stores, instances
on SQLite, ADR 0136): a turn's token admits its principal's Action
submission and is refused once the fence is lost or the instance is frozen;
a service principal with the capability claims and acks turns, and one
without it is refused; a turn acked `parked` is reclaimed with its
continuation after the decision, and the resumed run applies the Action
once. Reverse with a later ADR; tokens, the capability and the outcome are
additive.
