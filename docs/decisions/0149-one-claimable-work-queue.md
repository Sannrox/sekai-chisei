# ADR 0149: One claimable work queue, with typed kinds

- Status: accepted
- Date: 2026-11-08
- Owners: @Sannrox
- Discussion: none
- Supersedes: none
- Superseded by: none
- Related: [ADR 0129](0129-scheduling-ownership.md),
  [ADR 0137](0137-agent-turns-share-the-scheduling-split.md),
  [ADR 0148](0148-sources-and-one-connector-runtime.md)

## Context

ADR 0129 defines one claim contract: a claim has an owner, a TTL within the
plane's bounds, a generation and a fencing token; a lapsed claim may be
reclaimed, which raises the generation; only the current claim may write
back; repeated lease expiries fail the run. ADR 0137 applies the same
contract to agent turns.

The contract is shared. The implementation is not. Three work kinds each
carry their own:

| Kind | Storage | RPCs |
| --- | --- | --- |
| Transform work | `sekai_transform_work` | `ListClaimableTransformWork`, `ClaimTransformWork`, `HeartbeatTransformClaim` |
| Action work | claim fields in the Action effect record | `ListClaimableActionWork`, `ClaimActionWork`, `HeartbeatActionClaim`, `AckActionWork` |
| Agent turns | `sekai_agent_turn` | `ListClaimableAgentTurns`, `ClaimAgentTurn`, `HeartbeatAgentTurnClaim`, `AckAgentTurn` |

The claim state is the same in all three: owner, generation, fencing token
and expiry, plus a lease-expiry count where the kind limits reclaims.
Transform work and agent turns keep it as columns. Action effects keep it in
the effect record. `sekai-client/src/claim.rs` maps the
three wire families back onto one set of errors. Every fix to fencing,
reclaim or error mapping is made three times, and a new kind adds a fourth
family. ADR 0148 would add three more: source syncs, export deliveries and
writeback effects.

## Decision

1. **One claim engine.** The claim, heartbeat, reclaim, fence check and
   acknowledge logic lives in one module in `sekai-core`, for SQLite and
   PostgreSQL. It works on one claim record (owner, generation, fencing
   token, expiry, lease expiries) that each kind reads and writes inside
   its own row, in the same transaction as the kind's state. The existing
   tables keep their rows and layout. A kind registers how to find
   claimable rows, how to read and write its claim record, and its payload
   loader.
2. **Work kinds are typed.** A kind is a closed enum value with a stable
   wire name: `transform`, `action`, `agent_turn`. ADR 0148 adds
   `source_sync`, `export_delivery` and `external_effect`. A kind owns its
   payload, its admission rules and its write-back. The engine owns
   everything about who holds the work.

   An item is a kind only when exactly one consumer must act on it and
   the action has a side effect worth fencing. A per-recipient inbox
   (violation notifications) and a feed with no recipient (the criticality
   outbox) are not kinds.
3. **One RPC family.** `ListClaimableWork`, `ClaimWork`, `HeartbeatWorkClaim`
   and `AckWork` take a kind. The response carries a kind-specific payload
   as a `oneof`. Errors are one set: idle, contention, fence lost, denied,
   unavailable. Placement labels (ADR 0129) and the per-kind
   `accepts_continuation` style flags become kind options on the request.
4. **The old RPCs stay, as wrappers.** Each existing family calls the
   engine and keeps its wire shape until the next major version. A rolling
   deploy mixes old and new planes without a schema change. Old and new
   claim calls on the same row see the same generation and token.
5. **One set of gauges.** The ADR 0129 queue-depth gauges are labelled by
   `kind` as well as `profile` and `pool`, with no tenant or namespace
   labels.

## Alternatives considered

- **One table for all work.** Simpler reads, but the migration moves every
  live claim, and both versions of a rolling deploy would have to read both
  layouts. The claim state is already the same, so one engine gets the
  benefit without the move. A table can follow later if a query needs it.
- **Unify only the client.** That is today's state. The plane still keeps
  three implementations of fencing.
- **Leave it, and add the ADR 0148 kinds as new families.** Six families
  with one contract.

## Consequences

- Fencing, reclaim and error mapping are fixed once.
- A new kind is a row with the claim record, a payload loader and a
  write-back. It needs no new RPCs and no new client code.
- `sekai-client` exposes one claim client. The per-kind helpers become thin
  calls into it.
- ADR 0148's claims are kinds of this queue.
- Other claim-like state stays out of scope: Chisei work units, gateway
  dispatch claims, the export lease (ADR 0130) and the dataset-run lease
  holder. Each moves onto the engine only when it is next changed.

## Validation

- One conformance suite runs against every kind on both stores:
  - claim, heartbeat, expiry, reclaim with a higher generation;
  - write-back refused for a stale token;
  - failure after the lease-expiry limit.
- A rolling-deploy test claims a row through an old RPC and acknowledges
  it through `AckWork`, and the reverse.
