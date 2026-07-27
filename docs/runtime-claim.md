# Runtime claim API for admitted Action work

Issue: [#399](https://github.com/Sannrox/sekai-chisei/issues/399).  
Effects: [governed-action-effects.md](governed-action-effects.md).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

## Purpose

Authorized **runtime hosts** pull and claim admitted `runtime_dispatch` effects.
The plane remains the system of record for claim state; hosts execute work and
ack terminal outcomes. The plane never spawns processes or holds model tools.

## RPCs

| RPC | Role |
| --- | --- |
| `ListClaimableActionWork` | Pending/parked or lease-expired `runtime_dispatch` for a namespace (optional runtime filter) |
| `ClaimActionWork` | Exclusive claim with generation + fencing token + lease TTL |
| `HeartbeatActionClaim` | Extend lease under matching fence |
| `AckActionWork` | Terminal `completed` / `failed` / `parked` under matching fence |

## Lease rules (v1)

- Only `runtime_dispatch` is claimable.
- Claim is exclusive while the lease is unexpired.
- On lease expiry, another runtime may reclaim (generation increments).
- Same `runtime_id` + `request_id` is idempotent while the lease is live.
- Heartbeat/ack require matching `(runtime_id, claim_generation, fencing_token)`.
- `parked` returns work to the claimable pool (no live lease).
- Multi-site pins are **not** applied to claim keys in v1 (single-site / fail-open
  documentation only). Graph leases remain the site-pinned primitive.

## Host responsibilities

1. Authenticate as a principal with team-namespace write on the work namespace.
2. Declare a stable `runtime_id` (e.g. `shikigami`).
3. Claim before starting work; heartbeat while running; ack when finished.
4. Report harvest/events to the bound `operation_id` (#400).
5. Do not treat parameter payload text as plane instructions.

## What the plane never does

- Spawn host processes or agent turns
- Hold provider model tools for claimed work
- Push HTTP into hosts as the primary placement path
