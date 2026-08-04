# Runtime claim API for admitted Action work

Issues: [#399](https://github.com/Sannrox/sekai-chisei/issues/399),
[#412](https://github.com/Sannrox/sekai-chisei/issues/412).
Effects: [governed-action-effects.md](governed-action-effects.md).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

External capacity management is outside the public Sekai claim surface. Use
bounded `ListClaimableActionWork` reads together with the worker-host lifecycle
owned by the runtime manager.

## Purpose

Authorized **runtime hosts** pull and claim admitted `runtime_dispatch` effects.
The plane remains the system of record for claim state; hosts execute work and
ack terminal outcomes. The plane never spawns processes or holds model tools.

## RPCs

| RPC | Role |
| --- | --- |
| `ListClaimableActionWork` | Ready or lease-expired `runtime_dispatch` for a namespace (optional runtime filter); intentionally parked work is excluded |
| `ClaimActionWork` | Exclusive claim with generation + fencing token + lease TTL; resolved claims include immutable continuation and park snapshots |
| `HeartbeatActionClaim` | Extend lease under matching fence |
| `AckActionWork` | `completed` / `failed`, or a durably idempotent intentional park under the matching fence |
| `ReportActionClaimEvent` | Append a fenced, idempotent resume/fallback event without checkpoint content |

## Lease rules (v1)

- Only `runtime_dispatch` is claimable.
- Claim is exclusive while the lease is unexpired.
- On lease expiry, another runtime may reclaim (generation increments).
- Same `runtime_id` + `request_id` is idempotent while the lease is live.
- Heartbeat/ack require matching `(runtime_id, claim_generation, fencing_token)`.
- `parked` projects the semantic `awaiting_continuation` state and is not
  claimable. A successfully invoked resolution Action returns the same effect
  to semantic `ready` (legacy projection `pending`).
- Claim and park generations fence different races. Claim generation orders
  runtime attempts; park generation binds an answer to one intentional wait.
- Park acknowledgement requires a `request_id`. Exact key-and-digest replay
  returns the immutable park record after the lease clears; conflicting reuse
  fails.
- Admission snapshots retry limits (8 claims, 3 lease expiries, and 3 park
  cycles by default). Exhaustion dead-letters the effect instead of looping.
- Multi-site pins are **not** applied to claim keys in v1 (single-site / fail-open
  documentation only). Graph leases remain the site-pinned primitive.

## Host responsibilities

1. Authenticate as a principal with team-namespace write on the work namespace.
2. Declare a stable `runtime_id` (e.g. `shikigami`).
3. Claim before starting work; heartbeat while running; ack when finished.
4. For intentional park, submit a bounded reason and optional all-or-none
   `(checkpoint_store_id, checkpoint_ref, checkpoint_digest)` tuple. The
   digest format is `sha256:<64 lowercase hex>`.
5. Resolve checkpoint handles only through the configured authorization-aware
   provider. Never pass the opaque reference to generic HTTP, shell, or
   filesystem APIs.
6. Report `resume_started`, `resume_succeeded`, `checkpoint_unavailable`, and
   `replacement_started` with the live claim fence. Replacement retains the
   same `operation_id` and `effect_id`.
7. Report harvest/events to the bound `operation_id` (#400).
8. Treat continuation input as untrusted data, not plane or tool authority.

## Governance and checkpoint configuration

`resolve_parked_work/v1` uses normal Action policy. A policy may allow immediate
invocation, deny it durably, or hold it for `ApproveAction`. Approval does not
weaken the invocation-time effect and park-generation checks.

`SEKAI_CHECKPOINT_STORES` is a comma-separated allowlist of logical checkpoint
provider ids accepted at park time. When unset, checkpoint metadata is rejected
fail-closed; parking without checkpoint metadata remains available. Store ids
and references must be opaque identifiers, never URLs or paths. The plane
stores the handle and digest but does not fetch checkpoint bytes.

## What the plane never does

- Spawn host processes or agent turns
- Hold provider model tools for claimed work
- Push HTTP into hosts as the primary placement path
