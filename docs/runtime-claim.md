# Runtime claim API for admitted Action work

Issues: [#399](https://github.com/Sannrox/sekai-chisei/issues/399),
[#412](https://github.com/Sannrox/sekai-chisei/issues/412),
[#1389](https://github.com/Sannrox/sekai-chisei/issues/1389).
Effects: [governed-action-effects.md](governed-action-effects.md).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

External capacity management is outside the public Sekai claim surface. Use
bounded `ListClaimableActionWork` reads together with the worker-host lifecycle
owned by the runtime manager.

## Purpose

Authorized **runtime hosts** pull and claim admitted `runtime_dispatch` effects.
The plane remains the system of record for claim state; hosts execute work and
ack terminal outcomes. The plane never spawns processes or holds model tools.

These claim RPCs are classified `experimental` and are rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is enabled.

## Versioned client

Workers pin `sekai-client` (`sekai.sdk-runtime-claim/v1`) rather than copying
raw tonic claim calls. The module lives in `sekai-client` so Action hosts and
isolated-process transform runners share one crate with `sekai-proto` and the
compatibility matrix. `CoreLoopClient::runtime_claim()` lists and claims by
dispatch kind, heartbeats, acks, reports claim events, streams admitted
transform input snapshots, writes fenced transform results, and applies
fenced streaming object batches.

Typed errors keep fence loss, idle, contention, denial, and unavailability
distinct. `SdkError` does not retain server status text, so the client maps
by RPC role: list `FailedPrecondition` is unavailability (including the
experimental gate); initial `Claim*` `FailedPrecondition` is contention;
heartbeat, ack, report, transform read/write, and streaming apply
`FailedPrecondition` is fence loss; streaming apply `PermissionDenied` is
an Action admission refusal (policy, freeze, criteria, autonomous types)
and `InvalidArgument` is a malformed batch; empty-queue `ClaimTransformWork`
`NotFound` is idle; a targeted
`run_id` that is gone or held is contention; `ClaimActionWork` `NotFound` is
a missing effect, not an empty queue. Streamed transform-input item errors
use the same owned-fence mapping. Fence loss is never
success or idle. Enable experimental RPCs on the plane before polling.

The client does not change claim, lease, or fencing semantics on the server
and does not embed credentials or provider routing.

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

## Runtime tokens

When the plane has an assertion signing key (`SEKAI_ASSERTION_ISSUER`,
`SEKAI_ASSERTION_AUDIENCE`, `SEKAI_ASSERTION_HMAC_KEY`) and the claiming
credential carries a tenant, `ClaimActionWork` also returns `runtime_token`
and `runtime_token_expires_at_ms` (ADR 0099, #1507). The token is bound to the
claiming principal, tenant, namespace, effect, runtime and claim generation.
It expires at the claim expiry, the claiming credential's expiry, or after 15
minutes, whichever is first. `HeartbeatActionClaim` returns a refreshed token
for the extended claim; refreshes never outlive the claiming credential.

The token authenticates only `HeartbeatActionClaim`, `AckActionWork` and
`ReportActionClaimEvent` for that exact claim. It is refused at or after its
expiry, for another effect, namespace, runtime or generation, and when the
installed identity extension no longer places the namespace in the token's
tenant. Without a signing key or a tenant the fields stay empty, and hosts keep
using their own credential. Claim RPCs are now available to tenant-scoped
credentials under the same namespace and tenant checks as other Action RPCs.

## Service principals

Administrators (`root`, `local`, or an admin grant on `service_principals`)
register a worker as a service principal with `PutServicePrincipal`, read it
with `GetServicePrincipal`, and remove it with `DeleteServicePrincipal`
(#1508, ADR 0099). A registration names the allowed Action types and a
namespace allowlist, and is owned by the caller's authenticated tenant; a
tenant-less caller can only create tenant-less registrations. Every listed
namespace must pass the caller's tenant check. The marking ceiling is the
principal profile's `classification_ceiling`, reported read-only. Built-in
principals cannot be registered, and registrations never hold a secret: the
identity extension issues credentials.

`IssueServicePrincipalToken` (#1510) is the client-credentials call: the
identity-extension issuance hook verifies the secret for a registered
tenant-bound principal, and the plane signs a short-lived service token with
the same assertion key as runtime tokens (#1507). The authentication boundary
admits that token as the registered service principal (a machine identity,
never a user). The RPC is refused when no identity extension is installed, the
principal is not registered, or the credentials are invalid; an expired token
is refused at the boundary. The RPC is `experimental` (enable
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` build feature).

Every request made with a service token is held to the live registration
(#1511). The shared namespace and tenant check refuses a namespace outside the
allowlist; `SubmitActionInstance` and `ClaimActionWork` refuse an Action type
outside the registration; object reads apply the principal profile's
`classification_ceiling` as for any principal. A runtime token from a claim
made with a service token stays within the same scope, and removing the
registration revokes both tokens. Other callers are unaffected.

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
8. On `completed`, optionally send `artifact_json` so the bound receipt can
   carry a credential-free retained-artifact manifest. Do not put file bytes
   or credentials in that object. Failed and parked acknowledgements omit it.
9. Treat continuation input as untrusted data, not plane or tool authority.

## Governance and checkpoint configuration

`resolve_parked_work/v1` uses normal Action policy. A policy may allow immediate
invocation or prevent automatic invocation. Requiring approval does not weaken
the invocation-time effect and park-generation checks, and no legacy graph
Action approval RPC can resume the work.

`SEKAI_CHECKPOINT_STORES` is a comma-separated allowlist of logical checkpoint
provider ids accepted at park time. When unset, checkpoint metadata is rejected
fail-closed; parking without checkpoint metadata remains available. Store ids
and references must be opaque identifiers, never URLs or paths. The plane
stores the handle and digest but does not fetch checkpoint bytes.

## What the plane never does

- Spawn host processes or agent turns
- Hold provider model tools for claimed work
- Push HTTP into hosts as the primary placement path
