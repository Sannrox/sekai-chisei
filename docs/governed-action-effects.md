# Typed ActionInstance effects

Issue: [#398](https://github.com/Sannrox/sekai-chisei/issues/398).  
Admission: [governed-action-instances.md](governed-action-instances.md).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

## Purpose

When an ActionInstance is **admitted**, the plane records durable **effect**
children from the type's `allowed_effect_kinds`. Effects are not silent log
lines; they have lifecycle status and bounded JSON payloads.

## Effect kinds (v1)

| Kind | On admit | Lifecycle |
| --- | --- | --- |
| `runtime_dispatch` | `pending` / semantic `ready` | Claimable by runtime hosts; intentional park waits for governed continuation (#399, #412) |
| `notify` | best-effort `sent` or `failed` | Failure **does not** un-admit the instance |
| `external_mutate` | `pending` when `permit_id` is present; otherwise `skipped` | Permit-backed write-back; completion, failure, and compensation stay on the permit path |

Unknown kinds are rejected at type registry time (#396) and at materialization.

## Write timing

1. **Internal SoR first:** ActionInstance row + operation receipt are durable
   before effects are written.
2. Effects are children of the admitted instance; they never replace the
   operation receipt spine.
3. **Permit-backed** mutate/write-back materializes `external_mutate` as
   `pending` only when parameters include `permit_id`. Plane-side mutation
   without a permit remains forbidden.

## Wire

| RPC | Role |
| --- | --- |
| (implicit) | Materialized on successful `SubmitActionInstance` |
| `GetActionEffect` | Read one effect |

## Notify failure

Set parameter `"notify_delivery": "fail"` to force a best-effort notify failure
for tests. The ActionInstance remains `admitted`; only the effect is `failed`.

## Non-goals

- Runtime claim/lease fencing — see [runtime-claim.md](runtime-claim.md) (#399)
- Generic HTTP webhook effects
- Plane-side external mutations without permits
