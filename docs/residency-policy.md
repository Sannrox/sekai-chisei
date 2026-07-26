# Provider and data-class residency (single plane)

Issue: [#289](https://github.com/Sannrox/sekai-chisei/issues/289)  
Architecture freeze: [research/288-federation-residency-architecture.md](research/288-federation-residency-architecture.md)

## Posture

- **Default unrestricted** when no residency policy is configured (compatible).
- Once configured, checks **fail closed** before provider contact.
- Single control plane only; multi-site import is #290/#291.

## Constraint shape (`ResidencyPolicy`)

| Field | Meaning |
| --- | --- |
| `allowed_regions` | If non-empty, provider/model region tags must be in this set |
| `provider_regions` | Map provider id → region label |
| `model_regions` | Map model id → region label |
| `allowed_data_classes` | If non-empty, operation data class must be listed |
| `policy_id` / `version` | Cited on deny/allow decisions and receipt attributes |

Wildcards (`*`) and empty region labels are rejected.

## Decision + receipts

`ResidencyDecision` records allow/deny, resolved regions, and reasons.
Receipt attributes (when applied):

- `residency_allowed`
- `residency_policy_id` / `residency_policy_version`
- `residency_provider_region` / `residency_model_region` (when known)
- `residency_denial_reasons` on deny

## Call sites (wired)

| Surface | Behavior |
| --- | --- |
| `PlanExecution` / `resolve_model_for_run` | Enforces residency after final model/runtime resolution |
| `ExecutePlan` / `ExecutePlanStream` | Re-checks residency so cached plans cannot outrun policy |
| `DecideGatewayExecution` | Enforces residency as part of fat-decide route composition |
| Gunshi `AuthorizeGunshiAutoDispatch` | Forces advisory + denial reasons when selected model is residency-illegal; stamps receipt attributes |

## Gunshi

Auto-dispatch cannot authorize a residency-illegal model. Advisory selection
still ranks candidates; the authorize path fail-closes before automatic mode
is granted.

## Setting policy

In-process: `PolicyResolver::set_residency_policy(namespace, policy)`.
Durable namespace policy objects for residency (alongside route policy load)
remain an optional follow-up; process-local set is sufficient for tests and
single-plane control-plane configuration today.

## Non-goals (this slice)

- Multi-region write topology (#292–#294)
- Cross-site federation wire protocol (#291)
- Durable residency policy object schema / SetResidencyPolicy RPC (follow-up)
