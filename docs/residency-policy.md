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

## Gunshi

Auto-dispatch and advisory selection must not pick a residency-illegal model;
call `ResidencyResolver::evaluate_namespace` after model resolution.

## Non-goals (this slice)

- Multi-region write topology (#292–#294)
- Cross-site federation wire protocol (#291)
