# Tenant entitlement enforcement (#123)

Versioned entitlement sets from the enterprise authority. Entitlements **narrow**
product features and quota ceilings; they never widen governance policy,
grants, egress, approvals, budgets, or quotas beyond the assignment.

## Contract

| Type | Role |
| --- | --- |
| `EntitlementSet` | Versioned features + optional quota ceiling |
| `TenantEntitlementAssignment` | Active/removed assignment for a tenant |
| `EntitlementRegistry` | Resolve / require feature / narrow quotas |
| `EffectiveEntitlement` | Receipt-safe resolution record |

Version string: `chisei.entitlement-set/v1`.

## Rules

- Missing, removed, or expired assignments fail closed (`MissingAssignment` /
  `Expired`).
- Feature denial is a distinct error class from quota/budget/governance denial.
- Quota ceiling applies `min()` per dimension (narrow only).
- Migration default (`migration_entitlement_set`) is restricted, never unlimited.

## Relation to #119

`TenantQuotaGate` enforces limits; entitlements supply the ceiling and feature
flags. Operator-configured quotas that exceed the entitlement ceiling are
narrowed before admission.
