# Tenant resource quotas (#119)

Bounds each tenant’s request rate, token use, concurrency, and retained storage
so one tenant cannot exhaust shared capacity. Commercial plans stay outside the
control plane; limits are versioned operator/enterprise assignments.

## Scope model

Tenant quotas use the existing replica-safe budget tables with scope id:

```text
tenant:{tenant_id}
```

A namespace assignment (#3044, [ADR 0168](decisions/0168-tenant-and-namespace-quota-assignments.md))
is stored under the child scope:

```text
tenant:{tenant_id}/namespace:{namespace}
```

Neither part may contain `/`.

A transform run in a namespace reserves against its tenant and its namespace
together, or against neither. Each scope checks its own limit and the stricter
one wins. Requests and tokens reserve on the budget chain in one step.
Concurrency takes the tenant's hold first and then the namespace's under one
holder; if the namespace refuses, the tenant hold and the request are given
back. A namespace with no assignment shares what is left of its tenant. A
namespace assignment applies even when the tenant has none.

The claim's stored quota hold records the scope it reserved on
(`sekai_transform_quota_hold.quota_scope`). Every refund taken from the hold,
after a crash, a lease expiry, a cancel or a retry, reaches both scopes, and a
hold is taken once, so nothing is refunded twice. A hold written by an older
plane has an empty scope and refunds only the tenant. The namespace then stays
counted until its period or hold expires, which refuses rather than
over-admits. During a rolling deploy an older plane refunds a newer hold the
same way.

Project/namespace budgets remain on the hierarchical chain
(`global` / `project:…`). Tenant admission is an **additional** gate and never
widens a stricter project limit.

## Metrics

| Metric | Meaning |
| --- | --- |
| `tokens` | Period token budget |
| `requests` | Period request count |
| `concurrency` | In-flight operations (released on complete) |
| `storage_bytes` | Retained storage charge |

## API

`chisei::tenant_quota::TenantQuotaGate`:

- `configure(tenant_id, TenantQuotaLimits)` — operator assignment
- `configure_namespace(NamespaceQuotaScope, TenantQuotaLimits)` — namespace
  assignment (`DomainAdminSurface::configure_namespace_quotas` checks the
  role, refuses negative limits and narrows by entitlement)
- `admit(context, limits, min_version, estimated_tokens, idempotency_key)`
- `admit_in_namespace(context, limits, namespace, min_version,
  estimated_tokens, idempotency_key)` — tenant and namespace together
- `complete(admission, actual_tokens)` — release concurrency + reconcile tokens
- `charge_storage(tenant_id, limits, bytes)`

`AuthenticatedContext.tenant` is required. Stale assignment versions fail closed.
Exhaustion returns stable `TenantQuotaError::Exhausted` with a retry hint and
never includes another tenant’s usage.

An isolated-process run asks for one request and one concurrency unit. When
its tenant's or its namespace's limit for either is zero, the run can never fit, so the claim
refuses it for good: the run is marked `refused` with the code
`quota_larger_than_budget` and the details `metric`, `limit` and
`requested`.

Budgets refuse; only concurrency waits. When a claim finds the run's
tenant or namespace request or token budget spent, the run is marked
`refused` with the code `quota_budget_exhausted` and the detail `metric`,
and it reserves nothing. A full concurrency limit still leaves the run
`pending` until a unit frees.

Receipt-safe summary: `TenantQuotaReceiptNote` (own tenant id, assignment
version, admitted metrics only).

## Acceptance mapping

| Criterion | Evidence |
| --- | --- |
| Shared limit across concurrent work | Budget tables + existing replica-safe budget path |
| Exhausting A does not deny B | Isolation unit tests |
| No capacity leak on complete | Concurrency release test |
| Receipt without foreign usage | `TenantQuotaReceiptNote` |

## Non-goals

- Commercial plan catalogs or billing adapters (#124)
- Replacing namespace budgets or governance policy
