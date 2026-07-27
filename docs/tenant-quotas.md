# Tenant resource quotas (#119)

Bounds each tenant’s request rate, token use, concurrency, and retained storage
so one tenant cannot exhaust shared capacity. Commercial plans stay outside the
control plane; limits are versioned operator/enterprise assignments.

## Scope model

Tenant quotas use the existing replica-safe budget tables with scope id:

```text
tenant:{tenant_id}
```

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
- `admit(context, limits, min_version, estimated_tokens, idempotency_key)`
- `complete(admission, actual_tokens)` — release concurrency + reconcile tokens
- `charge_storage(tenant_id, limits, bytes)`

`AuthenticatedContext.tenant` is required. Stale assignment versions fail closed.
Exhaustion returns stable `TenantQuotaError::Exhausted` with a retry hint and
never includes another tenant’s usage.

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
