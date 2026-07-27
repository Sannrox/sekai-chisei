# Billing adapter contract (#124)

Provider-neutral adapter for synchronizing external subscription state and
closed usage periods. The adapter is **not** authority for tenants, usage, or
entitlements.

## Operations

| Method | Role |
| --- | --- |
| `link_customer` | Bind external customer ref to local tenant id |
| `publish_closed_usage` | Idempotent closed-period usage publication |
| `apply_normalized_event` | Apply verified, normalized webhook events |
| `reconcile_period` | Observe drift vs last local publication |

Version: `chisei.billing-adapter/v1`.

## Fake adapter

`FakeBillingAdapter` covers retries (duplicate publish), duplicate events,
customer link refusal, and reconciliation without any provider SDK or secrets
in normal tests. Signature verification is demonstrated with a toy HMAC.

## Non-goals

Card data, catalogs, prices, tax, revenue recognition, and real provider SDKs.
