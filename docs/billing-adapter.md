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
in normal tests.

Subscription events apply per tenant in `occurred_at_ms` order. An event older
than the last applied one is recorded as processed but changes nothing; ties
apply in arrival order. Activation and replacement store the event's
entitlement set; expiry and removal clear it.

`verify_fake_webhook_signature` checks a hex HMAC-SHA256 of the body under the
shared secret and compares it in constant time.

## Non-goals

Card data, catalogs, prices, tax, revenue recognition, and real provider SDKs.
