# Tenant usage event ledger (#122)

Immutable, tenant-scoped usage events projected from governed operation
receipts. Pricing, invoicing, and billing-provider sync are out of scope
(see #124).

## Contract

| Field | Role |
| --- | --- |
| `event_id` | Stable id |
| `tenant_id` | From verified enterprise context only |
| `unit` | `tokens` \| `requests` |
| `quantity` | Signed; corrections may be negative |
| `source` | `measured` \| `provider_reported` \| `estimated` \| `correction` |
| `receipt_operation_id` | Canonical operation receipt |
| `dedupe_key` | Replay-safe unique key |
| `corrects_event_id` | Optional append-only correction lineage |

Version: `chisei.usage-event/v1`. Table: `chisei_usage_events`.

## APIs

- `project_usage_from_receipt(tenant_id, receipt)` — measured request + tokens
- `append_usage_event` / `correct_usage_event` — append-only
- `aggregate_usage_for_tenant` / `export_usage_period` — period views

Replay of the same receipt is a no-op (dedupe). Corrections never mutate prior
rows.
