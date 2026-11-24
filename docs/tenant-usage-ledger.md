# Tenant usage event ledger (#122)

Immutable, tenant-scoped usage events projected from governed operation
receipts. Pricing, invoicing, and billing-provider sync are out of scope
(see #124).

## Contract

| Field | Role |
| --- | --- |
| `event_id` | Stable id |
| `tenant_id` | From verified enterprise context only |
| `unit` | `tokens` \| `requests` \| `input_tokens` \| `output_tokens` \| `compute_seconds` \| `storage_bytes` |
| `quantity` | Signed; corrections may be negative |
| `source` | `measured` \| `provider_reported` \| `estimated` \| `correction` |
| `receipt_operation_id` | Canonical operation receipt |
| `dedupe_key` | Replay-safe unique key |
| `corrects_event_id` | Optional append-only correction lineage |
| `principal_id` | Optional; the receipt's initiating actor, or the person an appending service acts for |
| `resource` | Optional `kind` and `id` of what consumed the usage, inside the namespace |
| `reported_by` | Optional; the service that appended `provider_reported` usage |

Version: `chisei.usage-event/v1`. Table: `chisei_usage_events`.

`tokens` is the total. A receipt also yields `input_tokens` and
`output_tokens` from its `input_tokens`/`prompt_tokens` and
`output_tokens`/`completion_tokens` attributes. Readers skip units they do not
know, so a newer release's events never break an older release's list or
export.

## APIs

- `project_usage_from_receipt(tenant_id, receipt)`: measured request, token
  total and split tokens, with the receipt's principal
- `append_usage_event` / `correct_usage_event`: append-only
- `aggregate_usage(tenant, unit, scope, …)`: per tenant, or narrowed by
  namespace and principal; `aggregate_usage_for_tenant` is the unscoped form
- `export_usage_period`: JSON lines for a period
- `ChiseiService.AppendUsageEvents` (experimental): a service holding a tenant
  assertion reports `compute_seconds` and `storage_bytes` it measured outside
  the plane ([ADR 0158](decisions/0158-reported-usage-enters-the-tenant-ledger.md)).
  A plane serves it only with `SEKAI_EXPERIMENTAL_RPCS=1` or the
  `experimental-rpcs` Cargo feature.

Replay of the same receipt is a no-op (dedupe). Corrections never mutate prior
rows.
