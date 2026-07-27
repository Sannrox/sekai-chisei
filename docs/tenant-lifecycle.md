# Tenant data lifecycle contract (#127)

Domain-local inventory, export, retention, and closure for Sekai Chisei-owned
data under a verified tenant request. Enterprise owns cross-service privacy
orchestration.

## Version

`sekai.tenant-lifecycle/v1`

## Operations

| API | Role |
| --- | --- |
| `inventory` | Per-store counts, secret flags, retention reasons |
| `export` | Portable bundle without secrets |
| `close_tenant` | Idempotent/resumable closure with incomplete-store report |
| `progress` | Inspect last closure state |

## Rules

- Two-tenant isolation on export/closure.
- Billing evidence retention is explicit (`retain_reason`, `retain_until_ms`).
- Closed tenants fail secret resolution and work admission.
- Exports never include provider secrets or other tenants’ aggregates.
- Backups may remain incomplete (immutable window) without promising immediate
  disappearance.
