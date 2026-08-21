# Evidence adapter catalog

The control plane ships a built-in discovery catalog of **reference external
evidence adapters**. Composition products (for example Aldunis) use it to learn
which adapter families and schemas this release documents.

## API

gRPC: `SekaiService.ListEvidenceAdapters`

```text
ListEvidenceAdaptersRequest { registered_only }
→ ListEvidenceAdaptersResponse { adapters, families }
```

- Authenticated read (any principal).
- `registered_only=true` keeps only adapters whose `schema_id`+`schema_version`
  are registered on this deployment.
- `schema_registered` is always populated for each returned adapter.

Rust (same process / library consumers):

```rust
use sekai_chisei::evidence_adapter_catalog::{
    built_in_evidence_adapter_families, built_in_evidence_adapters,
};
```

## Fields

| Field | Meaning |
| --- | --- |
| `adapter_id` | Stable id (usually equals `schema_id`) |
| `family` | Connector kind grouping (e.g. `social.observation`) |
| `evidence_type` / `schema_id` / `schema_version` | Admission contract |
| `delivery` | `document`, `webhook`, or `poll` for the reference edge |
| `reference_example` | Cargo example target when present |

## Families (connector kinds)

| Family | Adapters |
| --- | --- |
| `source_control.check_run` | GitHub check_run |
| `operations.health` | HTTP health snapshot |
| `ontology.concept_catalog` | Concept catalog document |
| `social.observation` | `social.post_snapshot`, `social.reply` |
| `source_control.object_sync` | GitHub Issue / PullRequest object upsert |

## Non-goals

- Tenant enablement or UI (composition layer)
- Network credentials
- Auto-registering schemas; admission still requires explicit registration

See also [adapters/README.md](../adapters/README.md) and
[social-evidence-adapters.md](social-evidence-adapters.md).
