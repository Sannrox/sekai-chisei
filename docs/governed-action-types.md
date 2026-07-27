# Governed Action type registry

Issue: [#396](https://github.com/Sannrox/sekai-chisei/issues/396).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

## Purpose

Operators register **namespace-scoped, versioned decision types** that the plane
may admit later as `ActionInstance` records (#397). This is **not** the graph
mutation DSL (`CreateActionType` / `ExecuteAction`).

## Wire names

| Concept | RPC / message |
| --- | --- |
| Type record | `GovernedActionType` |
| Create / idempotent put | `PutGovernedActionType` |
| Read | `GetGovernedActionType` |
| List | `ListGovernedActionTypes` |
| Enable / disable (no history delete) | `SetGovernedActionTypeEnabled` |

Identity is `(namespace, type_id, version)`. Version bodies are **immutable**
after first put; change fields by registering a new version. Disable keeps the
row for history.

## Fields

| Field | Meaning |
| --- | --- |
| `parameter_schema_json` | JSON object (JSON Schema or plane map) |
| `allowed_effect_kinds` | Subset of `runtime_dispatch`, `notify`, `external_mutate` |
| `policy_scope` / `budget_scope` | Empty = use namespace defaults |
| `enabled` | Fail-closed gate for submit ([#397](governed-action-instances.md) uses `require_enabled`) |

## Authz

Mutations require namespace write + action-admin (same shape as capability-package
admin). Reads require authentication, team namespace membership, and action-admin
on `governed_action:{namespace}`.

## Non-goals

- Condition engines that auto-submit actions
- Running agent turns or hosting runtimes
- Domain webhook / GitHub type packs in core
- Replacing graph `ExecuteAction`

## Dual-backend

SQLite and PostgreSQL both persist the registry (migration
`0020_governed_action_types` / SQLite migrate on first use).
