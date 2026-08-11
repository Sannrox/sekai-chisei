# Governed Action type registry

Issue: [#396](https://github.com/Sannrox/sekai-chisei/issues/396).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

## Purpose

Operators register **namespace-scoped, versioned decision types** that the plane
may admit later as `ActionInstance` records (#397).

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
| `parameter_schema_json` | Immutable closed parameter schema validated at `SubmitActionInstance` admission |
| `allowed_effect_kinds` | Subset of `runtime_dispatch`, `notify`, `external_mutate` |
| `policy_scope` / `budget_scope` | Empty = use namespace defaults |
| `enabled` | Fail-closed gate for submit ([#397](governed-action-instances.md) uses `require_enabled`) |

## Authz

Mutations require namespace write + action-admin. Reads require authentication,
team namespace membership, and action-admin on `governed_action:{namespace}`.

## Parameter schema

`parameter_schema_json` uses the same deliberately closed JSON-Schema subset as
Chisei evaluation plans:

- the root must be an object with `properties`, `required`, and
  `additionalProperties: false`;
- properties use only `string`, `number`, `integer`, or `boolean` types; and
- properties may declare `enum`, numeric `minimum`/`maximum`, or string
  `minLength`/`maxLength` constraints.

`SubmitActionInstance` validates producer parameters against the exact
immutable `(namespace, type_id, version)` schema before policy, admission, or
effect materialization. Unknown fields and values outside the declared subset
fail closed with a bounded error. Parameter bodies remain untrusted data and
are never copied into audit or receipt evidence.

There is no object-only compatibility path. A type whose stored schema does not
satisfy this closed subset cannot admit a new `ActionInstance`; it fails closed
at submission. Existing type rows and historical instances are not rewritten.
An exact idempotent re-put of an existing row may return that row without
rewriting it, but does not restore object-only admission. Publish a new
immutable type version with a closed v1 schema when replacing an older
definition.

## Non-goals

- Condition engines that auto-submit actions
- Running agent turns or hosting runtimes
- Domain webhook / GitHub type packs in core
- An in-process graph-mutation action DSL

## Dual-backend

SQLite and PostgreSQL both persist the registry through the existing
`0020_governed_action_types` schema (SQLite migrates on first use). No schema
migration or data rewrite is required for admission enforcement; both backends
validate the stored closed schema at the service boundary.
