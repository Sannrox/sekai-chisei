# Governed workflow-action bridge

Map external workflow steps onto ActionInstance admission without
transferring policy, budget, or receipt authority. See
[ADR 0054](decisions/0054-workflow-action-bridge.md).

## Contract

`sekai.workflow-action-bridge/v1` binds:

- identity `(namespace, profile_id, source_instance, step_id)`
- a registered governed action `type_id` / `version`
- cursor generation, callback identity, and callback digest
- explicit usage kind and a single admission-metered unit
- an idempotency key derived from the step identity when omitted

Submit creates the ActionInstance through existing admission. Park,
resume, cancel, and callback advance a generation-fenced binding.
Receipts remain on the bound `operation_id`.

Two reference profiles ship:

| Profile | Usage | Action type |
| --- | --- | --- |
| `adapter.workflow.job_step` | `step` | `workflow.job_step` |
| `adapter.workflow.approval_step` | `approval` | `workflow.approval_step` |

## Operator workflow

```text
sekaictl admin workflow submit --envelope ./step.json --actor integrator
sekaictl admin workflow park --envelope ./step.json --actor integrator
sekaictl admin workflow callback --envelope ./step.json \
  --payload-digest sha256:... --actor integrator
sekaictl admin workflow cancel --envelope ./step.json --actor integrator
sekaictl admin workflow get --namespace ops --binding-id sha256:... --actor integrator
sekaictl admin workflow reconcile --namespace ops --binding-id sha256:... --actor integrator
```

Exact replay of a command at the same cursor is idempotent even after
later transitions. A later cursor, foreign owner, unknown profile, or
hidden field fails closed. Each profile may submit only its catalogued
action type and version.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, stale, hidden, or usage-ambiguous step | `workflow action is unavailable` |
| Unknown contract revision | `workflow action revision is unsupported` |

SQLite stores bindings and callbacks. PostgreSQL surfaces stay unavailable.
Adapters persist a local outbox and never write graph, policy, budget, or
receipt rows.
