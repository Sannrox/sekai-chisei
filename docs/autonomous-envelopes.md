# Bounded autonomous envelopes

Admit autonomous Actions only inside a signed envelope whose state,
policy, model, prompt, evidence, simulation, budget, and lease pins are
current. See [ADR 0059](decisions/0059-autonomous-envelopes.md).

## Contract

`sekai.autonomous-envelope/v1` binds:

- identity `(namespace, envelope_id)`
- adapter `adapter.autonomy.simulate` or `adapter.autonomy.evaluate`
- current pin digests for state, policy, model, prompt, evidence,
  simulation, budget, and lease
- an Ed25519 signature over the envelope digest
- a receipt pin that can be invalidated without rewriting history

Exact digest replay is idempotent. Stop is idempotent. Rollback
supersedes history. Lease loss and receipt invalidation block further
live admission. Stale pins fail closed. The envelope is not a grant.

ActionInstance admission consumes a live envelope when `type_id`
starts with `autonomous.` or `autonomous_envelope_id` is set on the
request or in `parameters_json`.

## Operator workflow

```text
sekaictl admin autonomy admit --envelope ./envelope.json --actor operator
sekaictl admin autonomy get --namespace ops --envelope-id auto:simulate --actor operator
sekaictl admin autonomy stop --namespace ops --envelope-id auto:simulate --actor operator
sekaictl admin autonomy rollback --namespace ops --envelope-id auto:simulate --actor operator
sekaictl admin autonomy note-lease-loss --namespace ops --envelope-id auto:simulate --actor operator
sekaictl admin autonomy invalidate-receipt --namespace ops --envelope-id auto:simulate --actor operator
```

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, stale, stopped, rolled-back, lease-lost, invalidated, secret-bearing, or unsigned envelope | `autonomous envelope is unavailable` |
| Unknown contract revision | `autonomous envelope revision is unsupported` |

SQLite stores envelopes. PostgreSQL surfaces stay unavailable.
Adapters never receive grants, credentials, or receipt authority.
