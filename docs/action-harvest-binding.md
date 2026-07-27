# Bind Action lifecycle to harvest and operation receipts

Issue: [#400](https://github.com/Sannrox/sekai-chisei/issues/400).  
Claim: [runtime-claim.md](runtime-claim.md).  
Admission: [governed-action-instances.md](governed-action-instances.md).

## Correlation table (hosts and producers)

| Identity | Owner | Purpose |
| --- | --- | --- |
| `ActionInstance.instance_id` | Plane | Durable admission decision id |
| `ActionInstance.operation_id` | Plane | **Harvest / receipt spine** (`ReportOperationEvent`, `GetOperationReceipt`) |
| `ActionEffect.effect_id` | Plane | Claimable `runtime_dispatch` child |
| Host logical operation id | Host | **Must equal** `operation_id` when reporting harvest |
| Evidence submission ids | Producer | Optional inputs on submit; observation-only until Action submit |

## Enforced rules (v1)

1. Every admitted ActionInstance allocates exactly one `operation_id` at admit time.
2. Runtime hosts claim **effects**, not instances; they harvest to the bound `operation_id`.
3. `AckActionWork` with `completed` / `failed` appends `ActionPerformed` + `OutcomeRecorded`
   on the operation receipt when missing (ack-without-prior-harvest still lands a
   reconstructible outcome; hosts should still emit finer harvest events).
4. Consistency helper `evaluate_action_lifecycle` flags:
   - terminal effect without receipt outcome (ack without harvest spine)
   - receipt outcome while effect still claimed/pending (harvest without ack)
5. Notifications and external_mutate do not use this claim/harvest binding.

## Conflict preference

- Plane SoR for claim/ack effect status is the ActionEffect row.
- Operation receipt is the harvest narrative; ack backfills a minimal outcome if
  hosts forgot intermediate events.
- Disagreement is observable via lifecycle mismatches; operators resolve with
  host re-report or audit, not silent overwrite of claim fences.

## Non-goals

- Replacing host-local debug checkpoints
- Exactly-once notify delivery
