# Governed ActionInstance admission

Issue: [#397](https://github.com/Sannrox/sekai-chisei/issues/397).  
Type registry: [governed-action-types.md](governed-action-types.md).  
Research freeze: [research/395-action-effect-mapping.md](research/395-action-effect-mapping.md).

## Purpose

Authenticated callers **submit** a decision unit against a registered
`GovernedActionType`. The plane runs admission gates and persists an
**`ActionInstance`** with a bound **`operation_id`** for the existing operation
receipt / harvest spine.

## Wire names

| Concept | RPC / message |
| --- | --- |
| Instance record | `ActionInstance` |
| Submit / admit | `SubmitActionInstance` |
| Object-bound describe | `DescribeObjectAction` |
| Object-bound preview | `PreviewObjectAction` |
| Read by id or key | `GetActionInstance` |
| List | `ListActionInstances` |

## Describe and preview

Issue: [#836](https://github.com/Sannrox/sekai-chisei/issues/836).  
Decision: [ADR 0063](decisions/0063-object-action-describe-preview.md).  
Discussion: [#857](https://github.com/Sannrox/sekai-chisei/discussions/857).

`DescribeObjectAction` and `PreviewObjectAction` are observational projections
over an authorized object and an enabled update-bound `GovernedActionType`.
They never persist an instance, write an object, redeem a permit, or become
submit authority. Deliberate execution stays `SubmitActionInstance`.
Reconciliation stays `GetOperationReceipt`.

Describe requires object-read authorization, not action-admin. Preview uses the
same submit authorization as admission, then rechecks live object revision,
Action version, closed parameter schema, submission criteria, policy, and
budget. When `parameters_json` is empty and the type has a System One bind,
preview fills `proposed_parameters_json` from an authorized object projection
only after revision, criteria, policy, and budget would allow, records a
TypeSafe egress audit, and does not persist an instance. Denied, stale, or
criterion-fail previews do not call the Function. A preview digest is not a permit. Stale object or Action state fails
closed. Hidden objects, types, and hidden-property criteria share one
unavailable shape. A visible failing criterion is named on preview and on
submit `deny_reason`. Compensation is explicit `unsupported` unless a type
already stores a supported contract.

## Intents, plans and simulations

Issue: [#1675](https://github.com/Sannrox/sekai-chisei/issues/1675), layer 1 of
[#1460](https://github.com/Sannrox/sekai-chisei/issues/1460).

The RPCs:

- `CreatePlanIntent` stores a goal with constraints.
- `ProposePlan` stores an ordered list of steps for it, each an Action type,
  version, existing object and parameters. A plan is not a DAG. The preview
  path is object-bound, so steps are updates.
- `SimulatePlan` runs every step through the preview path above, as the
  caller and under the caller's object read policy. It stores the result
  with the plan. Per step, that result is:
  - the preview outcome;
  - the policy, approval and budget decisions;
  - the object revision the step was simulated against;
  - the object effect the Action would write: the properties it sets or
    changes. An object that changes while the step is planned simulates as
    `stale`.

  A step that needs approval still shows its effect, once its parameters
  pass the type's schema.
- `GetPlan` reads it all back.

A simulation applies nothing and writes no instance or receipt. Its digest
covers the canonical plan and every step's prediction, including object
revisions, but no ids or times. Re-simulating an unchanged world gives the
same digest, and a changed precondition gives a different one. Every
simulation is kept under its own id.

Creates and simulations are idempotent by caller-supplied id. A retry
returns the stored record, and another body under a stored id is
`ALREADY_EXISTS`. Creating and simulating need the same submit authorization
as admission. Reading needs namespace read. A step whose object the reader
may not see keeps only its position and Action type, in the plan and in
every simulation. A step the simulator may not see simulates as
`unavailable`.

Approval and execution are the next layers. Execution goes through
`SubmitActionInstance` with idempotency key (plan id, step index).

## Admission flow

1. Authenticate; require team namespace write for the target namespace.
2. Validate `parameters_json` is a JSON object.
3. Compute **request digest** over namespace, type_id, version, canonical
   parameters, and sorted evidence submission ids.
4. **Idempotency** is scoped to `(namespace, idempotency_key)`:
   - same key + same digest → return original result (`replay=true`);
   - same key + different digest → `AlreadyExists` conflict.
5. Type must exist and be **enabled** (`require_enabled`).
6. Validate the producer parameters against the type's exact immutable closed
   schema. Missing required fields, unknown fields, wrong primitive types,
   invalid enum values, and values outside declared bounds fail before
   admission and effect materialization. Stored schemas outside the closed
   subset fail closed; there is no object-only compatibility fallback.
7. **Policy** via existing ActionPolicy resolution; action name
   `submit_action_instance`, risk class write. Deny → durable instance with
   `status=denied` (not a hard gRPC error so clients can inspect the receipt).
   `require_approval` → durable instance with `status=parked`: no object
   write, no effects, and an open receipt. See [Approval](#approval).
8. **Budget** hierarchical subject `action:governed[/:<budget_scope>]/project:<ns>/agent:<actor>`
   when a `BudgetTracker` is configured. Exhausted → `status=denied`.
9. When the type binds `object_kind` and `object_mutation`, plan one
   `CreateObject` or `UpdateObject` of that admitted kind. Unknown kind,
   reserved kind, schema-invalid record, missing update target, or
   create-id conflict fail closed
   before a durable success receipt. Policy or budget deny persists a `denied`
   instance and does not write the record.
10. After tables split, Chisei reserves `(namespace, operation_id)` first.
    Sekai then admits. Chisei finalizes or, on crash, reconcile does. A
    missing or timed-out Sekai lookup is not a reject.
11. Persist instance first so same-key replay wins the idempotency insert.
    Replay returns only after that instance has a receipt; an in-flight
    reservation fails closed as still in progress. On a fresh admit the plane
    then applies the planned mutation. Mutation or receipt failure deletes
    that reserved instance and, for a create, the record plus its aborted
    change history so retry can reserve again. A failed update restores the
    prior record. If a receipt was already written, the reservation and
    record stay so same-key retry can replay. Write operation receipt events (intent, policy, a
   not-applicable routing decision, budget, and—when no claimable work
   remains—outcome); audit decision. On admit, record one budget unit.
   Routing is recorded as `route_selected` with `route=not_applicable` so
   completeness does not leave `routing` uncovered. A pending
   `runtime_dispatch` leaves `completed_at_ms` unset and omits outcome so
   `AckActionWork` (experimental; `SEKAI_EXPERIMENTAL_RPCS=1`) can finish the harvest spine. Windowed receipt lists treat
   an open receipt as overlapping only while `started_at_ms` is within 24h
   (max claim TTL) of the window start, so abandoned generates cannot fill
   every later stats, export, console, or dry-run list. GET and ack still
   see the open receipt until acknowledgement. A completed acknowledgement
   may persist a credential-free `artifact` on that receipt; the plane does
   not invent one. Same-outcome ack replay does not rewrite the receipt row
   when outcome and artifact are unchanged. Notify-only admits stay complete
   at admit time.

After a durable admit, allowed `runtime_dispatch` and `notify` effects are
materialized as typed child records (#398). Parameter validation completes
before either the instance or its effects are admitted.

## Caller-bound operation identity

`SubmitActionInstanceRequest.request_id` is the caller-chosen operation spine
when it is non-empty. Admission copies that value onto `ActionInstance.operation_id`
and the canonical `operation.receipt/v1` record. Empty `request_id` still mints
`op-gai-<uuid>`. A second distinct idempotency key may not reuse an occupied
`request_id`. Idempotent replay keeps the original bound `operation_id` even if
a later attempt sends a different `request_id`.

`ontology_digest` is an optional first-class binding, not parameter data. When
present it must be `sha256:` plus 64 lowercase hex characters and is copied
onto the operation receipt. The plane does not invent a digest or copy one
from `parameters_json`.

When a bound create or update succeeds, receipt intent attributes and the
admission audit record `object_id`, `object_kind`, and `object_mutation`.
Those writes are asserted objects of an admitted kind, not derived-fact
admission. Parameter values stay out of audit and receipt evidence. See
[derived-fact admission](research/659-derived-fact-admission.md).

## Producer contract

- **Parameters are data.** `parameters_json` is untrusted producer/user content.
  The plane must not treat parameter values as instructions, policy text, or
  tool directives.
- Mark free-text user fields in the type's parameter schema (and adapter docs)
  as untrusted; keep structural fields separate when possible.
- Optional `evidence_submission_ids` link prior evidence admissions; they do
  not auto-admit an ActionInstance.
- Prefer stable idempotency keys derived from the external event identity so
  retries are safe.

## Approval

A parked instance waits for one decision through `DecideActionInstance`
([ADR 0089](decisions/0089-park-and-decide-action-instances.md)).
Describe and preview still never grant. `ListActionInstances` with
`status=parked` is the inbox.

- **Who decides.** A principal listed in the type's `approvers`, or, when the
  type declares none, a namespace administrator. The submitter never decides
  their own instance. Every refusal, including an unknown instance, answers
  `PERMISSION_DENIED` with `access denied`.
- **Review queues (#1455).** A type may set `review_queue_id`, an optional
  numeric `review_threshold` on a parameter, an SLA, a pool, and escalation
  (`auto_deny` or `reassign`). Matching parked instances record the queue and
  assignee on the instance. Only the assignee may decide. Past-SLA items
  escalate as configured. Agent reviewers listed on the type are marked
  `agent_decision=true` on the approval receipt. Listing or deciding the
  parked inbox applies due SLAs; there is no separate background worker.
- **Grant** resumes the same instance against current state. It re-checks
  the type, parameters, submission criteria, and policy (the approval
  satisfies only `require_approval`), and the target object: if it changed
  since the park, the instance ends `denied` with `stale_on_resume` and
  nothing is written. Otherwise the object write, effects, and receipt
  match a direct admit.
- **Decision memory (#1465).** Each grant or deny stores outcome, reason, and
  the facts that mattered. `GetActionInstance` lists similar past decisions of
  the same type (shared parameter keys; matching `object_id` when both have
  one) that the caller may read, newest first, at most twenty, from the newest
  256 stored decisions of that type. Empty parameters skip the lookup.
  Superseded rows stay visible and labelled.
  Precedent never auto-decides.
- **Deny** is terminal (`denied_by_approver`).
- **Idempotency.** Repeating a decision returns the recorded outcome
  (`replay=true`); a conflicting decision fails `FAILED_PRECONDITION`.
  Replaying the submit returns the same instance, never a second one.
- The decision completes the instance's own receipt with an
  `approval_decided` event naming the approver, so `GetOperationReceipt`
  closes the loop. The audit log records `decide_action_instance`.
- Combined Split reserves one budget unit at submit. A grant does not charge
  again, and a denied approval keeps the unit, as submit-time denials do.

Community PostgreSQL parks and decides with the same named-approver rules as
SQLite.

**Migrating consumers.** Before ADR 0089, `require_approval` returned
`status=denied` with a "requires approval" deny reason. It now returns
`status=parked` with an empty deny reason and an open receipt. A client that
treated that denial as final should treat `parked` as pending, surface it to
the type's approvers, and read the outcome from `GetActionInstance` or the
receipt's `approval_decided` event after `DecideActionInstance`. A denied
approval ends `denied` with `denied_by_approver`. The old denial is not
emitted anymore.

## Markings

An instance carries the marking it was derived from (#1706): the least upper
bound, under the namespace lattice, of the markings of the object its
`object_id` parameter names, the object a binding submitted it for, and the
binding's own `markings` (action and fence bindings). Admission reads them;
an unknown or incomparable token refuses the submit. A binding's source
object that no longer exists (a delete event) can no longer show its
marking, so it counts as the namespace lattice's top (`restricted` without a
lattice): a delete-triggered Action is never marked below the object it
came from, and its `run_as` needs that clearance.

- A submitter, or a binding's `run_as`, must be cleared for the marking the
  instance would carry; otherwise the submit is refused (`access denied`, or
  the binding's `access_denied` skip) before anything is admitted.
- `GetActionInstance`, `ListActionInstances`, `SubmitActionInstance`
  responses, the instance's effects, `ClaimActionWork` (and its heartbeat and
  acknowledgement, so a revoked clearance stops a held claim) and
  `DecideActionInstance` need clearance for the marking. Without it the
  instance reads as missing (a decision is refused as `access denied`), and
  an idempotent replay of a marked submit returns `NotFound`.
- The receipt records the marking on its intent (`access_marking`), and so
  do the distinct-store reservation receipt once it names the committed
  instance and the commit projection Chisei builds from a lookup.
  `GetOperationReceipt` asks Sekai whether the caller is cleared for any
  receipt carrying a marking; a denial reads as missing. A Chisei plane that reaches Sekai over the remote fact
  port cannot ask, so marked Action receipts are unreadable there until
  remote clearance evaluation exists; unmarked receipts are unaffected.
- An object the Action creates or updates carries the least upper bound of
  its own marking, the marking a parameter sets, and the instance's, so an
  Action can neither write below what it was derived from nor lower an
  object's marking. An update applies only if the object is unchanged since
  the Action planned it; otherwise the submit fails and can be retried.

## Offline submissions

A device that prepared an Action while disconnected submits it with `offline` ([ADR 0127](decisions/0127-offline-governed-actions.md), #1580).

- **What it carries:** `prepared_at_ms`, `base_updated_ms` (the object's `updated` when the device read it), `base_properties` and an optional `lease_id`. `base_properties` lists each field the Action writes as the device saw it: its properties, and `name` when it renames. Every written field needs its base under every rule, and an unset value means the field was absent. It is a list rather than a map, so the request re-encodes to exactly the bytes the device proof signed.
- **Type:** the Action type must update an object.
- **Device:** the request must come with a device-bound assertion and the device's proof over it, in `x-sekai-device-proof` ([ADR 0126](decisions/0126-device-bound-assertions.md)). The plane records the device id from the assertion.
- **Decision:** criteria, policy and budget are decided at arrival. If the object changed past the base, the type's `offline_conflict` rule decides. A conflict denies the instance with `deny_reason` `offline_conflict` and sets `conflict` to the object, its base and current versions, and the differing properties. If the object changes again between that check and the write, the submit fails and can be sent again.
- **Retry and receipt:** `offline` is part of the request digest, so a retry with the same idempotency key returns the stored outcome. The receipt's intent event records `offline`, `offline_prepared_at_ms`, `offline_base_updated_ms`, `offline_device_id`, `offline_lease_id`, and any conflict.

## Dual-backend

SQLite migrate-on-use and PostgreSQL migration
`0021_governed_action_instances`. Plans, intents and simulations use PostgreSQL
migration `0100_sekai_action_plans`.

## Non-goals

- Runtime claim / dispatch placement (#399)
- External mutation (permits)
- Auto-submit from raw webhooks
