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
| List | `ListActionInstances` (classified `experimental`; requires `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` feature; see [rpc-maturity.md](rpc-maturity.md)) |

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
   `AckActionWork` can finish the harvest spine. Windowed receipt lists treat
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
(experimental, gated by `SEKAI_EXPERIMENTAL_RPCS=1`; [ADR 0089](decisions/0089-park-and-decide-action-instances.md)).
Describe and preview still never grant.

- **Who decides.** A principal listed in the type's `approvers`, or, when the
  type declares none, a namespace administrator. The submitter never decides
  their own instance. Every refusal, including an unknown instance, answers
  `PERMISSION_DENIED` with `access denied`.
- **Grant** resumes the same instance against current state. It re-checks
  the type, parameters, submission criteria, and policy (the approval
  satisfies only `require_approval`), and the target object: if it changed
  since the park, the instance ends `denied` with `stale_on_resume` and
  nothing is written. Otherwise the object write, effects, and receipt
  match a direct admit.
- **Deny** is terminal (`denied_by_approver`).
- **Idempotency.** Repeating a decision returns the recorded outcome
  (`replay=true`); a conflicting decision fails `FAILED_PRECONDITION`.
  Replaying the submit returns the same instance, never a second one.
- The decision completes the instance's own receipt with an
  `approval_decided` event naming the approver, so `GetOperationReceipt`
  closes the loop. The audit log records `decide_action_instance`.
- Combined Split reserves one budget unit at submit. A grant does not charge
  again, and a denied approval keeps the unit, as submit-time denials do.

Community PostgreSQL parks but does not decide yet: `DecideActionInstance`
answers `UNAVAILABLE` there and is not advertised.

**Migrating consumers.** Before ADR 0089, `require_approval` returned
`status=denied` with a "requires approval" deny reason. It now returns
`status=parked` with an empty deny reason and an open receipt. A client that
treated that denial as final should treat `parked` as pending, surface it to
the type's approvers, and read the outcome from `GetActionInstance` or the
receipt's `approval_decided` event after `DecideActionInstance`. A denied
approval ends `denied` with `denied_by_approver`. The old denial is not
emitted anymore.

## Dual-backend

SQLite migrate-on-use and PostgreSQL migration
`0021_governed_action_instances`.

## Non-goals

- Runtime claim / dispatch placement (#399)
- External mutation (permits)
- Auto-submit from raw webhooks
