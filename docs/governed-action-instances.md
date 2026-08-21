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
| Read by id or key | `GetActionInstance` |
| List | `ListActionInstances` |

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
8. **Budget** hierarchical subject `action:governed[/:<budget_scope>]/project:<ns>/agent:<actor>`
   when a `BudgetTracker` is configured. Exhausted → `status=denied`.
9. When the type binds `object_kind` and `object_mutation`, plan one
   `CreateObject` or `UpdateObject` of that admitted kind. Unknown kind,
   reserved kind, schema-invalid record, missing update target, or
   create-id conflict fail closed
   before a durable success receipt. Policy or budget deny persists a `denied`
   instance and does not write the record.
10. Persist instance first so same-key replay wins the idempotency insert.
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
Parameter values stay out of audit and receipt evidence.

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

## Dual-backend

SQLite migrate-on-use and PostgreSQL migration
`0021_governed_action_instances`.

## Non-goals

- Runtime claim / dispatch placement (#399)
- External mutation (permits)
- Auto-submit from raw webhooks
