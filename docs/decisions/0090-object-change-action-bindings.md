# ADR 0090: Bind object changes to governed Actions through a plane-owned binding

- Status: accepted
- Date: 2026-09-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1100
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1092 (#1092)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0068](0068-object-change-subscriptions.md),
  [ADR 0089](0089-park-and-decide-action-instances.md)

## Context

`ReadObjectChangeSubscription` delivers authorized create, update, and delete
facts (ADR 0068). Nothing admitted an Action from them. An external daemon
that calls `SubmitActionInstance` would own neither the idempotency nor the
pin, and the plane would not know which unattended writes were installed on
purpose.

In mature data platforms, automations that trigger actions from data changes
run as an explicit owner identity whose permissions are checked again when
they execute. The automation definition is versioned, effects are
deduplicated by event identity so a replayed event never applies twice, and
a failed run is recorded rather than retried into duplicate effects.

## Decision

- **Binding.** `sekai.action-binding/v1` is namespace-scoped and names:
  - one object kind (optionally with property filters);
  - the event operations that fire;
  - one `GovernedActionType` with a pinned version;
  - a `run_as` service principal;
  - a **closed parameter mapping**: object id, event op, event field, a
    property of the changed object, or a constant. There are no expressions
    and no builder.
- **Install.** `PutActionBinding` requires namespace administration. The
  bound type and version must exist and be enabled. Every mapped parameter
  must be declared by the type's schema, and `run_as` must hold namespace
  write. Each install increments the binding revision and restarts delivery
  from a fresh snapshot.
- **Run.** `RunActionBinding` reads the binding's own subscription as
  `run_as`. Namespace admins or `run_as` itself may trigger a run, from a
  scheduler or on demand. Each bound event submits one Action as `run_as`
  through normal admission, so ACL, policy, budget, schema, and criteria
  are checked on every submit. A `require_approval` type parks per ADR 0089
  and is never auto-granted.
- **Hidden fields never enter parameters.** Properties are read as `run_as`
  sees them. A mapping that needs a property `run_as` cannot read skips the
  event with `parameter_source_unavailable` instead of submitting without
  it. A binding that fires on delete cannot map properties.
- **Exactly one Action per event.** The idempotency key derives from the
  binding id, revision, event id, and offset, and a rerun or redelivery
  replays. Reading a page commits the subscription cursor, so each run first
  records the subscription's state on the binding, then persists the page's
  events and clears that record in one write before any submit. A run that
  finds pending events finishes them as replays. A run that finds a record
  but no events (a crash between reading and persisting) restores the
  subscription from the record, so the page is delivered again, not lost.
- **Subscription outcomes pass through.** The first run pins a snapshot and
  does not backfill. `resnapshot_required` re-pins. `slow_consumer`
  disconnects and clears the pin so the next run re-pins. The subscription
  and the binding never carry authority (`authority` stays false).
- **Wire.** Both RPCs are `experimental` until a sekaictl or SDK consumer
  ships. Community PostgreSQL answers `UNAVAILABLE`.

## Alternatives considered

- An external daemon only: rejected as the supported path, because there is
  no plane-owned idempotency or pin.
- Overloading workflow-action callbacks: rejected, because they are a
  different bridge.

## Consequences

Unattended writes are an explicit, audited install. Each submitted instance
carries `run_as` as its principal, and its receipt shows the binding's
operation id. Events beyond the subscription backlog disconnect and re-pin
rather than being admitted late.

## Validation

- Unit tests cover validation, the closed mapping with hidden properties
  skipped, idempotency-key stability, and revision-scoped cursors.
- `tests/native_server_smoke.rs::spawned_binary_admits_one_action_per_bound_object_change`
  proves on the shipped server:
  - a non-admin cannot install;
  - the first run does not backfill;
  - one update admits exactly one instance, and a rerun admits nothing new;
  - `require_approval` parks.
