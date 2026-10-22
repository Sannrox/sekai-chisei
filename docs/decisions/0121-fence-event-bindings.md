# ADR 0121: Bind Ezu geofence events to governed Actions

- Status: accepted
- Date: 2026-10-22
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1564 (#1564)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0090](0090-object-change-action-bindings.md),
  [ADR 0089](0089-park-and-decide-action-instances.md)

## Context

Ezu (Sannrox/ezu) is a spatial engine with no governance. It raises enter,
exit, inside and dwell events when entities cross its fences, and keeps them
readable after an id `(lsn, index)` that only grows. Nothing turned those
events into governed work, so a fence could not trigger an Action under
policy, approval or receipts.

ADR 0090 binds object changes to Actions. Its subscription read commits the
cursor, which forces it to persist each page before submitting. An Ezu read
commits nothing, so a fence binding needs less.

## Decision

- **Binding.** `sekai.fence-binding/v1` is namespace-scoped and names:
  - the fences that fire (all when empty) and the event kinds;
  - the Ezu collection whose entity ids are object ids, and their object kind;
  - one `GovernedActionType` with a pinned version and a `run_as` service
    principal;
  - a closed parameter mapping: object id, fence, event kind, event time, a
    property of the bound object, or a constant.

  `PutFenceBinding` checks it as `PutActionBinding` does: namespace
  administration, an enabled type, declared and required parameters, and
  `run_as` with namespace write. A reinstall bumps the revision and keeps the
  cursor.
- **Ezu.** A run reads `GET /v1/events` at `SEKAI_EZU_URL`, with the bearer
  resolved as provider `ezu` for `run_as`'s registered tenant (an enterprise
  resolver's credential, else the process `EZU_TOKEN`), never the caller's,
  so every run of a binding reads the same stream. The token decides the
  Ezu namespace; the plane never names one.
- **Run.** `RunFenceBinding`, triggered by namespace admins or `run_as` from a
  scheduler or on demand, first takes the binding's run lease (one minute,
  renewed before every submit), so one run at a time records outcomes. A
  second run is refused `ABORTED`; a crashed run's lease lapses and the next
  run takes over; a reinstall clears it. Then it:
  1. reads at most the binding's per-run cap of events after its cursor;
  2. resolves each entity to an object `run_as` can read, skipping the event
     with `object_unavailable` otherwise;
  3. submits one Action per bound event as `run_as`, under `run_as`'s
     registered tenant (whose freeze, like the caller's, stops the run),
     through normal admission,
     so ACL, policy, budget and schema are checked, and `require_approval`
     parks it;
  4. writes every event's receipt (instance, status, replay, or skip reason,
     by Ezu id) and moves the cursor to the page's read-through id in one
     write, forward only and only while it holds the lease of the revision
     that read.
- **Exactly one Action per event.** The idempotency key derives from the
  namespace, binding id and event id, not the revision, so a run that raced
  a reinstall and the run after it cannot both admit one event. An event
  whose key already names an Action replays it as it was admitted (type,
  version, parameters), even if the binding or the object changed since;
  one not yet admitted is built fresh under the current binding and
  grants. Renewing the lease before each submit also checks the
  revision, which a disable or reinstall bumps, so either takes effect at
  the in-flight run's next event; the submit already under way can still
  land. A crash before step 4 rereads the page and its submits replay. A
  write freeze, an internal admission failure, or an admission still in
  progress stops the run before the cursor moves, so the event is retried.
  An admission that crashed before writing its operation receipt cannot be
  told apart from one still running, and a reservation an earlier attempt
  left under the key with a different request conflicts; the binding waits
  on either visibly (the run fails `UNAVAILABLE` and lag grows) until
  admission recovers it.
  Refusals by policy, schema or grants are recorded and skipped. A run that
  lost its lease before committing the page answers `ABORTED`.
- **Back-pressure.** The per-run cap bounds each run (default 100, at most
  1000), and `more` tells the scheduler to run again. Lag is the age of the
  oldest event a run read, as `sekai_fence_binding_lag_ms`. A resume point
  past Ezu's retention fails the run visibly.
- **Storage and wire.** SQLite and PostgreSQL (`0091_fence_bindings`) keep
  the binding, its cursor and receipts. Both RPCs are `experimental`.

## Consequences

Fence-triggered work is an explicit, audited install with the same
admission path as every other Action. Markings of the bound object are not
yet carried onto the Action (#1706). A paused binding's lag shows on its next
run, not while it stays paused.
