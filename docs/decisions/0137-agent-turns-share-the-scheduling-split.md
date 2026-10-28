# ADR 0137: Agent turns use the transform scheduling ownership split

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Issue: #1611, split from #1610
- Related: [ADR 0129](0129-scheduling-ownership.md),
  [ADR 0103](0103-transform-schedule-and-dependency-graph.md),
  [ADR 0068](0068-object-change-subscriptions.md),
  [ADR 0136](0136-site-agent-instances.md), #838, #1387

## Context

A site agent instance (ADR 0136) must wake on its own: when a schedule is
due, or when an object it is responsible for changes. ADR 0129 decides who
owns scheduling for transforms: the plane schedules and keeps the queue,
workers pull, and the deployment layer scales. Agent turns are a second kind
of scheduled work, and must not grow a second orchestrator or let workers
decide what runs.

## Decision

1. **Same split as transforms.** The plane owns which turns exist and when:
   - the wake triggers (schedule, object change, manual);
   - the agent-turn queue, its claims and leases;
   - retries and receipts.

   Workers pull agent turns through a claim client with the transform claim
   contract: a claim carries a generation and a fencing token, a lapsed claim
   may be reclaimed, and only the current claim may write back. The
   deployment layer scales worker pools on queue-depth gauges labelled with
   the execution profile `agent-turn`, with no tenant or namespace labels.
2. **One turn per due schedule.** A turn's identity is its instance, its
   trigger and the due time or change window. Admitting a turn with an
   identity that exists is a no-op, so one schedule fire yields one turn
   across restarts and concurrent planes.
3. **Change wakes respect visibility and coalesce.** An object-change wake
   reads changes as the instance's principal, through the object-change
   subscription rules (ADR 0068): a change the principal cannot see, or a
   change only to a hidden field, wakes nothing. Changes inside one debounce
   window become one turn.
4. **Who acts.** A turn acts as the instance's principal (ADR 0136); the
   worker holds no authority of its own. A frozen instance admits no turns,
   and the refused wake is audited.
5. **Receipts name the cause.** Every turn's receipt records its trigger,
   `schedule`, `object_change` or `manual`, with the schedule id or the change
   window it came from.

Both stores keep turns (#1950); instances are written only on SQLite
(ADR 0136), so a PostgreSQL plane has no instance to wake until their parity
slice.

### Schedule wakes (#1951)

An instance's `wake_policies` holds self-describing tokens rather than
references to a separate policy record: `schedule:<every_ms>` wakes the
instance every `every_ms`, at least one minute. Instance writes refuse an
unknown or malformed token. The instance's governed update Action is the only
way to change a schedule, so every change leaves a receipt, and no second
governed kind or dangling reference exists. A shared, named schedule can be
added later as a token form that resolves an id, without breaking inline
tokens.

`TickGovernedTransforms` admits schedule wakes alongside transform and export
schedules. Each tick admits the latest due time of each token, with cause
reference `<token>@<due_ms>`; missed fires are not backfilled. Due times are
offset per instance by a phase derived from its id, so instances on one
interval do not fall due together, and every plane derives the same times.

### Change wakes (#1952)

`change:<debounce_ms>` (at least one second) wakes the instance when an
object named in its `responsibility` changes. The same tick reads committed
object mutations after a durable cursor per instance and token; a new token
starts at the present. Each object is read as the instance's principal, as a
read request would be, and the object-change subscription projection decides
the events. An update wakes only when the principal may read the changed
property: a property grant must allow it, and a restricted property needs
object admin. Creates of visible objects wake; deletes do not, since the
principal can no longer be shown to read the object. Changes in one window
of `debounce_ms` share one turn, due when the window closes, with cause
reference `<token>@<window_start_ms>`. The cursor advances after admission
with a compare-and-set, so a crash or a second plane replays the page and
admission dedupes it. The cursor keeps the change id at its sequence; when
purged history has reused or removed that sequence, it restarts from the
beginning and the replay dedupes the same way. The responsibility is a list of object ids; an
ObjectSet responsibility is a later slice.

## Alternatives considered

- Waking agents from the worker (a runner polls and decides). Rejected:
  fairness and visibility would not be governed by the plane.
- A separate agent scheduler. Rejected for the same reasons as ADR 0129's
  separate orchestrator.
- Waking on every change. Rejected: bursts would flood the queue; debounce
  keeps one turn per window.

## Consequences

#1611 is delivered in layers on this contract: the agent-turn queue and claim
client, schedule wakes, and change wakes. Each layer reuses the transform
claim, lease and receipt spine instead of adding its own.

## Validation and reversal

Conformance shows one turn per schedule fire across a restart, no wake from a
hidden change, a coalesced burst, a refused and audited wake on a frozen
instance, and the cause on every receipt. Reverse with a later ADR; turns are
additive.
