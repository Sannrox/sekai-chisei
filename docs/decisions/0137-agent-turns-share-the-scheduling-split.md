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

SQLite is the reference store for turns, as for instances (ADR 0136).

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
