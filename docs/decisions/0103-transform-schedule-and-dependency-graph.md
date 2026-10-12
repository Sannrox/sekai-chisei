# ADR 0103: The plane admits scheduled and change-triggered transform runs

- Status: accepted
- Date: 2026-10-12
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1387
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1387 (#1387)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0074](0074-plane-owned-transforms.md),
  [ADR 0097](0097-in-process-transform-host.md),
  [ADR 0101](0101-analytical-transform-profile.md),
  [ADR 0102](0102-isolated-process-transform-profile.md)

## Context

[ADR 0097](0097-in-process-transform-host.md) and
[ADR 0102](0102-isolated-process-transform-profile.md) admit a run only when
an operator calls `RunGovernedTransform`. Pipelines need a due schedule, a
run when an upstream dataset or applied source batch commits, and an order
across transforms that feed each other. Workers must not decide what runs.

## Decision

1. Optional `schedule` and `trigger` fields on `GovernedTransform` participate
   in the definition digest only when present. Existing projection, analytical,
   and isolated-process digests stay stable.
2. The plane admits triggered runs. A replica tick is idempotent: one due
   schedule produces one run across restarts. Bursts of upstream changes
   coalesce into one downstream run per transform inside a debounce window.
3. `ApplySourceBatch` counts as an upstream change, not only a new dataset
   version.
4. The dependency graph is derived from published definitions (and recorded
   lineage). Cycles are refused at `PutGovernedTransform`. A failed upstream
   run stops downstream with a recorded reason; a later successful upstream
   run unblocks them.
5. Every triggered receipt records why it ran: schedule tick, upstream
   version, source batch, or manual. The same admission path serves in-process
   compute and isolated-process claimable work.
6. Output freshness is `fresh`, `stale`, or `blocked`, with the upstream
   version that made it stale. Cancelling a run skips not-yet-started
   downstream work and records that on the receipts.

## Alternatives considered

- External orchestrator. Rejected: lineage and authorization would sit
  outside the plane.
- Workers polling for due work. Rejected: workers execute claimed isolated
  work; they do not choose what runs.
- One replica as elected scheduler. Rejected for community: idempotent ticks
  on every replica are enough; leader election is a later HA profile.

## Consequences

Manual `RunGovernedTransform` stays. Triggered admission uses the same
authorization as a manual run. Per-namespace concurrency (default 4)
bounds isolated admission on this graph; it is not a second scheduler.

## Validation

SQLite tests: one run per schedule tick across restarts; an upstream commit
triggers downstream once; a cycle is refused at definition time; an upstream
failure halts downstream. PostgreSQL repeats the envelope. Receipts carry
the trigger cause.
