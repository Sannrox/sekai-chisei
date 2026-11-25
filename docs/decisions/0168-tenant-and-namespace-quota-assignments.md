# ADR 0168: Tenant and namespace quota assignments

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3044 (#3044)
- Supersedes: none
- Superseded by: none
- Related: none

## Context

Tenant quotas (#119) cap requests, tokens, concurrency and storage per tenant
in the replica-safe budget tables under the scope `tenant:{id}`. They gate
isolated-process transform runs when a worker claims one. A run that does not
fit is released and deferred as `pending`. A platform admitting work against
richer limits needs a limit per namespace too, a concurrency limit that
queues, budgets that refuse, and a report-only mode (#3044).

The maintainer accepted the shape on 2026-11-24:

- Concurrency queues. Work past the concurrency limit of its scope waits as
  durable held `pending` work, FIFO by `(created_at, run id)` within the
  stricter scope.
- Budgets refuse. A run that would exceed a budget is refused and reserves
  nothing.
- A namespace assignment is a second budget scope,
  `tenant:{id}/namespace:{ns}`. Admission reserves on both scopes or
  neither, and the stricter scope wins.
- A per-tenant mode, `report_only` or `enforce`. Report-only records each
  would-be refusal or queue on the run's receipt and audit, then admits.
- A run larger than the whole budget is refused at admission, not queued.

## Decision

1. A namespace assignment is stored as budget limit rows under
   `tenant:{id}/namespace:{ns}`, written by
   `TenantQuotaGate::configure_namespace` and, for tenant administrators, by
   `DomainAdminSurface::configure_namespace_quotas`. It uses the tenant
   assignment's metrics and field names. The budget chain splits scopes on
   `/`, so the namespace scope is a child of the tenant scope. That is the
   chain the both-or-neither reservation will run on. Neither the tenant id
   nor the namespace may contain `/`; otherwise namespace `a/b` would
   inherit `a`'s limits. Limits are non-negative.
2. A run that asks more of one metric than its tenant's whole budget, or
   from 1b its namespace's, is refused for good at claim. It is marked `refused` with the code
   `quota_larger_than_budget` and the details `metric`, `limit` and
   `requested`, through the terminal refusal path an enterprise extension
   already uses (#1701). Every run reserves one request and one concurrency
   unit, so a limit of zero for either refuses. Usage that frees with time
   never refuses here; it defers as before.
3. Delivery is split into parts, each mergeable alone:
   - **1a (this decision):** the namespace assignment, stored and validated
     but not enforced; the oversize refusal; and this ADR.
   - **1b:** namespace enforcement. Admission reserves on both scopes or
     neither. The unused-reservation hold records the scope so a refund
     after a crash reaches the namespace too. A hold an older plane wrote
     records no scope and refunds only the tenant.
   - **1c:** report-only. The gate evaluates without reserving. Each would-be
     refusal or queue is recorded on the audit and on the run.
   - **2a:** budgets refuse. A claim that finds a request or token budget
     of the run's tenant or namespace spent marks the run `refused` with
     the code `quota_budget_exhausted` and the detail `metric`, through the
     same terminal path. The gate has already rolled back what it took, so
     the run reserves nothing. A full concurrency limit still defers.
   - **2b:** `compute_seconds` reserved at claim from the run's estimate,
     settled to the measured seconds (#3043), and released on lease expiry.
     The stored quota hold gains the reserved seconds. The reservation
     takes no idempotency key: budget usage keys are global, and each claim
     of a run is its own reservation, refunded when that claim is lost. A
     reclaim reserves compute again, so a spent compute budget refuses it.
   - **Part 3:** the concurrency queue. A claim that finds a concurrency
     limit full puts the run's work in the state `held`, queued in the
     scope whose limit refused it (`tenant:{id}` or the namespace scope).
     The run's dispatch status stays `pending`. Older planes claim only
     `pending` work, so they never take a held run. Held work stays
     claimable on this version, and a claim admits it in order: a run
     with an older held run in any of its limited scopes is held behind
     it, so release is FIFO by `(created_at, run id)` within the scope.
     A run read while held carries `queue { reason: "concurrency",
     position }`, its 1-based place in that scope.
4. How `mode` is stored is pending a maintainer decision: a dedicated
   column, or a reserved row in the budget limit table. 1c depends on it.

## Alternatives considered

- **A separate namespace quota table.** Rejected. The budget tables already
  hold limits per scope id and are replica-safe. The scope chain already
  links a child scope to its parent.
- **Defer a run larger than its whole budget.** Rejected. It would wait as
  `pending` forever and be skipped on every claim.
- **Rename the limit fields to match the accepted wording.** Rejected. The
  existing fields already are the per-metric budgets and the
  concurrent-run limit, and the entitlement ceiling stores them serialized.

## Consequences

- A tenant with only today's assignments keeps today's limits, scope and
  admission. Two exceptions: a limit of zero requests or zero concurrency
  used to defer every run forever and now refuses each run for good; and
  from 2a an isolated run whose request or token budget is spent is
  refused for good instead of waiting for the next period. From 2b the same
  holds for a compute budget, which only a new assignment sets.
- A namespace assignment has no effect on admission until 1b.
- Parts 1 and 2 change no `proto/`. 2b adds the hold's `reserved_compute_seconds` column,
  default zero; a hold an older plane wrote has no compute to settle. An
  older plane ignores `compute_seconds` rows and admits without them, and a
  hold it releases leaves the newer claim's reservation charged until the
  period resets. An older plane ignores namespace
  rows, because it reads only `tenant:{id}` and its parents. During a
  rolling deploy an older instance defers a zero-budget run that a newer one
  refuses. Either way the run never executes. Likewise an older instance
  defers a run whose budget is spent; it can run it after the period
  resets unless a newer instance claims it first and refuses it.
- Part 3 adds `TransformRun.queue` to `proto/` and the work column
  `queue_scope` (SQLite on open, PostgreSQL migration 185). An older plane
  does not claim, cancel or count a held run: it can enqueue a second run
  of a transform whose run is held, and its cancel reports a held run as
  finished.
- Rollback leaves namespace rows that nothing reads, and refused runs stay
  refused. Held runs wait until a plane of this version claims them again;
  raise the concurrency limit and let the queue drain before rolling back.

## Validation

- A namespace scope is a child of its tenant on the budget chain, and a `/`,
  an empty value, surrounding spaces or a control character is refused.
- A namespace assignment is stored under its own scope and leaves the
  tenant's configured limits and admission unchanged.
- A zero request or concurrency limit refuses with
  `quota_larger_than_budget`. Positive limits never do.
- Over gRPC, an isolated run whose tenant allows no concurrency is refused
  for good and never claimed again.
- Over gRPC, an isolated run whose namespace request budget is spent is
  refused with `quota_budget_exhausted` and leaves the tenant's remaining
  request unreserved.
- A claim reserves its compute estimate. A written result settles it to the
  measured seconds, so later claims fit, and a spent compute budget refuses
  with `quota_budget_exhausted` and the metric `compute_seconds`.
- A claim lost on lease expiry refunds its compute, and the cancel of the
  reclaimed run refunds the reclaim's.
- A hold table without the compute column gains it on SQLite and
  PostgreSQL, and older holds read as zero.
- Two plane instances over one SQLite file, and over one PostgreSQL
  database, hold runs past a full tenant limit at positions 1 and 2, keep
  them across a restart, admit the oldest when the unit frees, and take a
  lapsed claim over before the next held run.
- A run newer than a held run in its namespace waits behind it, and a
  cancelled held run leaves the queue.
- A work table without `queue_scope` gains it, and its pending work stays
  claimable.
