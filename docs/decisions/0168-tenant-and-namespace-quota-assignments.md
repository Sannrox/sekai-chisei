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
2. A run that asks more of one metric than its tenant's whole budget is
   refused for good at claim. It is marked `refused` with the code
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
     after a crash reaches the namespace too.
   - **1c:** report-only. The gate evaluates without reserving. Each would-be
     refusal or queue is recorded on the audit and on the run.
   - **Part 2:** budgets that refuse, and `compute_seconds` reserved and
     settled (#3043). Sequenced with #2753.
   - **Part 3:** the concurrency queue, its held state, FIFO release and
     `queued(concurrency)` with a position in `proto/`.
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
  admission. One exception: a limit of zero requests or zero concurrency
  used to defer every run forever and now refuses each run for good.
- A namespace assignment has no effect on admission until 1b.
- No schema, migration or `proto/` change. An older plane ignores namespace
  rows, because it reads only `tenant:{id}` and its parents. During a
  rolling deploy an older instance defers a zero-budget run that a newer one
  refuses. Either way the run never executes.
- Rollback leaves namespace rows that nothing reads, and refused runs stay
  refused.

## Validation

- A namespace scope is a child of its tenant on the budget chain, and a `/`,
  an empty value, surrounding spaces or a control character is refused.
- A namespace assignment is stored under its own scope and leaves the
  tenant's configured limits and admission unchanged.
- A zero request or concurrency limit refuses with
  `quota_larger_than_budget`. Positive limits never do.
- Over gRPC, an isolated run whose tenant allows no concurrency is refused
  for good and never claimed again.
