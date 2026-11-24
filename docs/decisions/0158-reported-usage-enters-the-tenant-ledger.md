# ADR 0158: Reported usage enters the tenant ledger

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3043 (#3043)
- Supersedes: none
- Superseded by: none
- Related: none

## Context

The tenant usage ledger (`chisei.usage-event/v1`) counted `tokens` and
`requests` per tenant and namespace, projected from receipts. A platform that
bills and enforces from it also needs compute seconds of isolated jobs,
retained storage bytes, input and output tokens priced apart, and the principal
and resource behind the work. The plane runs none of those isolated jobs, so it
cannot measure their compute or storage itself. `RecordUsage` is a budget
counter with no tenant attribution and is not a billing fact.

## Decision

- **Units.** `input_tokens`, `output_tokens`, `compute_seconds` and
  `storage_bytes` join `tokens` and `requests`. `tokens` stays the total, so
  existing readers keep their numbers. Receipt projection also writes the input
  and output parts.
- **Attribution.** Each event may carry `principal_id`, `resource` (`kind`,
  `id`) and `reported_by`, all from verified context: the receipt's initiating
  actor, or the tenant assertion on append. Aggregates narrow by namespace and
  by principal.
- **Tolerant readers.** Units are validated by the typed ledger, not by a
  storage `CHECK`. Readers filter on the units they know, so a later release
  can add a unit without breaking list or export on this one.
- **Append call.** `ChiseiService.AppendUsageEvents` (experimental) accepts
  `compute_seconds` and `storage_bytes` only, with source `provider_reported`.
  It requires an enterprise tenant assertion: the tenant is the assertion's
  tenant, the principal is the person the caller acts for (`act`, else the
  caller), and the caller is `reported_by`. Each event needs namespace write.
  Its caller dedupe key is scoped to the tenant; a replay is a no-op success.
  The event time is the plane's clock. Every event in a request is checked
  before any is written.
- **Resource is a label inside the namespace.** The ledger does not resolve or
  return the resource, so the namespace write that admits the event is the
  authority for naming it. No per-resource read check is made.

## Consequences

- The ledger is the single meter for the platform's isolated jobs.
- A reporting service can over-report within namespaces it may write;
  corrections stay append-only.
- Upgrade: SQLite rebuilds `chisei_usage_events` once, in a transaction;
  PostgreSQL migration 177 drops the unit `CHECK` and adds nullable columns.
  A reader of the previous release fails on a new unit, so drain instances of
  the previous release before any caller appends a new unit.

## Alternatives considered

- Extend `RecordUsage`: a budget counter with 32-bit tokens and no tenant.
- Take the principal from the request body: spoofable.
- Ship the units without an append path: compute and storage would stay empty.
