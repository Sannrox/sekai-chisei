# ADR 0014: Expose bounded runtime claim pressure to external capacity managers

- Status: accepted
- Date: 2026-08-02
- Owners: @Sannrox
- Discussion: resolved through [Tenkai ADR 0011](https://github.com/Sannrox/tenkai/blob/main/docs/decisions/0011-shikigami-worker-pool-lifecycle.md)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/489
- Supersedes: none
- Superseded by: none

## Context

Tenkai owns Shikigami worker-pool desired state and capacity intent, while
Sekai Chisei remains authoritative for admitted work, claims, leases, fencing,
retry/park decisions, dead-lettering, and operation receipts. A capacity
manager needs bounded pressure signals without repeatedly listing work,
scraping Chisei storage, or copying queue authority into Tenkai.

The cross-repository ownership boundary is accepted by Tenkai ADR 0011. The
pressure contract must therefore be a read-only projection that cannot select,
claim, acknowledge, or mutate individual work.

## Decision

Add `GetRuntimeWorkPressure` to `SekaiService` as the versioned
`sekai.runtime-work-pressure/v1` contract. The request requires one canonical
namespace and one runtime id; wildcard runtime reads are not supported. Normal
namespace read authorization applies, and the response is limited to the
requested runtime scope.

The response is an aggregate-only document containing:

- exact claimable count (ready plus currently expired leases);
- oldest claimable age and sample timestamp;
- active and expired claim counts;
- parked, failed, and dead-lettered terminal pressure;
- `current` / `degraded` / `unknown` status, an authoritative flag, and an
  approximation flag.

Storage computes the projection with one bounded aggregate query and returns no
effect, operation, claim, task, parameter, credential, or workspace data. A
successful sample is exact for its timestamp (`authoritative=true`,
`approximate=false`). Storage or projection failure returns an `unknown`
document with `authoritative=false`; callers must not scale up or fabricate
zero pressure from that result.

Tenkai may combine a current pressure sample with the Shikigami worker-host
lifecycle contract when proposing capacity changes. It never receives claim
authority and must treat stale, degraded, unknown, or unsupported-version
samples as non-authoritative.

## Alternatives considered

- **Repeatedly list claimable work.** Rejected because it materializes bounded
  pages, couples scaling to claim pagination, and cannot provide a stable
  aggregate age signal.
- **Scrape Chisei storage.** Rejected because it violates the service boundary
  and couples Tenkai to SQLite/PostgreSQL internals.
- **Copy queue state into Tenkai.** Rejected because it creates a second work
  authority and stale recovery path.
- **Let Chisei autoscale workers.** Rejected because worker desired state,
  deployment, rollout, and capacity remain Tenkai/executor concerns.

## Consequences

The additive RPC and fixture provide a stable later-phase autoscaling input
without changing admission or claim behavior. SQLite and PostgreSQL retain the
same aggregate semantics and use a namespace/kind/runtime expression index to
narrow repeated polls before evaluating aggregate state. The index stores only
a bounded runtime prefix and the query performs an exact runtime recheck, so
long deployment-generated ids do not become unbounded index keys.
Operators and Tenkai must monitor sample freshness and fail closed when Chisei
storage or the projection is unavailable. This contract is not a scheduler,
queue replacement, or Chisei recovery dependency.

## Validation

- Deterministic storage tests cover empty, runtime-isolated, growing/expired,
  active, parked, failed, and dead-lettered pressure.
- gRPC tests prove namespace authorization, exact runtime scoping, and the
  payload-free response shape.
- SQLite and PostgreSQL backend conformance exercises the pressure aggregate.
- The Tenkai-facing fixture requires `current` + `authoritative` evidence and
  keeps the last safe capacity intent for unknown samples.
