# ADR 0062: Expose quality trends as an authenticated read projection

- Status: accepted
- Date: 2026-09-12
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/854
- Issue: https://github.com/Sannrox/sekai-chisei/issues/821 (#821)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0011](0011-separate-invariant-facts-and-evaluation-plans.md)

## Context

`query_quality_trends` already reconstructs `chisei.evaluation-quality-trend/v1`
from authorized canonical receipts. `sekaictl report quality` was the only
supported caller. Remote clients needed the same report without copying the
reducer.

## Decision

Add `ChiseiService.GetQualityTrend`. The RPC authorizes the namespace, then
returns the same `QualityTrendReport` the local command produces, including
`semantic_digest`. The reducer and receipt store remain authoritative. The RPC
does not persist a dashboard, cache success, or invent totals.

Supported SDKs call the generated client. They do not reimplement reduction.
Denied namespaces, over-limit windows, missing dependencies, incomparable
baselines, incomplete populations, and cancellation stay explicit. Subject
identities, evidence payloads, prompts, and raw model output remain
unprojected.

## Alternatives considered

A different remote schema would force clients to re-derive meaning.
Recomputing trends in SDKs would fork authority from canonical receipts.
A write or cache RPC would invent a second analytics truth.

## Consequences

Authenticated callers can read the same digest the operator CLI produces.
Follow-up work may add gateway translation; this slice is the native RPC and
SDK facades.

## Validation

Deterministic tests prove CLI and RPC share one digest; denied namespaces and
invalid windows fail closed; inventory lists the new query RPC.
