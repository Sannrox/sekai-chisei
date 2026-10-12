# ADR 0102: Isolated-process governed-transform profile uses a dedicated claim queue

- Status: accepted
- Date: 2026-10-12
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1386
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1386 (#1386)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0097](0097-in-process-transform-host.md),
  [ADR 0101](0101-analytical-transform-profile.md),
  [ADR 0074](0074-plane-owned-transforms.md)

## Context

[ADR 0097](0097-in-process-transform-host.md) hosts `projection` in process
and leaves other engines as later JobSpec profiles.
[ADR 0101](0101-analytical-transform-profile.md) adds in-process SQL. Issue
#1386 needs a runner that is not the plane process: a pinned engine and
runtime image, claimable dispatch, streamed input reads, and a fenced
write-back that commits the output dataset, receipt, and lineage together.

Reusing Action `runtime_dispatch` would mix transform work with Action
effects and inherit Action retry/park semantics that #1386 does not want.

## Decision

1. `isolated_process` is a JobSpec profile on the same
   `GovernedTransform` as `projection` and `analytical`. It names `engine`
   and `runtime_image`. It does not combine with analytical SQL or
   in-process steps.
2. Existing `projection` and `analytical` definition digests stay stable.
   Isolated extras participate in the digest only when the profile is
   present.
3. `RunGovernedTransform` admits pending `sekai_transform_work` instead of
   computing output. Dispatch uses a dedicated transform claim kind, not
   Action `runtime_dispatch`.
4. A worker lists claimable work, claims with a fencing token and lease,
   heartbeats, streams the admitted JobSpec input snapshot while the claim
   is live, and writes the result. Write-back uses the admitted JobSpec,
   validates the fence and the output digest, and commits output rows, the
   run receipt, and lineage in one transaction. A stale fence or digest
   mismatch commits nothing. An expired lease returns the work to pending
   under the existing retry-style expiry cap. Claim RPCs require credential
   admin.
5. The new RPCs stay experimental. `DiscoverCapabilities` reports
   `sekai.transforms.isolated_process` on the core pack, disabled unless
   experimental RPCs are enabled.
6. Both community backends persist work, claims, and receipts.

## Alternatives considered

- Action `runtime_dispatch`. Rejected: transform work is not an Action
  effect; sharing that queue would couple unrelated retry and park
  semantics.
- In-process engine host for Spark/DuckDB. Rejected: #1386 asked for an
  isolated process with a pinned runtime image.
- Promote the new RPCs to `stable`. Rejected: the stable cap is 68.

## Consequences

In-process projection and analytical runs are unchanged. Isolated-process
runners own incrementality; the plane always rebuilds on write-back.
Cluster submit remains a later profile if measurement shows a need.

## Validation

SQLite tests `isolated_process_run_claims_reads_and_commits_write_back`,
`isolated_process_stale_fence_write_back_commits_nothing`,
`isolated_process_expired_lease_returns_to_the_queue`, and
`isolated_process_write_back_uses_the_admitted_jobspec`. PostgreSQL repeats
the same envelope. DiscoverCapabilities advertises the isolated profile.
