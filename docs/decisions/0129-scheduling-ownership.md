# ADR 0129: Chisei schedules, workers pull, the deployment layer scales

- Status: accepted
- Date: 2026-10-23
- Issue: #1447
- Related: ADR 0097, #1385, #1386, #1387, #1388, #1389; follow-ups #1732, #1733

## Context

Governed transforms have grown a scheduler and dependency graph (#1387), a published claim client (#1389), an isolated-process profile (#1386), an embedded analytical profile (#1385), and streaming reads and write-back (#1388). The batch runner is the first worker. Without a recorded owner for each concern, scheduling logic could end up split across the plane, the workers and the deployment layer, or a separate orchestrator could be proposed.

## Decision

1. **No orchestrator service or repository.**
2. **Chisei owns what runs and when:**
   - the JobSpec and the dataset dependency graph with its triggers;
   - the queue, claims and leases;
   - retries, priorities and per-owner fairness;
   - receipts (ADR 0097).
3. **Workers pull.** Runners claim work through the published claim client:
   - `ListClaimableTransformWork`, `ClaimTransformWork` and `HeartbeatTransformClaim`, then fenced write-back and acknowledgement.

   Distribution across workers comes from claiming, so nothing pushes. Isolated execution uses #1386, in-process analytical execution #1385, and large reads and write-back #1388.
4. **The deployment layer owns how many workers exist and where:** deployment, rollout and autoscaling of worker pools on the queue-depth metrics below. It never decides which job runs where.

### Open points, answered

1. **Queue-depth metric.** The plane exports three gauges per execution `profile` and worker `pool`:
   - `sekai_transform_work_queued`;
   - `sekai_transform_work_claimable`;
   - `sekai_transform_work_oldest_claimable_age_seconds`.

   They carry no tenant or namespace labels, which keeps cardinality bounded and leaks nothing. A pool is the placement-label set a run requires; runs without requirements are `default`. Autoscalers scale a pool on claimable depth and oldest age. Delivery: #1732.
2. **Liveness, lease expiry and fencing.**
   - A claim lasts the `ttl_ms` the worker asks for, within the plane's bounds, and the worker heartbeats at most every third of it.
   - Each claim carries a generation and a fencing token. A lapsed claim may be reclaimed, which raises the generation.
   - Write-back and acknowledgement require the current generation and token, so a worker whose lease lapsed cannot write.
   - Lease expiries count toward the run's `max_lease_expiries`, after which the run fails instead of cycling.

   This is the #1389 contract, recorded here as the rule.
3. **Placement constraints.** A transform may declare `requires`: label key and value pairs, part of its definition digest. A worker registers its labels with its runtime id. A run is listed and claimable only for runtimes whose labels include every required pair. There is no scoring or preference. Pools are label sets, so the deployment layer deploys pools by label. Delivery: #1733.

## Alternatives considered

- A separate orchestrator. Rejected: it duplicates the queue, retry and fairness state the plane already governs, and adds a plane to secure.
- Scheduling in the workers. Rejected: fairness and dependency ordering would not be global.
- Scheduling in the deployment layer. Rejected: it mixes deployment state with job and data state.

## Consequences

Workers stay stateless beyond their current claim. A crashed worker's run is reclaimed after its lease lapses, so recovery needs no coordinator. Scaling decisions read only the exported gauges.
