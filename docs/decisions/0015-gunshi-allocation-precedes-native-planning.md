# ADR 0015: Apply Gunshi allocation before native execution planning

- Status: accepted
- Date: 2026-08-03
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/280
- Supersedes: none
- Superseded by: none

## Context

Gunshi makes fleet-scoped allocation decisions from multiple pending operations
and a capacity envelope. Native `PlanExecution` makes one operation executable
through policy, context enrichment, budget, routing, review, and evaluation
decisions. Kioku already participates inside that per-operation pipeline.

Keeping Gunshi completely separate left no governed handoff from an issued
allocation to native planning. Treating Gunshi as another inner enrichment step
would also be incorrect: by the time one operation enters `PlanExecution`, the
fleet capacity and competing-operation context needed by Gunshi is absent.

## Decision

Gunshi is the optional outer allocation stage for fleet-managed native work:

```text
Gunshi allocation -> PlanExecution -> Kioku enrichment -> ExecutePlanStream -> receipt/feedback
```

`PlanExecutionRequest` may bind one `AllocationPlan` and its Gunshi issuance
id. Chisei accepts the binding only when the allocation exactly matches the
durable issued recommendation and its namespace, logical operation, operation
class, priority, tool set, and policy revision still match the live planning
request. Planning then re-resolves provider availability and policy and must
produce the allocated runtime and model exactly; it never silently falls back
to a different allocation.

The resulting `ExecutionPlan` and operation receipt preserve the issuance,
allocation, agent, policy, input fingerprint, attempt limit, budget ceiling,
and review requirement. The receipt keeps its native plan id as the canonical
receipt id and records the Gunshi operation as `logical_operation_id`, allowing
outcome feedback to close against the issued allocation without conflating the
two identities.

Kioku remains an inner per-operation enrichment step. Gunshi may separately
consult governed Kioku outcome evidence while selecting fleet resources; that
does not replace the context enrichment performed during native planning.

Direct `PlanExecution` without a Gunshi binding remains valid for work that has
not entered a fleet allocation cycle. Automatic dispatch remains separately
gated by the existing namespace opt-in, promoted allocation policy, and the
auto-dispatch decision returned alongside `IssueGunshiRecommendations`.

## Alternatives considered

- **Run Gunshi as an inner `PlanExecution` step.** Rejected because a
  single-operation request does not contain the fleet capacity or competing
  pending operations required for allocation.
- **Keep Gunshi and native execution disconnected.** Rejected because callers
  could not prove that a native plan implements an issued recommendation or
  carry allocation provenance into the receipt and feedback loop.
- **Require Gunshi for every native plan.** Rejected because direct and
  first-run operations do not necessarily have a fleet capacity envelope;
  manufacturing one would turn advisory allocation into hidden policy.

## Consequences

Fleet-managed work now has one governed, fail-closed path from recommendation
through planning, execution receipt, and feedback. The protobuf change is
additive within the new 1.0 contract and adds no RPC endpoint. Clients that
bind an allocation must send the exact issued allocation JSON and issuance id.

Allocation attempt, budget, and human-review limits are retained as explicit
plan and receipt evidence. Chisei's own budget, policy, privacy, evaluation,
and provider-availability checks remain authoritative and may deny planning;
they cannot broaden or reroute the Gunshi allocation.

## Validation

- Service tests bind a durably issued allocation and verify exact route,
  logical operation identity, Gunshi metadata, receipt limits, and continued
  execution of the Kioku enrichment step.
- Negative tests reject modified allocations and allocations issued under a
  stale policy revision.
- Feedback tests accept a completed native receipt only when its governed
  `logical_operation_id` matches the allocation.
- Protocol inventory tests assert that allocation binding adds no endpoint.
