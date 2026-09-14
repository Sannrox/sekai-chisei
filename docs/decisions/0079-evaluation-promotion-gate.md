# ADR 0079: Bound evaluation suites gate promotion on existing certification

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/901
- Issue: https://github.com/Sannrox/sekai-chisei/issues/887 (#887)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0058](0058-model-platform-certification.md),
  [ADR 0013](0013-governed-external-evaluator-adapters.md)

## Context

Evaluation manifests, plans, executions, and portable evidence already
exist. [ADR 0058](0058-model-platform-certification.md) already issues a
digest-bound certification envelope and states that certification is not a
runtime grant. Live routing does not read that envelope. Issue #887 asked
where a bound suite should refuse promotion.

## Decision

1. Evaluation suites are a plane capability. They are not a delivery
   product.
2. Promotion (publishing or activating a route, prompt-package, or
   agent-definition revision) requires a current, non-revoked certification
   whose bound suite passed at or above the recorded baseline. The suite is
   the already-shipped manifest + evidence pair. This ADR does not invent a
   new suite language.
3. Routing of an uncertified or revoked version fails closed unless an
   explicit namespace policy allows it. That allow is a policy revision, not
   a header. Live grants still recheck policy, budget, and authorization.
   A certification record is not a grant.
4. Unavailable, failed, or stale evidence is `deny`.

## Alternatives considered

- Gate only in an external delivery plane. Rejected: this repository has no
  delivery system of record.
- Advisory only: publish regressions and never refuse. Rejected: not a gate.

## Consequences

The unused certification envelope becomes the promotion record. Routing
gains a fail-closed check. Operators who need an uncertified route must
say so in namespace policy.

## Validation

Passing suite → certifiable. Regressing suite → promotion refused with the
same reason as the eval `deny`. Unavailable evaluator → refuse, not pass.
Revoked certification cannot route. `PlanExecution` still rechecks policy.
