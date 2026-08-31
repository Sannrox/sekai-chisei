# ADR 0054: Map workflow steps through ActionInstance admission

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/750
- Issue: https://github.com/Sannrox/sekai-chisei/issues/709 (#709)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0013](0013-governed-external-evaluator-adapters.md)

## Context

Shipped ActionInstance admission, work lifecycle, receipts, and evidence
adapters still leave external workflow systems without a bounded way to
project a step onto a governed action. If an adapter parks, resumes, or
cancels work by writing plane state itself, it acquires admission,
policy, budget, or receipt authority.

## Decision

Accept `sekai.workflow-action-bridge/v1` as a mapping envelope, not a
second admission authority. Identity is
`(namespace, profile_id, source_instance, step_id)`. Two domain-neutral
profiles ship: `adapter.workflow.job_step` and
`adapter.workflow.approval_step`. Submit calls existing ActionInstance
admission. Park, resume, cancel, and callback are generation-fenced on
the binding. Receipts stay on the operation spine; adapters only
reconcile them.

Hidden fields, unknown versions, foreign owners, stale cursors or
callbacks, ambiguous usage, and missing authority fail closed. Exact
command replay is idempotent. SQLite is the reference store. PostgreSQL
stays unavailable.

## Alternatives considered

Giving adapters a claim/ack runtime identity was rejected because it
would mix executor fencing with workflow projection. A vendor workflow
engine in core was rejected because it would transfer execution
authority. Treating callback success as a receipt was rejected because
receipts remain plane-owned.

## Consequences

Operators submit, park, resume, cancel, callback, get, and reconcile
through `sekaictl admin workflow`. Reference adapters persist an outbox
command and call the plane; they never write graph, policy, budget, or
receipt rows.

## Validation

Deterministic fixtures cover two adapters through submit, park, resume,
cancel, duplicate, stale, callback, and receipt reconciliation, plus
hidden-field and foreign-owner denials.
