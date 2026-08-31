# ADR 0059: Admit autonomous actions only inside a signed current envelope

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/785
- Issue: https://github.com/Sannrox/sekai-chisei/issues/715 (#715)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0043](0043-reversible-learning-changes.md),
  [ADR 0054](0054-workflow-action-bridge.md)

## Context

Learned changes are inspectable and reversible. They do not yet admit
autonomous Actions. Without a signed envelope whose state, policy,
model, prompt, evidence, simulation, budget, and lease pins are
current, autonomous behavior can continue after those inputs change.

## Decision

Accept `sekai.autonomous-envelope/v1`. Identity is
`(namespace, envelope_id)`. Two domain-neutral adapters
(`adapter.autonomy.simulate`, `adapter.autonomy.evaluate`) admit a
signed envelope. Exact digest replay is idempotent. Stop is
idempotent. Rollback supersedes history. Lease loss and receipt
invalidation block further live admission. Stale pin changes fail
closed. The envelope is not a runtime grant.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Automatic admission from a passing evaluation was rejected because
that would expand authority. Unsigned current-state flags were
rejected because they cannot be independently verified. Deleting
history on stop or rollback was rejected because later review would
have no retained envelope.

## Consequences

Operators admit, inspect, stop, roll back, note lease loss, and
invalidate receipts through `sekaictl admin autonomy`. ActionInstance
admission consumes a live envelope when `type_id` starts with
`autonomous.` or `autonomous_envelope_id` is set. Existing
ActionInstance admission remains the runtime write path.

## Validation

Two adapter fixtures cover current pins, stop, rollback, lease loss,
and receipt invalidation.
