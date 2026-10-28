# ADR 0136: Site agent instances bind a responsibility to a certified definition and act as their principal

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Issue: #1932, split from #1610
- Related: [ADR 0093](0093-agent-drafts-use-definition-members.md),
  [ADR 0079](0079-evaluation-promotion-gate.md),
  [ADR 0059](0059-autonomous-envelopes.md), #1353, #1449, #715

## Context

Agent definition members (`sekai.agent-definition/v1`, ADR 0093) describe how
an agent behaves, and certification gates their publication (ADR 0079,
#1353). Nothing durable represents an always-on instance that owns a site
responsibility, such as a production line, a fleet or a pipeline. Wakes,
working memory and review queues have nothing to bind to. The contract must
be fixed before code, because it decides where authority lives.

## Decision

Accept `sekai.site-agent-instance/v1`. Identity is
`(namespace, instance_id)`. An instance has exactly these fields:

- `definition_revision_digest`: the published, certified definition revision
  the instance runs.
- `agent_member`: the agent member of that revision the instance runs. A
  revision can hold several agents, so the digest alone does not say which.
- `principal_id`: the org-owned principal the instance acts as.
- `responsibility`: the object ids or the ObjectSet it owns.
- `wake_policies`: references to wake policies, by id. Wake admission is a
  separate contract.
- `autonomy_envelope_id`: optional. When set, live autonomous admission
  follows ADR 0059 for that envelope.
- `frozen`: whether the instance is frozen.

Only governed Actions create, update, freeze and unfreeze an instance. Each
change goes through ActionInstance admission and leaves a verifiable receipt
(#1449). There is no direct write path.

An instance grants no authority. Grants and markings stay on its principal,
and a wake acts as that principal. Creating or updating an instance never
widens what the principal may read or do. List and get apply the caller's
markings to the instance as to any object. An instance the caller may not
read is indistinguishable from a missing one.

Admission refuses binding an instance to a revision that is unpublished, not
certified, or published in another namespace, and refuses an `agent_member`
that is not an agent member (`sekai.agent-definition/v1`) of that revision.
Admission, not later execution, decides this, and re-checks it on every
update that changes `definition_revision_digest` or `agent_member`.

A frozen instance admits no new wakes and no new Actions on its behalf.
Freezing and unfreezing are audited governed Actions. Work admitted before the
freeze completes under its existing receipts; freezing is not cancellation.
An Action's commit is ordered against the freeze (#1970): its object write, or
its receipt when it writes none, re-checks the instance in the committing
transaction, and a parked Action granted after the freeze ends denied with a
receipt naming it.

SQLite is the reference store, as on dark sites. PostgreSQL stays
unavailable for instances until a slice adds parity and shared conformance,
as for autonomous envelopes (ADR 0059). A PostgreSQL deployment refuses
instance Actions with an explicit unavailable error rather than storing them
elsewhere.

## Alternatives considered

- Instance-held grants: rejected. Authority would follow a configuration
  object instead of an identity, and two instances could widen one
  principal's reach.
- Binding to a draft or uncertified revision with a warning: rejected,
  because certification would stop gating what runs.
- A direct CRUD API beside the Actions: rejected, because changes would leave
  no receipts and could bypass policy.
- PostgreSQL parity in the first slice: deferred, because dark sites need
  SQLite first and the gap is explicit and fails closed.

## Consequences

#1610's code slices implement this contract: the type, the four governed
Actions, revision admission, the freeze check at wake and Action admission,
and marking-aware list and get. Wake admission, working memory and channel
adapters build on the instance without changing it. A new field needs a new
schema version. No existing schema, policy or runner contract changes.

## Validation and reversal

Conformance shows that instance changes happen only through Actions with
receipts, that binding to an unpublished or uncertified revision, or to a
member that is not an agent in it, is refused,
that a frozen instance admits no wake or Action, and that a hidden instance
reads as missing. Reverse with a later ADR. Instances are additive and can be
removed without migrating other data.
