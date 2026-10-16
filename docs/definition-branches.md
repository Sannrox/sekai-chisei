# Governed definition branches

Governed definition branches let an authorized schema author evolve one exact
namespace-scoped definition revision without changing published definitions or
runtime facts. The experimental product-tier contract now also publishes or
rejects one pinned candidate through a proposal, compares two revisions,
classifies compatibility, and proposes an append-only rollback of a prior
published revision. Rollback never rewrites history.
Branch, proposal, rollback, compare, compatibility, and fact-migration RPCs are
classified `experimental` and are rejected unless `SEKAI_EXPERIMENTAL_RPCS=1`
or the `experimental-rpcs` Cargo feature is enabled. See
[rpc-maturity.md](rpc-maturity.md). `GetPublishedDefinitionRevision` stays
`stable`. `ListPublishedDefinitionRevisions` is an additive experimental read of merge history.

## Contract

`CreateDefinitionBranch` creates a stable branch identity from an existing
authorized published revision. The request supplies:

- `namespace`;
- a canonical `branch_id`;
- the exact `parent_revision_digest`; and
- an `idempotency_key`.

The new branch initially has the parent as both its base and head. Creation
does not update the namespace's published head.

**Genesis.** Every namespace starts from a deterministic, empty, published
genesis revision (no members, no parent). An empty `parent_revision_digest`
means "branch from genesis". It is accepted only while the namespace has
published nothing else: the caller needs namespace write authority, genesis is
seeded idempotently as the published head, and the branch starts there. The
first real revision then follows the normal edit, proposal, approval, and merge
flow, with `expected_published_digest` set to the genesis digest. Once a
namespace has published anything else, an empty parent fails
`FAILED_PRECONDITION`; branch from the published head instead.

`GetDefinitionBranch` returns the current authorized branch head and a
content-addressed `pin_digest` bound to the branch contract, namespace,
branch id, and head revision. A delivery consumer verifies the pin against
that same identity; the pin is not a second authority. Use this read after
a stale-head result before preparing another edit. The path reauthorizes
the current revision and returns no member bodies.

`ApplyDefinitionBranchEdit` advances an existing branch. The request supplies
the exact `expected_head_digest`, bounded member upserts and removals, and an
idempotency key. The server:

1. rechecks namespace and member authorization;
2. canonicalizes each upserted JSON object;
3. recomputes every supplied member digest;
4. applies the resource-level changes to the immutable parent member map;
5. computes a new immutable revision digest;
6. stores members, revision, request result, and audit evidence; and
7. advances the branch head with compare-and-swap.

The response reports the new digest for every upsert and the prior digest for
every removal, sorted and deduplicated as one changed-member set.

A competing writer that already advanced the head makes the request stale.
The server does not automatically merge it.

`CreateDefinitionProposal` pins the current published head as `base_digest`
and the branch head as `candidate_digest`. Optional `eval_plan_digests` are
frozen Chisei dependencies; `named_foreign_digests` may be recorded but never
enter the published member map. Creating a proposal does not move the
published head.

`ApproveDefinitionProposal` records a live approval on an open proposal.
`MergeDefinitionProposal` requires `expected_published_digest` and rechecks
that the live published head equals both that digest and the pinned base, the
branch head still equals the candidate, the candidate descends from the pinned
base, at least one recorded approver still holds namespace write and
changed-member admin, and named foreign digests are not members. It classifies
the candidate against the published head and refuses the whole merge when a
`function`, `transform`, or `policy` change is breaking, or when any member
kind is unknown, naming `compatibility_gate:{member_kind}`. Breaking
object-type, interface, ontology, link, action, and control members still
publish so checkpointed fact migration can follow the published head. A
refused gate leaves the published head unchanged. It then compare-and-swaps
the namespace published head, stores a durable `receipt_id` on the merged
proposal, and writes the receipt, audit, and idempotency record in the same
transaction. Exact replay of the same idempotency key returns that receipt
without moving the published head again. A stale expected digest or a
candidate that is not a descendant of the pinned base fails closed as not
mergeable. Interrupted merges leave the published head unchanged and store no
receipt.

`CloseDefinitionProposal` rejects an open proposal with a canonical
`reason_code` (`operator_abort`, `superseded`, or `policy_denied`) without
moving the published head. Merge of a closed proposal remains denied.
`GetPublishedDefinitionRevision` returns the current published pointer.
`ListPublishedDefinitionRevisions` returns that namespace's published merge history, newest first. Each entry names the published revision digest, previous published digest, merged proposal id, merge receipt id, actor, and time. Optional `member_kind` and `member_id` must both be set or both empty and keep only merges that added, removed, or digest-changed that member. Pagination is keyset on merge time then proposal id so a concurrent merge cannot duplicate or skip an earlier page. Auth matches `GetPublishedDefinitionRevision`. A nonempty member filter also reauthorizes that member the same way `GetDefinitionMember` does, so a later removal cannot disclose its history to a caller without that grant. The RPC does not restore or roll back a revision.

`ProposeDefinitionRollback` opens a draft whose candidate members match a
previously published revision `A` while remaining a descendant of the live
published head `B`. It creates the branch, applies the restore edits, and
pins the proposal in one transaction. The response returns the proposal and a
preview diff of `B` versus the candidate. Auth matches
`CreateDefinitionProposal`: namespace write plus write on every member that
would change. `restored_from_digest` and optional `migration_plan_digest` are
additive proposal fields. Merge of that proposal publishes a new revision `C`
(never a rewrite of `A`) and records `restored_from_digest` on the merge
receipt. When the rollback would drop object-type properties that live objects
or datasets still carry, merge without a pinned `migration_plan_digest` fails
`definition_rollback_requires_migration_plan`. The pin is a digest, not an
executed fact migration; `ExecuteDefinitionFactMigration` still requires the
TO revision to already be the published head.

`CompareDefinitionRevisions` takes two revision digests in one namespace. It
reauthorizes every member on both revisions, then reports added, removed, and
changed members in kind-then-id order. Changed object-type properties are
named without returning definition JSON. Unknown property constructs fail
closed. Unauthorized or missing revisions are unavailable and do not
distinguish hidden from absent members.

`ClassifyDefinitionRevisionCompatibility` reuses that authorized comparison
and assigns a worst-wins class of `compatible`, `conditional`, `breaking`, or
`unknown`, with content-bound reasons that name member identities, property
keys, and reason codes. Reason volume inherits the revision member and
definition-byte ceilings. It does not return definition bodies, mutate a
published parent, or execute a fact migration.

Classification vocabulary:

- `compatible`: additive optional properties and new `object_type`,
  `interface_type`, `ontology_class`, `ontology_relation`, or `link_type`
  members. Removing a required constraint without removing the property is
  compatible.
- `conditional`: new `action_type`, `function`, `transform`, `policy`, or
  `control` members, `access_marking` changes, and known field changes such
  as `name` or `mode`. These require live authorization or review before
  effect; they are not silent success.
- `breaking`: removed members, removed properties, and newly required
  properties. Breaking changes need an approved migration path before facts
  can follow the candidate.
- `unknown`: a well-formed change the classifier does not map, such as an
  unrecognized field. Unknown is never treated as compatible.

Malformed `properties`, `required`, or `access_marking` constructs fail closed
instead of producing a class. The compatibility digest binds both revision
digests, the class, the ordered reasons, and the compare digest.

## Content identity

Member contract `sekai.definition-member/v1` supports these domain-neutral
member kinds:

- `object_type`
- `interface_type`
- `ontology_class`
- `ontology_relation`
- `link_type`
- `action_type`
- `function`
- `transform`
- `policy`
- `control`

Member identity binds the contract version, namespace, member kind, stable
member ID, and canonical definition JSON. Objects are key-sorted recursively;
arrays retain their declared order. Duplicate object keys, non-object
definitions, unsupported member kinds, and a supplied digest that differs from
the server result are invalid.

Revision contract `sekai.definition-revision/v1` binds the namespace, exact
parent revision, and the deterministically ordered map of member identities and
digests. Author and timestamp metadata do not affect content identity.

Branch contract `sekai.definition-branch/v1` treats the branch head as a
mutable concurrency projection. Members and revisions remain insert-only
authority.

## Authorization and non-disclosure

Every operation requires namespace write access. Creating a branch also
requires read access to every member inherited from its published parent.
Editing requires read access to every inherited member and administrative
access to every changed member through the existing schema, ontology, or
action authorization boundary.

Unknown and unauthorized revision identities return an unavailable result
without definition bodies. Errors and audit rows never include member JSON or
restricted property values.

## Retry and recovery

Idempotency is scoped by namespace, authenticated actor, and key. Exact replay
returns the recorded branch or edit result. Reusing the key with different
canonical input fails explicitly.

Member, revision, idempotency, audit, and head writes share one backend
transaction. A failed transaction cannot leave an advanced branch head without
its immutable revision and audit evidence.

## Current limits

- Branch creation starts from a published parent or from genesis. There is no
  implicit snapshot of legacy mutable schema or ontology rows.
- A branch cannot yet be rebased, previewed, archived, or used to migrate
  runtime facts.
- `CompareDefinitionRevisions` reports deterministic added, removed, and
  changed members and property keys between two authorized revisions without
  returning definition bodies.
- `ClassifyDefinitionRevisionCompatibility` classifies that same authorized
  pair as compatible, conditional, breaking, or unknown.
- `ExecuteDefinitionFactMigration` runs one approved checkpointed fact
  migration from an ancestor revision onto the published head, with dry-run,
  execute, resume-by-replay, and rollback. Unknown compatibility, stale
  parents, and unapproved breaking or conditional changes fail closed. Blocked
  transforms do not mutate objects. Published definition rows are never
  rewritten. Rollback names the stored parent and candidate. Live object and
  property grants are rechecked at effect; hidden objects are omitted and
  ungranted properties are not stripped. Mutation, audit, and object lineage
  share one transaction. `GetDefinitionFactMigration` does not distinguish
  missing from unauthorized revisions. See
  [ADR 0028](decisions/0028-checkpointed-fact-migration.md).
- Runtime objects of `object_type` members are rebound by that migration.
  Source bindings remain attached to their existing type identities.
- Package identity is not a runtime grant. Evaluation-plan digests on a
  proposal are frozen references, not a second merge protocol.

See [ADR 0024](decisions/0024-governed-definition-branches.md) for the
branch/revision foundation, [ADR 0026](decisions/0026-governed-branch-proposals.md)
for publication as a digest-bound proposal, and
[the native protocol](../proto/sekai.proto) for exact messages.

## Agent draft documents and exact member reads

`agent` members use this strict document shape:

```json
{
  "contract_version": "sekai.agent-definition/v1",
  "name": "Triage",
  "task_class": "lookup",
  "instructions": "Inspect records.",
  "allowed_action_types": ["Ticket.inspect"]
}
```

Names, task classes, and Action references must be nonempty canonical identifiers
of at most 256 bytes. Instructions must be nonempty text of at most 128 KiB,
without NUL bytes. The Action allowlist contains at most 128 unique references.
Unknown fields, missing fields, duplicate JSON keys, and unsupported document
versions are rejected before persistence. Action references grant no authority.

Use existing branch edits to save a draft. `GetDefinitionMember` accepts the
namespace, exact `revision_digest`, `member_kind`, and `member_id`, returning
canonical `definition_json`, its member digest, and the revision digest. It
supports existing member kinds too. A read requires namespace access and read
grants for every member of the selected revision, preserving revision-wide
visibility. Missing and denied members return the same generic NotFound status;
corrupt or incorrectly bound content returns a generic Internal status.

The RPC is experimental and disabled unless the server sets
`SEKAI_EXPERIMENTAL_RPCS=1` or builds with `experimental-rpcs`. This does not change
credential scopes or resource grants. Merging a proposal that changes an
agent-definition member requires a current, non-revoked, baseline-passing
certification bound to the candidate revision
([ADR 0079](decisions/0079-evaluation-promotion-gate.md)). Missing, stale,
failed, or revoked evidence is `failed_precondition` with a stable
`agent_promotion_*` reason. Direct publish of an agent member is still
refused. `PutDefinitionCertification` binds suite identity and pass/fail from
a stored eval run (`certification_id`) to the candidate revision. Authors
of agent-member changes since the published base cannot bind; a later bind
cannot clear `revoked_at_ms`; expiry cannot exceed 90 days from
`bound_at_ms`.
`GetDefinitionCertificationGate` reports the same admitted or refused state
the merge uses. Proposals that do not change agent members are unchanged.
See [ADR 0093](decisions/0093-agent-drafts-use-definition-members.md).

`DryRunAgent` runs one caller-supplied input against an Agent member at an
exact revision. Auth matches `GetDefinitionMember`, including the same
unavailable answer for a missing or unreadable member. The response is a
step trace: model steps, tool calls, and proposed Actions marked
`would_submit` or `refused`. No Action instance is created. The attempt is
stored as an eval run marked `dry_run` and cannot bind
`PutDefinitionCertification` ([ADR 0109](decisions/0109-agent-dry-run.md)).
Route admission and budget are checked once; a failure is returned, not
retried. The RPC is experimental.

### Scoped draft authoring

Scoped authenticated contexts can call qualified `sekai.SekaiService`
`GetDefinitionBranch`, `CreateDefinitionBranch`, and `ApplyDefinitionBranchEdit`
through the normal server-established RPC identity. All three remain experimental.
Creation and editing require actual namespace write scope and grants; editing
also requires revision-wide read visibility and administration of changed members.
The server attributes writes to the authenticated subject, not caller metadata.

Use separate idempotency keys for branch creation and each edit. Every edit
requires the exact expected head digest. A stale head returns FailedPrecondition;
a conflicting request under the same key returns AlreadyExists. After a timeout,
the outcome is unknown: retry the identical operation and key with a fresh
assertion. Identical retries return the original receipt, even after the head has
advanced. Reload before choosing a new edit following a conflict.

Draft authoring never advances the published pointer. See
[ADR 0094](decisions/0094-scoped-definition-draft-authoring.md).

Scoped contexts can also call qualified `GetDefinitionProposal`,
`CreateDefinitionProposal`, `ApproveDefinitionProposal`, and
`MergeDefinitionProposal` to publish a draft. The same namespace write, member
administration, approval, expected-published-digest, and ADR 0079 certification
checks apply; `CloseDefinitionProposal` is not available to scoped contexts. See
[ADR 0111](decisions/0111-scoped-definition-proposals.md).
