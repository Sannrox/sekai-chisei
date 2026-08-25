# Governed definition branches

Governed definition branches let an authorized schema author evolve one exact
namespace-scoped definition revision without changing published definitions or
runtime facts. The experimental product-tier contract now also publishes or
rejects one pinned candidate through a proposal. It does not yet preview,
rebase, or migrate facts.

## Contract

`CreateDefinitionBranch` creates a stable branch identity from an existing
authorized published revision. The request supplies:

- `namespace`;
- a canonical `branch_id`;
- the exact `parent_revision_digest`; and
- an `idempotency_key`.

The new branch initially has the parent as both its base and head. Creation
does not update the namespace's published head.

`GetDefinitionBranch` returns the current authorized branch head. Use it after
a stale-head result before preparing another edit. The read path reauthorizes
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
changed-member admin, and named foreign digests are not members. It then
compare-and-swaps the namespace published head, stores a durable `receipt_id`
on the merged proposal, and writes the receipt, audit, and idempotency record
in the same transaction. Exact replay of the same idempotency key returns that
receipt without moving the published head again. A stale expected digest or a
candidate that is not a descendant of the pinned base fails closed as not
mergeable. Interrupted merges leave the published head unchanged and store no
receipt.

`CloseDefinitionProposal` rejects an open proposal with a canonical
`reason_code` (`operator_abort`, `superseded`, or `policy_denied`) without
moving the published head. Merge of a closed proposal remains denied.
`GetPublishedDefinitionRevision` returns the current published pointer.

`CompareDefinitionRevisions` takes two revision digests in one namespace. It
reauthorizes every member on both revisions, then reports added, removed, and
changed members in kind-then-id order. Changed object-type properties are
named without returning definition JSON. Unknown property constructs fail
closed. Unauthorized or missing revisions are unavailable and do not
distinguish hidden from absent members.

## Content identity

Member contract `sekai.definition-member/v1` supports these domain-neutral
member kinds:

- `object_type`
- `interface_type`
- `ontology_class`
- `ontology_relation`
- `link_type`
- `action_type`
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

- Branch creation still requires an existing published parent. Tests and
  adoption paths seed that parent; there is no implicit snapshot of legacy
  mutable schema or ontology rows.
- A branch cannot yet be rebased, previewed, archived, or used to migrate
  runtime facts.
- `CompareDefinitionRevisions` reports deterministic added, removed, and
  changed members and property keys between two authorized revisions without
  returning definition bodies. Compatibility classification and fact migration
  remain separate contracts.
- Runtime facts and source bindings remain attached to their existing type
  identities.
- Package identity is not a runtime grant. Evaluation-plan digests on a
  proposal are frozen references, not a second merge protocol.

See [ADR 0024](decisions/0024-governed-definition-branches.md) for the
branch/revision foundation, [ADR 0026](decisions/0026-governed-branch-proposals.md)
for publication as a digest-bound proposal, and
[the native protocol](../proto/sekai.proto) for exact messages.
