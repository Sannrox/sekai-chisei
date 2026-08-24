# Governed definition branches

Governed definition branches let an authorized schema author evolve one exact
namespace-scoped definition revision without changing published definitions or
runtime facts. Branch create and edit remain an experimental persistence and
concurrency foundation. Publication is a separate experimental change-set
contract: a digest-bound proposal, live approval, and atomic published-head
merge. The surface still does not preview, compare, rebase, or migrate facts.

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

## Change-set publication

A namespace has one canonical published definition head. `GetPublishedDefinitionHead`
returns that pointer after reauthorizing the published revision. Branch edits
never move it.

`CreateDefinitionProposal` pins the current published head as `base_digest` and
the current branch head as `candidate_digest`. Optional frozen evaluation-plan
references and named foreign digests are part of the proposal digest. They
record dependencies; they are not grants and not a second merge protocol.

`ApproveDefinitionProposal` records set-level approval for that exact proposal
digest. `RejectDefinitionProposal` denies the whole change set. Approval is
not authority: merge rechecks live member publish/admin grants.

`MergeDefinitionProposal` succeeds only when:

- the proposal is approved for the expected digest;
- the published head still equals the pinned base;
- the branch head still equals the pinned candidate;
- the candidate still descends from the base;
- named foreign digests do not impersonate member grants.

The merge compare-and-swaps the published head, marks the candidate revision
published, and stores a receipt in the same transaction. Exact replay returns
the stored result. Interrupted merge leaves the published head unmoved.

Rollback does not rewrite history. Undo is a new branch from the previous
published head.

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
  operators seed that parent until an adoption path replaces it.
- A branch cannot yet be rebased, previewed, or archived.
- Revision differences and compatibility classifications are not inferred.
- Runtime facts and source bindings remain attached to their existing type
  identities. Merging a proposal does not migrate objects, datasets, or source
  records.
- Existing mutable schema and ontology APIs remain separate legacy authoring
  surfaces; branch creation never snapshots them implicitly.
- Package trust is not a runtime grant.

See [ADR 0024](decisions/0024-governed-definition-branches.md) for the branch
foundation, [ADR 0026](decisions/0026-governed-branch-proposals.md) for
publication, and [the native protocol](../proto/sekai.proto) for exact
messages.
