# Governed definition branches

Governed definition branches let an authorized schema author evolve one exact
namespace-scoped definition revision without changing published definitions or
runtime facts. The current contract is a persistence and concurrency
foundation advertised at the experimental product tier; it does not yet
publish, preview, compare, rebase, review, merge, or migrate a branch.

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

- No public registration or publication operation is part of this foundation.
  Branch creation requires an existing published parent registered by a later
  governed adoption path.
- A branch cannot yet be rebased, proposed, approved, previewed, merged, or
  archived.
- Revision differences and compatibility classifications are not inferred.
- Runtime facts and source bindings remain attached to their existing type
  identities.
- Existing mutable schema and ontology APIs remain separate legacy authoring
  surfaces; branch creation never snapshots them implicitly.

See [ADR 0024](decisions/0024-governed-definition-branches.md) for the durable
design and [the native protocol](../proto/sekai.proto) for exact messages.
