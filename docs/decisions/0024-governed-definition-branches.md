# ADR 0024: Evolve governed definitions through branches with immutable revision history

- Status: proposed
- Date: 2026-08-24
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/722
- Supersedes: none
- Superseded by: none
- Related: ADR 0020, Issue #666

## Context

ADR 0020 makes a namespace-scoped type revision the durable identity consumed
by runtime facts. The shipped object-sync profile has one code-owned digest,
while schema and ontology authoring still updates global rows by name. There is
no generic parent, branch, immutable member, revision history, rebase,
proposal, preview, or merge contract.

A single immutable proposal snapshot would protect one parent, but it would
not give repeated edits, concurrent published changes, conflict resolution,
proposal refresh, or preview cleanup one stable lifecycle. Extending mutable
upserts with audit history would preserve neither an exact parent nor an
independently verifiable candidate.

## Decision

1. A governed definition branch has a stable namespace-scoped identity, an
   immutable base revision, and a head advanced only by compare-and-swap.
2. Definition members are canonical, content-addressed documents. A revision
   digest binds its contract version, namespace, immutable parent, and
   deterministically ordered member identities and digests.
3. Editing a branch appends members, a revision, request identity, and audit
   evidence before advancing the head in the same backend transaction. It
   never rewrites a parent revision.
4. Exact idempotent replay returns the stored result. Reusing a key for
   different canonical input or writing from a stale head fails explicitly.
5. Every branch operation rechecks namespace and member authorization.
   Missing, hidden, and unauthorized revision identities do not disclose
   protected definition bodies or property values.
6. Branch creation and editing do not change the published head, runtime
   facts, source bindings, object identities, or mutable legacy definition
   rows.
7. Rebase, deterministic differences, compatibility classification, isolated
   preview, branch archival, and fact migration extend this branch/revision
   foundation through separate public contracts. Proposal, approval, and
   published-head merge are the #683 publication contract.
8. SQLite and reusable PostgreSQL advertise a branch surface only when they
   pass shared transactional and concurrency conformance.

## Alternatives considered

- Keep mutable definition upserts and add audit rows. Rejected because an audit
  log cannot recover an exact immutable parent or prevent silent concurrent
  overwrite.
- Store one immutable proposal snapshot. Rejected because later authoring
  stages would need separate branch, rebase, conflict, and lifecycle identity.
- Store only edit commands. Rejected because runtime bindings, comparison, and
  independent verification require an exact resulting revision digest.

## Consequences

- The control plane gains insert-only member and revision state plus mutable
  branch-head, idempotency, and audit projections.
- Existing schema, ontology, action, and object-sync APIs retain their current
  behavior until an explicit adoption or publication contract replaces them.
- Member and revision canonicalization becomes a public compatibility
  boundary. New member forms require a versioned contract.
- Stale writers must reload the branch head and later rebase; the service will
  not manufacture an automatic merge.
- Rollback never deletes revision history. After publication and fact binding
  exist, rollback requires a superseding revision and an explicit migration.

## Validation

- Deterministic fixtures recompute member and revision digests across input
  order, reject mismatches and duplicate identities, and preserve parent rows.
- Concurrent edits from one expected head produce one successful advancement
  and one stale-head result.
- Exact replay, conflicting replay, unknown parent, authorization denial, and
  interrupted-transaction fixtures fail without partial durable success.
- SQLite runs in normal CI. PostgreSQL uses the same backend conformance suite
  when an isolated test database is available.
