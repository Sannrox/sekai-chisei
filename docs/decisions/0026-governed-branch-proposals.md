# ADR 0026: Publish atomic change sets as governed branch proposals

- Status: proposed
- Date: 2026-08-24
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/726
- Supersedes: none
- Superseded by: none
- Related: ADR 0024, ADR 0020, ADR 0011, Issue #669, Issue #683

## Context

ADR 0024 gives a namespace an immutable definition-revision history and a
compare-and-swap branch head. It explicitly deferred proposal, approval, and
merge. Without that publication contract, a reviewed overlay can still land
after the published head moved, after a member digest changed, or without a
live publish grant, and a signature or package identity can be mistaken for
authority.

## Decision

1. A namespace has one canonical published definition head. Seed and merge
   compare-and-swap that pointer; they never rewrite revision history.
2. A change set is a **proposal** on a governed branch. Content identity is
   `(namespace, branch_id, proposal_id, base_digest, candidate_digest)` plus
   canonical frozen evaluation-plan references and named foreign digests.
3. Proposal creation pins the current published head as `base_digest` and the
   current branch head as `candidate_digest`. The candidate must descend from
   the base. Branch-head or published-head movement invalidates the pin.
4. Approval is two-layer and live at merge: set-level approval is digest-bound
   on the proposal, and every changed member is rechecked against current
   publish/admin grants. One rejection denies the whole proposal. Historical
   approval is not authority.
5. Merge rechecks the pin, approval, member grants, and parent chain, then
   compare-and-swaps the published head from base to candidate in one
   namespace transaction bound to a receipt. Interrupted merge reconstructs
   from the receipt; the published head either advanced with its revision and
   audit or it did not.
6. Frozen evaluation-plan digests and named foreign digests may be recorded.
   They confer no grant and are not a second merge protocol. Evaluation plans
   are not definition members.
7. Rollback never rewrites history. Undo is a new branch from the previous
   published head. Rebase, preview, protection policy, and fact migration
   remain separate contracts.
8. SQLite and reusable PostgreSQL implement the same transactional
   conformance. Unsupported surfaces fail explicitly.

## Alternatives considered

- Selector over already-published members. Rejected because members would be
  visible before review and atomicity would only cover review-to-publish
  drift.
- Draft members with visibility-gated publication. Rejected because it splits
  every participating family into draft versus live and breaks current
  write-equals-readable behavior.

## Consequences

- Branch edits still do not publish. Publication is an explicit proposal merge.
- Existing schema, ontology, and action mutation APIs remain separate until an
  adoption path binds runtime facts to published revision digests.
- Package certification (#690) may later name a merged digest. Package trust
  is never a runtime grant.

## Validation

- Deterministic fixtures cover mixed definition members, frozen evaluation
  references, named foreign digests, missing approval, rejection, changed
  digest, stale base, exact replay, and interrupted merge without a moved
  published head.
- SQLite runs in normal CI. PostgreSQL uses the shared backend conformance
  suite when an isolated test database is available.
