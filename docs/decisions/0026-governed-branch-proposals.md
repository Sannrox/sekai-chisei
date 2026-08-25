# ADR 0026: Publish change sets as governed branch proposals

- Status: accepted
- Date: 2026-08-25
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/726
- Issue: https://github.com/Sannrox/sekai-chisei/issues/734
- Supersedes: none
- Superseded by: none
- Related: ADR 0024, Discussion 726, Issues #669, #683, #731, #733

## Context

[ADR 0024](0024-governed-definition-branches.md) established governed branches
with immutable revision history and deferred proposal, approval, and
published-head merge to a later publication contract (#683).

Without one named contract, a reviewed overlay can still land with a stale
base, a changed candidate, missing approval, or a foreign digest treated as a
grant. Signatures, discovery, and package identity can be mistaken for
runtime authority. Discussion 726 selected the publication model; #731 shipped
it and #733 completed merge receipt, expected published-head compare-and-swap,
not-descendant denial, and close-reason diagnosis.

This record is the durable decision so later package, rebase, and fact-migration
work cannot reopen the rejected alternatives.

## Decision

A change set is a **proposal** on a governed branch. It pins exact base and
candidate digests, rechecks live grants, and compare-and-swaps one namespace
published head.

1. A namespace has one canonical published definition head. That pointer is
   production, not a draft.
2. A governed branch is a named overlay. Edits mint immutable revisions and
   compare-and-swap the branch head. The branch does not change published
   heads, production facts, source bindings, or object identities.
3. Proposal identity is `(namespace, branch_id, proposal_id, base_digest,
   candidate_digest)`. Replay of that tuple is the same evidence.
4. The proposal pins the published base and the branch-head candidate. A later
   branch-head change invalidates checks and approvals.
5. Validation at create and again at merge fails closed on stale base, missing
   member, conflict, unknown mandatory member, digest mismatch, unauthorized
   member, revoked grant, privilege-expanding change without explicit
   approval, or a foreign-authority member treated as a grant. Foreign digests
   may be named; they confer nothing.
6. Approval is two-layer and **live at merge**. Historical approval is not authority.
   At least one recorded approver must still hold namespace write and
   changed-member admin. One rejection denies the whole proposal.
7. Unchanged resources remain on the published head. Evaluation plans may be
   referenced by digest as frozen dependencies; they are not a second merge
   protocol. Objects, datasets, and source records are not members.
8. Merge rechecks live grants, expected published head, ancestry, and
   approvals, then compare-and-swaps the published head in one namespace
   transaction bound to a receipt. Interrupted merge reconstructs from that
   receipt. The head either advanced with its revision and audit or it did
   not.
9. Rollback never rewrites history. Undo is a new branch from the previous
   published head.
10. Rebase produces a new immutable revision and does not preserve prior
    proposal approval.
11. External writeback and permits stay on the ADR 0020 path. They are not
    change-set members.
12. Signatures, discovery, and package trust are not runtime grants.
    Portable packages (#690) may later certify a merged digest; that
    certification still confers no grant.

Shipped #731 behavior is current: pin a governed branch overlay, record live
approval, and compare-and-swap one namespace published head, or close without
moving the head.

#733 names the remaining evidence obligations from this decision—merge
receipt identity, expected published-head compare-and-swap, not-descendant
`FailedPrecondition` denial, and canonical close reasons. Those obligations
are evidence work, not an open design question. They shipped in #735.

## Alternatives considered

- **Selector over already-published members.** A change set would be a
  content-addressed manifest of already-live published resources. Rejected
  because members would be visible before review, and atomicity would only
  protect review-to-publish drift.
- **Draft members with visibility-gated publication only.** Members would stay
  unpublished until one transaction made the set readable. Rejected because it
  splits every participating family into draft versus live and breaks
  write-equals-immutable-and-readable behavior for plans, types, facts, and
  actions.

## Consequences

- Publication stays an overlay on ADR 0024 branches. ADR 0024 remains the
  branch/revision foundation.
- Clients must supply the expected published digest at merge. Empty, stale, or
  unknown CAS tokens fail closed.
- Package, signature, and discovery work cannot treat those artifacts as
  grants without a new ADR.
- Rebase, isolated preview, protection policy, and fact migration remain
  separate contracts.

## Validation

- #731 and #735 deterministic fixtures cover definition members, frozen
  evaluation-plan references, missing approval, changed digest, stale base,
  unauthorized member, named-but-not-granted foreign identity, atomic merge,
  exact receipt replay, not-descendant denial, close reasons, and interruption
  without a moved head.
- SQLite runs in normal CI. PostgreSQL uses the shared definition-branch
  conformance suite when an isolated test database is available.
