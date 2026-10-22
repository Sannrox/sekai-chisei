# ADR 0119: Dataset branches are one working copy, merged as one version

- Status: accepted
- Date: 2026-10-22
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1444
- Issue: #1444
- Supersedes: none
- Superseded by: none
- Related: [ADR 0080](0080-dual-community-runtime-storage.md)

## Context

Datasets have versions and rollback (#1412) but no branches. To check a
transform change against a copy of its data, the copy must not touch the
version that objects and other transforms read. The merge must be
reviewable and leave a record.

## Decision

1. A branch is one working copy of a dataset, named per dataset
   (`[A-Za-z0-9._-]`, at most 64 characters), forked from a version (default:
   the latest). It has no version history of its own. Branch rows live in
   `sekai_dataset_branch_rows`, outside `sekai_dataset_versions`, so version
   listing, sequence numbers and count-based retention are unchanged.
2. Creating a branch copies nothing. Until its first write, the branch reads
   its base version. The first append copies the base into the working copy,
   and a replacing write does not. Retention never purges a version that an
   open branch forks from.
3. Compare reports the column set, row counts and an order-independent row
   digest of the branch head against the parent's live rows.
4. Merge goes through a proposal that pins the branch digest and the parent's
   latest version. Proposing the same pair again returns the same proposal.
   A different principal in the same tenant merges it; that merge is the
   approval. The merge is refused when either pinned head has moved. It
   replaces the parent's live rows with the branch head, writes exactly one
   new version, and marks consuming transform outputs stale, as rollback
   does. It records a receipt id: a digest over the dataset, the proposal,
   both pinned heads and the new version. Replaying a merged proposal returns
   it and writes nothing.
5. Merge and delete drop the branch and its working copy, and delete closes
   the branch's open proposals. The proposal row is the durable record.
6. Redaction and subject erasure rewrite branch working copies with live and
   version rows, so a branch never keeps a value they removed. Each branch
   incarnation has its own id, so a recreated branch gets fresh proposals.
7. SQLite and PostgreSQL store the same three tables (`0088_dataset_branches`
   on PostgreSQL). On PostgreSQL every branch mutation takes the dataset rows
   lock that appends, rollback and redaction use, so they serialize.

## Consequences

A transform run on a branch reads each input's branch head where that
dataset has the branch, and the parent's live rows otherwise. It computes in
full and writes only the output dataset's branch, creating it on demand in
the caller's tenant. It writes no parent rows, checkpoint, trigger or marking
stamp. Because a branch cannot carry a stricter stamp than its parent, a run
whose derived marking would raise the output's marking is refused. The
isolated transform runtime refuses branch runs until it carries a branch. Abandoned open branches do not expire;
an operator deletes them. Row-level merge conflicts are out of scope: a moved
parent means proposing again.
