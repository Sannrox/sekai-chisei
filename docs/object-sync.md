# Inbound object sync

Shared type revisions receive objects from one system of record at a time.
The first family is `source_control.object_sync` for GitHub Issue and
PullRequest records.

Rules:

- Source identity is `github:{owner}/{repo}#{number}`.
- Object id is derived from `type_digest` plus source identity.
- Delete observations tombstone the same object; they do not mint a new id.
- A source identity that would move across type revisions is a conflict.
- This is not a pipeline or transform product.

Write-back uses permit-backed `external_mutate`. Dataset lineage records
source → dataset → object → action → write-back without a second object
identity. See [ADR 0020](decisions/0020-shared-type-revisions-and-object-sync.md).
