# Inbound object sync

Shared type revisions receive objects from one system of record at a time.
The first family is `source_control.object_sync` for GitHub Issue and
PullRequest records. There is no second source. See
[ADR 0021](decisions/0021-defer-second-object-sync-source.md).

Rules:

- Source identity is `github:{owner}/{repo}#{number}`.
- Object id is derived from `type_digest` plus source identity.
- Issue and PullRequest share GitHub's number space, so `source_id` omits
  `type_name`. A pull request and its issue number are one identity.
- Delete observations tombstone the same object; they do not mint a new id.
- A source identity that would move across type revisions is a conflict.
- Webhook, document, and poll feeds are transport into the same mapper. They
  do not create a second family or identity.
- Additional GitHub kinds (discussions, releases, deployments, check runs)
  are rejected under this identity format. Check runs stay evidence
  observations.
- This is not a pipeline or transform product.

Write-back uses permit-backed `external_mutate`. Dataset lineage records
source → dataset → object → action → write-back without a second object
identity. See [ADR 0020](decisions/0020-shared-type-revisions-and-object-sync.md).
