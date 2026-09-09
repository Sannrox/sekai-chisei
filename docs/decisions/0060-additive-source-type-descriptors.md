# ADR 0060: Admit later object-sync kinds through additive registered descriptors

- Status: accepted
- Date: 2026-09-09
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/817
- Issue: https://github.com/Sannrox/sekai-chisei/issues/818 (#818)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0021](0021-defer-second-object-sync-source.md),
  [research #817](../research/817-source-type-admission.md)

## Context

[ADR 0021](0021-defer-second-object-sync-source.md) bound
`source_control.object_sync` to GitHub Issue and PullRequest with identity
`github:{owner}/{repo}#{number}`. Extra GitHub kinds cannot share that number
space. [Issue #817](https://github.com/Sannrox/sekai-chisei/issues/817) asked
how a later kind can be admitted without colliding with GitHub or inferring a
type from a free-form name. The research spike proved two local synthetic
kinds can keep independent refresh and tombstone identities.

## Decision

Accept additive registered descriptors. Do not replace the GitHub profile.

- GitHub Issue/PullRequest stays the code-owned catalog profile. Identity,
  discovery, and object ids are unchanged. Extra GitHub kinds remain rejected
  under the current `github:{owner}/{repo}#{number}` format.
- Family stays `source_control.object_sync`. Do not add a second adapter
  family or a connector marketplace.
- A later kind is one descriptor: registered source, one record kind, one
  schema revision, and a digest. Identity is
  `{source}:{instance}#{record_kind}/{immutable_key}`.
- Descriptor identity is immutable after the first successful put. Retire or
  disable; never reuse. Conflicting reuse and unauthorized discovery fail
  without disclosure.
- Do not infer a descriptor from display names or unregistered `type_name`
  strings.
- Schema revision is type-revision identity. A new revision is a new digest
  and a new object-id space. Rebinding the same source id across revisions is
  `type_identity_conflict`. The same source version with a different payload
  remains a retained schema-drift denial.
- Registration requires authenticated namespace administration. Inspection
  returns bounded identity fields only: no cursors, payloads, or secret-like
  text. Unknown or unadmitted descriptors cannot authorize batches.
- #818 persists the catalog on SQLite. PostgreSQL stays unavailable until a
  later parity Issue. GitHub is not rewritten as a registered descriptor in
  this ADR.

## Alternatives considered

- **Status quo (GitHub only).** Leaves #818–#824 blocked and forces a one-off
  mapper for every later kind.
- **Extra GitHub kinds on the current id.** Rejected by ADR 0021; those kinds
  do not share Issue/PR numbers.
- **Replace GitHub with the generic descriptor now.** Would migrate every
  committed GitHub identity.
- **One descriptor with many record kinds.** That exception exists only
  because GitHub Issue and PullRequest share a number space. New kinds must
  not inherit it.

## Consequences

`ApplySourceBatch` does not admit a second source until #818 registers a
descriptor. The research mapper in `sekai::source_type_descriptor` remains a
spike until that registration contract exists. Composition products still
must not assume GitLab, Jira, incident, or deployment objects can be upserted
through the GitHub identity.

#818 implements register, inspect, and retire for one admitted descriptor.
#819 may apply batches for registered types only after that contract is live.

## Validation

- GitHub Issue and PullRequest that share instance and number still map to
  one object id.
- Two synthetic kinds in `source_type_descriptor` keep distinct source ids
  and object ids, including when the immutable key is the same decimal.
- `built_in_source_adapters` still advertises only GitHub.
- `sync_github_record` still rejects non-GitHub sources and extra GitHub
  kinds.
