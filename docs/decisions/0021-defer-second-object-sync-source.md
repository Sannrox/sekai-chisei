# ADR 0021: Defer a second object-sync source until GitHub Issue/PR admission is live

- Status: accepted
- Date: 2026-08-22
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/657
- Supersedes: none
- Superseded by: none

## Context

[ADR 0020](0020-shared-type-revisions-and-object-sync.md) named
`source_control.object_sync` as the first inbound family and limited it to
GitHub Issue and PullRequest records. Identity is
`github:{owner}/{repo}#{number}`. Object id is `type_digest` plus that source
id. Refresh, tombstone, and type-revision conflict are explicit. Evidence
adapters stay observations.

[Issue #657](https://github.com/Sannrox/sekai-chisei/issues/657) asked which
named system of record should be next, and whether streaming is only transport
into the same identity contract. The live dogfood workflow already uses GitHub
Issue and PullRequest as planning and implementation truth. No other workflow
in this repository has both a stable external id and an admitted type
revision. `sync_github_record` is transport-agnostic; the catalog already lists
webhook delivery, but there is no reference adapter that feeds the mapper.

## Decision

Do not add a second object-sync source or adapter family.

- Keep `source_control.object_sync` bound to GitHub Issue and PullRequest.
- Treat webhook, document, and poll feeds as transport into
  `sync_github_record`. They must not mint a second source id, object id, or
  family.
- Reject additional GitHub record kinds under the current source-id format.
  Issues and pull requests share GitHub's number space, so `source_id` omits
  `type_name`. Discussions, releases, deployments, and check runs do not share
  that space; admitting them as `github:{owner}/{repo}#{number}` would collide.
- Keep `source_control.check_run` and other evidence adapters as observations.
  Promoting a check run into object sync would create a second identity for the
  same verification signal.
- Do not invent a GitLab, ticket, incident, or deployment family until a live
  tenant workflow presents a stable source id and an admitted type revision
  that can refresh and tombstone without a second object identity.

A later source requires a new bounded decision. It must name one system of
record, an identity format that cannot collide with GitHub Issue/PR numbers,
and refresh/tombstone rules. Completing the first source's webhook or document
feed is not a second source.

## Alternatives considered

- **Same-family additional GitHub kinds:** looks cheap, but Discussion,
  Release, Deployment, and similar records use different number or id spaces.
  They need a new source-id rule, not a new `type_name` on the current format.
- **Another Git host in `source_control.object_sync`:** would reuse the family,
  but this tenant has no live GitLab or other-host workflow with an admitted
  type revision.
- **New operational family (tickets, incidents, deployments):** matches VISION
  domain-in-adapters language, but the incident example is in-graph teaching
  material, not a system of record. A new family before the first source has a
  live admission path recreates the connector marketplace ADR 0020 rejected.
- **Streaming first on GitHub identity:** correctly treats push as transport,
  and the catalog already names webhook delivery. It does not name a second
  source. The follow-up is to feed the existing mapper, not to change identity.

## Consequences

#657 closes with an explicit no-second-source result. #659 treats that
result as the delivered dependency and closes with no persisted derived
facts: there is no second inbound source to bind derived-fact admission to.

Composition products must not assume GitLab, Jira, incident, or deployment
objects can be upserted through `source_control.object_sync`. Check-run
webhooks remain evidence. A follow-up feature may add the missing GitHub
Issue/PR reference adapter that normalizes one observation into `SourceRecord`
and calls `sync_github_record`. That adapter must reuse the current identity
contract.

No schema migration, public RPC, or persistence change is required.

## Validation

- `sync_github_record` continues to reject non-GitHub sources and any
  `type_name` other than `Issue` or `PullRequest`.
- Issue and PullRequest observations that share instance and number map to the
  same object id.
- [Inbound object sync](../object-sync.md) states the no-second-source rule and
  that streaming is transport.
- A future second source must add a new ADR before changing `source_id` shape
  or adding a family.
