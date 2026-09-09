# Additive source-type admission beyond the GitHub profile

[Issue #817](https://github.com/Sannrox/sekai-chisei/issues/817) asked whether
object-sync may admit more record kinds than GitHub Issue/PullRequest without
reusing GitHub's identity space.

## Recommendation

Recommend **additive registered descriptors** with immutable namespaced keys.
Do **not** accept that contract in this issue. Do **not** supersede
[ADR 0021](../decisions/0021-defer-second-object-sync-source.md). Production
`ApplySourceBatch` remains bound to the code-owned GitHub Issue/PullRequest
digest.

A later Design Discussion, then an accepted ADR, is required before #818 may
register descriptors. Until then:

- Keep `source_control.object_sync` catalog-advertised as GitHub only.
- Reject inference from free-form record names, display titles, or unregistered
  `type_name` strings.
- Keep GitHub Issue and PullRequest on `github:{owner}/{repo}#{number}`. Extra
  GitHub kinds stay rejected under that format.
- Express any later kind as one registered descriptor: source, record kind,
  schema revision, and digest. Identity is
  `{source}:{instance}#{record_kind}/{immutable_key}`.
- Treat schema revision as type-revision identity. A new revision is a new
  digest and a new object-id space. Rebinding the same source id across
  revisions is `type_identity_conflict`. Same source version with different
  payload remains a retained schema-drift denial.

The spike lives in `sekai::source_type_descriptor`. It is not an admission
RPC, catalog profile, or second production source.

## Alternatives considered

- **Same-family extra GitHub kinds.** Cheap, and already forbidden by ADR 0021.
  Discussions and alerts do not share Issue/PR numbers. Putting them on
  `github:{owner}/{repo}#{number}` collides.
- **Infer a descriptor from the record name.** Fails closed in the spike.
  `Incident` as a title or class name is not a source type.
- **Replace GitHub with the new descriptor contract immediately.** Would force
  a migration of every committed GitHub identity. Keep GitHub as the
  code-owned profile; add descriptors beside it after an accepted ADR.
- **One descriptor with many record kinds.** That is GitHub's special case
  because Issue and PullRequest share a number space. New kinds should not
  inherit that exception.

## Compatibility

| Rule | Spike evidence |
| --- | --- |
| GitHub Issue/PR identity unchanged | `github:acme/ops#42` still maps Issue and PullRequest to one object id |
| Synthetic kinds cannot reuse that space | `synthetic.pager:acme/ops#Alert/42` is a different source id and object id |
| Two synthetic kinds are independent | pager `Alert/42` and CMDB `Service/42` refresh and tombstone separately |
| Refresh/tombstone | later source version and delete keep the same object id |
| Schema change | `v1` → `v2` changes the digest; `detect_identity_conflict` is breaking |
| Catalog | `built_in_source_adapters` still advertises only GitHub |
| Production mapper | `sync_github_record` rejects synthetic sources and foreign digests |

## Unresolved questions for Design Discussion

1. Who may register, retire, or refuse a descriptor, and whether identity is
   immutable after first commit.
2. Whether additive descriptors stay in `source_control.object_sync` or need a
   distinct family.
3. Persistence and dual-backend catalog rows for #818; this spike has none.
4. Whether GitHub is ever rewritten as a registered descriptor. Recommendation:
   not in the first accepted ADR.
5. How operators inspect unadmitted descriptors without disclosing hidden
   records or secret-bearing cursors.

#818 should implement only the descriptor contract that discussion accepts.

## Validation

```bash
cargo test --locked source_type_descriptor --offline
cargo test --locked --test source_type_descriptor_research --offline
```
