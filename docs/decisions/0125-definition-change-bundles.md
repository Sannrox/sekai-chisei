# ADR 0125: Definition change bundles

- Status: accepted
- Date: 2026-10-23
- Issue: #1691

## Context

A schema change to an object type takes several separate steps: compare
revisions, plan the data migration, write a backfill, and check consumer
impact. Reviewers approve a definition change without seeing the migration
that goes with it. Object-type definitions list property names without
types, so a rename, a value for a new required property, or a type change
cannot be read from the diff alone.

## Decision

1. **One read-only bundle.** `GenerateDefinitionChangeBundle` takes two
   revisions of a namespace and author hints, and returns the revision
   diff, a migration plan, a declarative backfill, and the consumer impact
   report. It publishes, writes, and runs nothing.
2. **Hints declare what the diff cannot show.** A rename names a removed
   and an added property of the same object type. A default names a
   property that is newly required. A type change names a property the
   candidate defines. A hint that does not match the revisions, or names
   the same property twice, is refused, not ignored. A rename only fills a
   newly required target when its source was already required; otherwise
   the target needs a default as well.
3. **No guesses.** Anything hints do not cover becomes a manual step with a
   reason code: `required_property_without_default`,
   `property_values_dropped`, `type_change_not_convertible`, and
   `object_type_removed`. A type change is always manual, because no
   conversion is declared.
4. **Format.** The bundle is `sekai.definition-change-bundle/v1`: the diff,
   steps sorted by object type, property, and kind, and a
   `sekai.definition-backfill/v1` backfill of `copy` (from a source
   property) and `default` (a literal, for values still empty) assignments,
   with copies first. `bundle_digest` is a
   SHA-256 over the canonical JSON of the bundle. The impact report depends
   on the caller, so it sits next to the bundle, outside the digest.
5. **Impact follows the consumer impact rules.** The report runs under the
   caller's own request, so revision access and binding visibility match a
   direct `ReportDefinitionConsumerImpact` call. Hidden consumers are not
   named. Blocking bindings are disclosed as that RPC discloses them.
6. **Apply is a later layer, recorded here.** Applying a bundle will be a
   durable apply record keyed by `bundle_digest`. It is fenced on the
   published head the bundle was generated from, records progress per step,
   and is resumable by any instance after a crash. A step that already
   finished is not run again. Manual steps must be acknowledged on the
   record before apply continues past them.

7. **Dry runs use dataset branches** (#1692). The backfill runs on a branch
   of each backing dataset, named for the bundle digest and forked from the
   latest version, never on the dataset, and written once; reruns return
   it. A backfill writes only columns the dataset does not define and copies
   only from public columns. Dry-run branches are never proposed for
   merge, and redaction or erasure of the dataset deletes them.
   Samples follow the dataset's bound object read policy.

## Consequences

- Reviewers see the diff, the data plan, and the impact in one response.
- The plan is only as complete as the hints. Undeclared intent shows up as
  manual steps instead of hidden data loss.
- The RPC is experimental and needs `SEKAI_EXPERIMENTAL_RPCS=1` or the
  `experimental-rpcs` build feature.

## Rejected alternatives

- Inferring renames from similar names: a wrong guess silently moves data.
- Typed conversions in this layer: definitions carry no property types.
- Storing generated bundles: generation stays a pure read, and the digest
  identifies a bundle for the apply record.

Amended by #1693: an approved proposal's bundle is applied by
`ApplyDefinitionChangeBundle` as a durable, resumable record of ordered,
idempotent steps (backfill, verify and merge per backing dataset, then
publish last), so a failed or interrupted apply never leaves a published
revision ahead of its data. Cross-store two-phase commit and publishing
first with a rollback were rejected. See [definition-change-bundles.md](../definition-change-bundles.md#apply).

