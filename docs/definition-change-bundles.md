# Definition change bundles

`GenerateDefinitionChangeBundle` returns everything a reviewer needs for a
candidate object-type revision in one read: the revision diff, a migration
plan, a declarative backfill, and the [consumer impact](definition-consumer-impact.md)
report. It is classified `experimental` and is rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled. Generation publishes, writes, and runs nothing. See
[ADR 0125](decisions/0125-definition-change-bundles.md).

## Request

- `namespace`, `from_revision_digest` (usually the published head), and
  `to_revision_digest` (the candidate). The caller needs read access to
  both revisions, as for `CompareDefinitionRevisions`.
- `hints`, the intent the diff cannot show:
  - `renames`: `object_type`, `from_property` (removed), `to_property`
    (added).
  - `defaults`: `object_type`, `property`, and the `value` existing objects
    get for a property that is newly required.
  - `type_changes`: `object_type` and `property`.

A hint that does not match the diff, names a property twice, or names a
type change on a property the candidate does not define fails with
`INVALID_ARGUMENT`. A renamed property that becomes required needs a
default too, unless its source was already required: a copy cannot fill
objects that never had the source value.

## Migration plan

| `kind` | Automatic when | Manual `reason` otherwise |
| --- | --- | --- |
| `rename_property` | always (declared) | |
| `default_required_property` | a default hint exists | `required_property_without_default` |
| `drop_property` | never | `property_values_dropped` |
| `type_change` | never | `type_change_not_convertible` |
| `remove_object_type` | never | `object_type_removed` |

A removed property without a rename hint is a manual drop: its values are
lost on migration. Steps are sorted by object type, property, and kind.

## Backfill

`backfill_contract` is `sekai.definition-backfill/v1`. Each assignment
names an object type and target property, with `mode` `copy` (from the
`source` property) or `default` (to the `source` literal where the property
is still empty). For one property, `copy` comes before `default`. Running
the backfill is not part of this RPC.

## Digest and impact

`contract_version` is `sekai.definition-change-bundle/v1`. `bundle_digest`
covers the diff, steps, and backfill. The `impact` report is evaluated as a
direct `ReportDefinitionConsumerImpact` call by the same caller: hidden
consumers are not named, and blocking bindings are disclosed. Because it
depends on the caller, it is not part of the digest.
