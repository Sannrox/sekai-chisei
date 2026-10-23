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

## Dry run

`DryRunDefinitionChangeBundle` (#1692) takes the same request, plus an
optional `bundle_digest` the regenerated bundle must still match, and runs
the backfill for every object type with a backing dataset (its object type
datasource) on a dataset branch. It needs write on the namespace and on each
dataset, like creating a branch, and is experimental like the bundle RPC.

- The branch is named `bundle-` plus the start of the bundle digest and
  forks from the dataset's latest version. The dataset itself is never
  written, and a dry-run branch is never proposed for merge: applying a
  bundle is a later, governed step.
- Copies run first, then defaults fill properties that are still empty.
  No column is dropped: a renamed source column stays beside its copy, so
  dataset redaction still finds the rows by their original fields; dropping
  it is the apply step's. Columns follow the datasource's property mapping.
- The branch is written once, from the bundle and the fork; a rerun returns
  it as it stands (including any redaction applied since), and a retry
  after a crash or a concurrent call fills it once. Delete the branch to
  dry-run against newer data.
- Each run reports the row count, the changed rows, and up to five
  before/after samples keyed by the datasource key column. Samples follow
  the dataset's bound object: a caller who may not read it under the full
  object read policy (namespace, grants, marking, security policy and
  purpose) gets counts only (`samples_withheld`). A dataset under enforced
  property grants is refused, as for transform replays.
- Copies and defaults may only write columns the dataset does not define
  (`definition_change_bundle_overwrites_column`): a changed identifier or
  field, even an empty one filled in, would let filtered redaction or
  erasure miss the row. A default for an existing property that becomes
  required is therefore not dry-run yet.
- Branch names starting with `bundle-` are reserved: `CreateDatasetBranch`
  and transform runs on a branch refuse them, so an existing one is a
  bundle's dry run.
- Any redaction or subject erasure of the dataset deletes its dry-run
  branches: their copies carry no classification of their own, so they go
  whole, and a rerun refills from the edited base.
- A rename that copies from a column classified above `public` is refused
  (`definition_change_bundle_classified_copy`): dataset redaction finds
  values by column definition, and a copied value under a new name would
  escape it.
- Object types with a backfill but no backing dataset (none registered, or
  an edits-only datasource) are listed in `unbacked_object_types`. A
  dataset that also backs another object type, in any namespace, is refused
  (`definition_change_bundle_shared_dataset`): a rename could drop a column
  the other binding reads.
- The base read, backfill and branch write share one storage transaction
  under the lock dataset redaction takes, fenced on the branch incarnation:
  a branch recreated meanwhile fails with `ABORTED` (retry).

