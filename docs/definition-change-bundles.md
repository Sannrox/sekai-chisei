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
  written, and `ProposeDatasetBranchMerge` and `MergeDatasetBranch` refuse
  bundle branches: only [apply](#apply) merges one, through the approved
  proposal.
- Copies run first, then defaults fill properties that are still empty.
  No column is dropped: a renamed source column stays beside its copy, so
  dataset redaction still finds the rows by their original fields. Apply
  keeps it too. Columns follow the datasource's property mapping.
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

## Apply

`ApplyDefinitionChangeBundle` (#1693) applies the bundle of an approved
proposal as one governed change. It takes the `proposal_id`, the `hints`, the
`bundle_digest` the reviewers approved, and the `expected_published_digest`
the final publish compare-and-swaps against. It is experimental like the
other bundle RPCs, and the caller needs what `MergeDefinitionProposal` needs:
not the proposal's creator (operator identities excepted), read on both
revisions, write on the changed members, and a still-current approval. The
proposal must carry the bundle's digest as its `migration_plan_digest`, set
when it was created and so covered by the approval: the bundle is
regenerated from the proposal's pinned base and candidate with the request's
`hints` and must have that digest
(`definition_bundle_apply_unapproved_bundle`), so an applier cannot change
the approved renames or defaults. A bundle with manual migration steps is
refused.

Apply keeps a durable record (`sekai.definition-bundle-apply/v1`, one per
proposal) of ordered steps:

1. For each dataset backing an object type the bundle backfills:
   `backfill:<dataset>` fills the bundle branch as the dry run does,
   replacing a branch this apply did not fill (a dry run's, which may predate
   a datasource change), and its own fill is written once; `verify:<dataset>` checks the backfill
   would change nothing more on the branch; `merge:<dataset>` opens a
   dataset merge proposal (proposer `definition-proposal:<id>`, so any
   applier keeps the dataset's two-person rule) and merges it as one new
   dataset version, then defines the target columns the dataset does not
   define yet (`public`: copies come only from public columns, defaults are
   approved literals), so a datasource mapping a property to them stays
   valid; a later refill may write those columns again, but only while they
   are still `public` (a column reclassified since, perhaps redacted, is
   refused like any defined column). A recorded dataset
   proposal that can no longer merge (closed, its branch gone or changed)
   starts the dataset over. The backfill records the branch incarnation it filled;
   verify and merge refuse another (`definition_bundle_apply_branch_changed`),
   and the dataset proposal captures the branch rows only while it is still
   that incarnation, in the same transaction.
   The proposal must find the version the branch forked from as its parent:
   when the dataset was written since the backfill, the step fails
   (`definition_bundle_apply_stale_base`), the derived branch is dropped, and
   the dataset's steps start over, so the next apply refills from the new
   version. The merge checks the copy and overwrite rules again on the
   column definitions it reads under its dataset lock, so a source
   reclassified since a dry run never reaches live data under a new name.
2. `publish` merges the definition proposal, last, with an idempotency key
   derived from the record. A proposal already merged (by an earlier
   attempt or by hand) completes the step. Every merged dataset must still
   be at the version its merge wrote, checked in the publish transaction
   itself (under the store's write lock on SQLite, each dataset's rows lock
   on PostgreSQL): a dataset written since fails the step
   (`definition_bundle_apply_data_moved`) and starts over, so the next apply
   backfills the new rows before publishing. Every migrated object type's
   datasource must still have the configuration the steps used, checked in
   the same transaction (`definition_bundle_apply_datasource_changed`); on
   PostgreSQL registration and the publish share a lock per object type, so
   a registration (even of a type with no binding yet) waits for the publish.

The steps follow the datasets backing the bundle at each call: a type
rebound to another dataset, newly backed, or no longer backed since the last
attempt gets steps for its dataset now (completed steps of datasets still
backing are kept). The record also keeps, for every object type the bundle
backfills, a digest of its datasource configuration (dataset, key column,
property mapping, hidden column; empty when unbacked): when it changed
between attempts, the dataset's bundle branch is dropped and its steps start
over, and the publish requires every digest unchanged. A step's effect (the branch incarnation it
filled, the dataset proposal it opened) is kept apart from its error text, so
a retry after an ambiguous commit replays that effect instead of making a
second one.

A step is recorded done only after its effect, and each effect is idempotent
(the branch is written once, the merge step records its dataset proposal
before merging and a merged proposal replays, the publish replays by key),
so calling apply again after a crash continues from the first step not done
and applies none twice. A failed step leaves the published revision
unchanged and the record `failed` with `failed_step` and `error`; calling
apply again retries from that step. A completed record is returned as is,
to a caller who may read both revisions.
Every record write is a compare-and-swap on its revision; a concurrent
applier fails with `ABORTED` (retry). `GetDefinitionBundleApply` returns the
record to a caller who may read both revisions.

