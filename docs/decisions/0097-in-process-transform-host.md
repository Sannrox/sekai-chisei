# ADR 0097: Sekai hosts in-process governed transform compute

- Status: accepted
- Date: 2026-10-07
- Owners: @Sannrox
- Discussion: none
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1287 (#1287)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0072](0072-in-process-function-host.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0074](0074-plane-owned-transforms.md),
  [ADR 0036](0036-open-table-projections.md)

## Context

`PutGovernedTransform` / `RunGovernedTransform` / `GetGovernedTransformRun`
existed as an experimental SQLite measurement of
`sekai.governed-transform-execution/v1` `projection`. Community PostgreSQL
fail-closed. Operators could not tell whether the plane hosted transform
compute. Issue #1287 required a usable class or an explicit non-goal.

ADR 0074 already owns transforms as a plane class that writes datasets.
This ADR names the execution host.

## Decision

1. Governed transforms are a **Sekai** class. The plane admits a content-
   addressed JobSpec, runs an in-process `projection` in the combined
   binary, writes dataset rows, and stores a run receipt with lineage.
2. Objects stay Action-written ([ADR 0073](0073-source-and-action-objects.md)).
   Functions stay the read-time host ([ADR 0072](0072-in-process-function-host.md)).
3. Both community backends persist definitions, checkpoints, and runs.
4. The engine is a later profile on the same JobSpec. This ADR does not
   pick Spark, Flink, DataFusion, or a pipeline-builder UI.
5. `sekaictl admin transform` is the mutation path. The operator console
   lists definitions and run receipts. Wire RPCs stay `experimental`
   (stable set is capped); DiscoverCapabilities reports
   `sekai.transforms.projection` as an active core class.

## Alternatives considered

- Declare hosted compute a non-goal. Rejected: the dataset surfaces and
  conformance profile already exist; #1287 option A is the product.
- Host a cluster in this process. Rejected: local-first combined binary;
  cluster submit is a later isolated-process profile after measurement.
- Promote the three RPCs to `stable` now. Rejected: the stable cap is 66.

## Consequences

Community PostgreSQL no longer fail-closes these RPCs. Incremental rebuild
and quality quarantine stay the envelope from #879/#880. A later file-backed
or BYO-engine profile must keep the same JobSpec, transaction, and receipt.

## Validation

SQLite tests `incremental_run_processes_only_new_rows`,
`quality_failure_quarantines_and_keeps_previous_output`, and
`five_transform_pipeline_is_incremental`. PostgreSQL repeats the incremental
envelope behind `SEKAI_TEST_POSTGRES_URL`. `transform_cli::dry_path_put_run_get_lists_receipt`
covers the operator dry path.
