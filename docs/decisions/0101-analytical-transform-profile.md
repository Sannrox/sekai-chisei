# ADR 0101: Analytical governed-transform profile uses in-process SQLite SQL

- Status: accepted
- Date: 2026-10-12
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1385
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1385 (#1385)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0097](0097-in-process-transform-host.md),
  [ADR 0074](0074-plane-owned-transforms.md),
  [ADR 0102](0102-isolated-process-transform-profile.md)

## Context

[ADR 0097](0097-in-process-transform-host.md) hosts governed transforms in
process and leaves engine choice as a later JobSpec profile. The `projection`
host only filters and projects one input dataset. Issue #1385 needs join,
group/aggregate, derived columns, more than one input, bounded resources, and
a list read over gRPC.

DuckDB and DataFusion were the named candidates. The plane already embeds
SQLite for community storage.

## Decision

1. The analytical profile is in-process SQLite SQL on a private memory
   connection. Version pinning is the bundled rusqlite SQLite already in this
   binary. Do not add DuckDB or DataFusion for this profile.
2. The engine registers only caller-supplied governed dataset rows as tables.
   It accepts a single `SELECT` or `WITH` statement and rejects `ATTACH`,
   `LOAD`, DDL, and DML. SQL does not open caller files or the network.
   Sorter spill uses engine-owned SQLite temp files, not caller paths.
3. Default resource envelope: 64 MiB and 5 seconds (interrupt watchdog).
   Memory is a thread-local SQLite allocator cap for the engine thread, plus
   `PRAGMA cache_size` and `max_page_count` on main and temp, with
   `temp_store=FILE` so sorter PMA is capped by cache_size. A JobSpec may
   lower those bounds. Over-budget runs fail with `transform_budget_time` or
   `transform_budget_memory` and leave the previous output readable.
4. Existing `projection` definitions keep their digests. Analytical extras
   (`inputs`, `sql`, limits) participate in the digest only when the profile
   is present.
5. `ListGovernedTransforms` and `ListGovernedTransformRuns` are experimental
   namespace-authorized reads. Put/Run stay credential-admin.

## Alternatives considered

- DataFusion. Rejected: large crate and compile cost for SQL the plane already
  runs in SQLite.
- DuckDB. Rejected: a second bundled native library next to rusqlite, without
  a measured need on this host. Isolated-process runners may still pick it.
- Hand-grown join/aggregate steps. Rejected: every operator becomes custom
  code; SQL is the JobSpec surface #1385 asked for.

## Consequences

Binary size stays the rusqlite envelope. Analytical SQL is SQLite dialect,
not DuckDB. A later isolated-process profile may pin a different engine
without changing this JobSpec.

## Validation

SQLite tests `incremental_run_processes_only_new_rows_on_analytical_profile`,
`quality_failure_quarantines_and_keeps_previous_output_on_analytical_profile`,
`five_transform_pipeline_is_incremental_on_analytical_profile`,
`analytical_join_aggregate_writes_receipt`, and
`over_budget_analytical_query_keeps_previous_output`. Example
`analytical_transform` prints a join+aggregate receipt. List RPCs deny
unauthenticated and non-member callers.
