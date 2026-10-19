# Governed transforms

Sekai hosts an in-process dataset transform class
([ADR 0074](decisions/0074-plane-owned-transforms.md),
[ADR 0097](decisions/0097-in-process-transform-host.md),
[ADR 0101](decisions/0101-analytical-transform-profile.md),
[ADR 0102](decisions/0102-isolated-process-transform-profile.md),
[ADR 0103](decisions/0103-transform-schedule-and-dependency-graph.md),
[ADR 0105](decisions/0105-partitioned-transform-io.md)). A JobSpec
names input and output datasets and a list of `filter` / `project` steps, the
analytical SQL profile with one or more named inputs, or an
`isolated_process` profile that admits work for an external runner. In-process
runs write output rows, record lineage, and store a receipt. Isolated-process
runs return a pending receipt; a claimed worker streams the admitted input
snapshot and writes the output, receipt, and lineage in one fenced
transaction against the admitted JobSpec. Claim, heartbeat, input, and
write-back, and streaming object-apply RPCs require credential admin.
Workers pin `sekai-client::claim` rather than copying those RPCs. Objects
stay Action-written. `ApplyStreamingTransformBatch` commits object edits
and the input checkpoint in one transaction; replay of the same
`(run_id, checkpoint)` returns the original receipt. Checkpoint identity is
opaque and is stored without trimming. Admitted `markings_out` is the
classification floor on every output object; a stricter existing marking is
kept. Updates still run declassify the same as guarded object writes.

A dataset may declare ordered `partition_keys`. Empty keys keep the
whole-dataset `sha256-sum-v1:` digest. Partitioned datasets use
`sha256-partitions-v1:` over a sorted map of partition identity to that
partition's `sha256-sum-v1:` digest; the prefixes do not fold into each
other. Isolated `ReadTransformRunInputs` stays row maps on gRPC. A page may
name a partition and a byte cap; an unset selector reads every partition and
the empty string selects the empty identity. Resume is `(partition_key, alias,
after_row_id)`. Isolated write-back may replace named output partitions in
the same transaction as the receipt. Incremental in-process projection
appends into partitions whose new rows changed; untouched output partitions
stay on disk and historical output row IDs stay stable. Get/List/run/write-back
replace partition identities and member digests with `redacted` unless the
caller can read the datasets bound by the run's definition. Arrow/Parquet remains out of scope (#879).

The gRPC RPCs (`PutGovernedTransform`, `RunGovernedTransform`,
`GetGovernedTransformRun`, `ListGovernedTransforms`,
`ListGovernedTransformRuns`, `ListClaimableTransformWork`,
`ClaimTransformWork`, `HeartbeatTransformClaim`, `ReadTransformRunInputs`,
`WriteTransformRunResult`, `ApplyStreamingTransformBatch`, `TickGovernedTransforms`,
`GetTransformOutputState`, `CancelGovernedTransformRun`) are `experimental`:
start the plane with `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs`
feature. See [rpc-maturity.md](rpc-maturity.md). `DiscoverCapabilities`
reports `sekai.transforms.projection`, `sekai.transforms.analytical`,
`sekai.transforms.isolated_process`, and `sekai.transforms.scheduler` on the
core pack; `lifecycle_state` is `disabled` unless experimental RPCs are
enabled. Enterprise-scoped sessions may `PutGovernedTransform` with
namespace Write and read access to the bound datasets; community credentials
still require credential administration. `RunGovernedTransform` stays
unadmitted for scoped sessions.

A definition may carry a `schedule` interval and an `on_input_commit` trigger.
The plane admits due work on an idempotent replica tick. An upstream commit
or `ApplySourceBatch` coalesces into one downstream run inside the debounce
window. Cycles are refused at Put. Failed upstream runs mark downstream
outputs `blocked`; a later success unblocks them. Cancelling a run skips
not-yet-started downstream work and records that on the receipts.

The analytical profile runs SQL in a private in-memory SQLite connection
(bundled rusqlite). Default bounds: 64 MiB and 5 seconds. Over-budget runs
fail with `transform_budget_time` or `transform_budget_memory` and leave the
previous output readable. Example: `cargo run --example analytical_transform`.

## Operator path

```bash
sekaictl admin transform put --file transform.json
sekaictl admin transform run --namespace ops --transform-id t1
sekaictl admin transform run --namespace ops --transform-id t1 --incremental
sekaictl admin transform get --run-id <run>
sekaictl admin transform list --namespace ops
```

Console: `/console/n/{namespace}/transforms` lists definitions and run
receipts. Open a run id for the receipt.

Quality failures quarantine the run and leave the previous output queryable.

Both community backends persist definitions, checkpoints, and runs.

A cluster engine (Spark or similar) is a later JobSpec profile, not this
host.
