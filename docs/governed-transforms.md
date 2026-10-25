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

Every run receipt pins the version each input dataset was read at
(`input_versions`, dataset id to version id, #1794). The pins are read in the
run's own transaction, so the rows the run read are exactly those versions.
They are part of the receipt signed into the namespace's receipt chain and
verify offline with it. Two runs with the same pins read identical inputs.
Replaying a transform pinned to a receipt's `input_versions` reads those
versions as they were, even after the inputs moved on, and reproduces the
receipt's output digest. Receipts from before the pins carry none and still
read. An input with no version and no rows yet pins as `unversioned`, which a
replay reads as no rows. A populated input with no version history is
snapshotted in the run transaction and pinned to that version; an incremental
run rebuilds from all rows in that case so the snapshot stays inside the load
budget. A skipped run reads nothing and carries no pins. A quarantined run
does not snapshot.

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
`GetTransformOutputState`, `CancelGovernedTransformRun`,
`ShadowGovernedTransform`) are `experimental`:
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

## Shadow runs

Experimental `ShadowGovernedTransform` tries a candidate revision beside
the active one on the inputs the active revision actually ran on (#1795).
For each named run of the active revision, or its newest runs (10 by
default, at most 25, among the transform's newest 500 runs), it replays the candidate pinned to that run's
`input_versions` on a fresh `replay-` branch of the output
([ADR 0120](decisions/0120-transform-replays.md)) and diffs the result with
the output version the run left. A run that writes its output records that
version beside its finish, in its own transaction; runs from before the
record, or whose version no longer has the run's `output_digest`, are
reported skipped rather than compared. An input the candidate
adds reads its version as of the run's admission. The
report lists, per run, rows compared, matched, added, removed and changed
with the changed keys, and sums them into a match rate with up to 10 sample
rows. Cost and latency compare the active run's measured compute and
admission-to-finish time with the candidate replay's time. Runs of another
revision, without pinned inputs, quarantined or not finished are skipped
with a reason, as is a run whose replay fails; earlier replays stay
committed and charged.

A shadow writes only replay branches and replay records. It never writes
the output dataset, objects, checkpoints or run history, and starts no
Actions or downstream runs. Nothing runs on a schedule or trigger: a shadow
runs when it is requested. It is admitted like a replay, under one
transform quota admission. The report is returned, not stored; each
replay's record is stored, and its branch is deleted when it is no longer
needed.

## Measured usage

A finished run reads back with `finished_at_ms` and `compute_seconds`
(`TransformRun` fields 26 and 27, #1651), so an extension can record usage
once per run id with the transform definition as a label.

- **In-process runs:** compute is measured from the start of compute to the
  moment the run's own output is written. Downstream runs it triggers in
  the same transaction are measured as runs of their own, not counted here.
- **Isolated-process runs:** compute is measured from the latest claim to
  write-back.
- **Never computed:** a failed, refused or cancelled run has
  `finished_at_ms` and no `compute_seconds`.
- **Unfinished:** a pending or claimed run has neither.

The values live beside the run, written in the same transaction, so the
run's receipts are unchanged. Transforms call no model, so runs carry no
token counts.

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
