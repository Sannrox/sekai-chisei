# Governed transforms

Sekai hosts an in-process dataset transform class
([ADR 0074](decisions/0074-plane-owned-transforms.md),
[ADR 0097](decisions/0097-in-process-transform-host.md),
[ADR 0101](decisions/0101-analytical-transform-profile.md),
[ADR 0102](decisions/0102-isolated-process-transform-profile.md)). A JobSpec
names input and output datasets and a list of `filter` / `project` steps, the
analytical SQL profile with one or more named inputs, or an
`isolated_process` profile that admits work for an external runner. In-process
runs write output rows, record lineage, and store a receipt. Isolated-process
runs return a pending receipt; a claimed worker streams the admitted input
snapshot and writes the output, receipt, and lineage in one fenced
transaction against the admitted JobSpec. Claim, heartbeat, input, and
write-back RPCs require credential admin. Workers pin
`sekai-client::claim` rather than copying those RPCs. Objects stay
Action-written.

The gRPC RPCs (`PutGovernedTransform`, `RunGovernedTransform`,
`GetGovernedTransformRun`, `ListGovernedTransforms`,
`ListGovernedTransformRuns`, `ListClaimableTransformWork`,
`ClaimTransformWork`, `HeartbeatTransformClaim`, `ReadTransformRunInputs`,
`WriteTransformRunResult`) are `experimental`: start the plane with
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` feature. See
[rpc-maturity.md](rpc-maturity.md). `DiscoverCapabilities` reports
`sekai.transforms.projection`, `sekai.transforms.analytical`, and
`sekai.transforms.isolated_process` on the core pack; `lifecycle_state` is
`disabled` unless experimental RPCs are enabled.

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
