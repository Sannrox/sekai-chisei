# Governed transforms

Sekai hosts an in-process dataset transform class
([ADR 0074](decisions/0074-plane-owned-transforms.md),
[ADR 0097](decisions/0097-in-process-transform-host.md)). A JobSpec names
input and output datasets and a list of `filter` / `project` steps. A run
writes output rows, records lineage, and stores a receipt. Objects stay
Action-written.

The gRPC RPCs (`PutGovernedTransform`, `RunGovernedTransform`,
`GetGovernedTransformRun`) are `experimental`: start the plane with
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` feature. See
[rpc-maturity.md](rpc-maturity.md). `DiscoverCapabilities` reports
`sekai.transforms.projection` on the core pack; `lifecycle_state` is
`disabled` unless experimental RPCs are enabled.

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
