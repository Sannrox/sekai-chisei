# Source quarantine inspect and repair preview

Issue: [#820](https://github.com/Sannrox/sekai-chisei/issues/820)  
Decision: [ADR 0061](decisions/0061-quarantine-repair-preview.md)  
Discussion: [#852](https://github.com/Sannrox/sekai-chisei/discussions/852)

Inspect the latest quarantined source batch, preview a correction against the
live checkpoint and type revision, and re-admit only through existing
`ApplySourceBatch`. Inspection and preview do not write, advance a checkpoint,
or grant apply authority.

```text
sekaictl admin sync inspect-quarantine --namespace acme --source-instance owner/repo \
  --type-digest sha256:<github-object-sync-type-digest>
sekaictl admin sync preview-batch --batch ./repair.json
sekaictl admin sync apply-batch --batch ./repair.json
```

Inspect exposes reason codes, outcomes, and source identities. It never returns
raw secret-bearing cursors, payload properties, or hidden records. Hidden and
unknown sources share one unavailable result.

Preview binds the observation to the live `committed_batch_digest`, live
`type_digest`, and the proposed `batch_digest`. A mismatched cursor or type
revision is `stale`. A preview is not a permit. `ApplySourceBatch` still owns
the fence: a stale correction cannot overwrite a newer checkpoint.

Exact replay of the original quarantined batch remains the stored quarantine.
A correction uses a new idempotency key and records a new attributable
outcome. SQLite apply plus the shared projector cover persistence-backed
reports. Historical quarantine search is out of scope.
