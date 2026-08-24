# ADR 0023: Fence ordered source change feeds by synchronization generation

- Status: proposed
- Date: 2026-08-24
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/672
- Supersedes: none
- Superseded by: none
- Related: ADR 0020, ADR 0021, ADR 0022

## Context

ADR 0022 commits bounded source batches atomically and advances one
plane-owned opaque checkpoint only after object, audit, lineage, result, and
checkpoint writes succeed. Checkpointed snapshots reuse that contract, but an
opaque cursor alone does not let the control plane distinguish a contiguous
ordered feed from an overlapping, reordered, or missing range.

Source ordering is also capability-dependent. A connector cannot prove
completeness by inventing a counter over records it happened to observe.
Ordered consumption therefore needs an explicit source epoch, monotonic
sequence, snapshot handoff, and recovery boundary without turning object sync
into a general pipeline runtime.

## Decision

1. Version 2 source batches carry one structured delivery window. It binds the
   delivery mode, positive synchronization generation, source feed epoch,
   exclusive starting offset, inclusive ending offset, and snapshot completion
   state.
2. Change-feed records carry strictly increasing contiguous source sequences.
   The first sequence is the committed offset plus one and the final sequence
   is the proposed ending offset.
3. A snapshot opens the first generation. Its terminal committed page records
   the source-provided feed epoch and consistency-barrier offset from which
   change-feed delivery may resume.
4. The control plane owns generation and offset progress. It commits progress
   only in the same backend transaction as graph objects, object-change audit,
   source identities, lineage, record results, and the source checkpoint.
5. Exact committed replay returns the stored result without mutation. A
   different batch that overlaps or moves behind committed progress is denied.
6. Duplicate, reordered, or noncontiguous sequence metadata is contract-invalid
   and cannot mutate generation state. Overlapping ranges durably abort without
   checkpoint movement. A stateful gap whose `offset_start` is ahead of the
   plane-owned committed offset additionally marks the generation
   `RECOVERY_REQUIRED`.
7. Only a snapshot for the next generation, referencing the last committed
   cursor, may reset ordered progress after recovery is required. Old
   generation batches cannot advance the new generation.
8. The batch and record-result history is the durable ordered-feed evidence.
   Retain object-change audit for object history; do not infer feed continuity
   from audit rows that retention may purge.
9. Sources that cannot provide a stable epoch, contiguous monotonic sequence,
   and snapshot/feed consistency barrier fail explicitly. Timestamps,
   pagination positions, and locally invented counters are not substitutes.
10. `sekai.source-batch/v1` remains replay-compatible. Once a binding starts a
    version 2 generation, later version 1 batches for that binding fail closed.

## Alternatives considered

- Keep generation and offsets encoded only in the opaque cursor. Rejected
  because the control plane could accept a jump from one cursor to another as
  successful convergence.
- Persist an independent per-event ledger. Rejected because canonical batch
  transactions and record results already retain the required causal evidence.
- Treat a later snapshot as an unrelated binding. Rejected because source,
  type-revision, object, and lineage identity must survive recovery.
- Accept best-effort timestamp ordering. Rejected because duplicate timestamps,
  delayed observations, and source retention gaps would manufacture order.

## Consequences

- The public source-batch contract and both reusable databases gain additive
  generation and offset metadata.
- Existing version 1 batches and checkpoints remain readable. A version 2
  snapshot is required to establish ordered progress for an existing binding.
- SQLite and PostgreSQL must share generation transition, contiguous range,
  exact replay, gap, restart, and checkpoint conformance.
- A source that lacks an authoritative ordering capability remains usable for
  snapshots but cannot advertise ordered change-feed support.
- Rollback to a binary that cannot read version 2 state requires restoring the
  graph, audit, source transaction, generation, result, identity, lineage, and
  checkpoint tables from one consistent backup.
- This decision adds no second source family, transform language, plugin
  runtime, connector marketplace, credential store, or unrestricted
  write-back.

## Validation

- Exact duplicate, reordered, overlapping, missing-range, restart, and
  transactional-checkpoint fixtures run deterministically without external
  services.
- A missing range leaves graph state and the checkpoint unchanged and exposes
  `RECOVERY_REQUIRED`.
- A recovery snapshot opens exactly the next generation and cannot erase
  source, type-revision, object, or lineage identity.
- Version 1 canonical digest and committed replay fixtures remain unchanged
  after upgrade.
- SQLite normal CI and reusable PostgreSQL conformance exercise the same state
  transitions; unsupported source capabilities fail explicitly.
