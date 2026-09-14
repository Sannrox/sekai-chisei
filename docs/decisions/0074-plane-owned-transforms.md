# ADR 0074: Governed transforms are plane-owned and write datasets

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/908
- Issue: https://github.com/Sannrox/sekai-chisei/issues/879 (#879)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0036](0036-open-table-projections.md),
  [ADR 0037](0037-event-stream-projections.md),
  Discussion [907](https://github.com/Sannrox/sekai-chisei/discussions/907)

## Context

`sekai.governed-transform-execution/v1` already names `projection` and
`stream_projection`. Datasets accept append and query. Nothing yet runs an
incremental pipeline into a governed dataset. Issue #879 asked which engine
and table format should do that.

## Decision

1. A transform is a content-addressed, receipt-bound, authorized operation
   owned by the plane. Incremental dataset materialization is a missing
   *class* of that profile, not a missing product.
2. Transform outputs are datasets or pinned snapshots. They do not mint
   type-revision object identity (Discussion 907).
3. Lineage and a receipt are required on every run. Secrets do not live in
   transform documents.
4. This ADR does not pick an engine, table format, or cluster. #880 stays
   implementation-blocked until incremental rebuild time and memory on the
   published fixture are measured.

## Alternatives considered

- Defer the product and accept only external outputs. Rejected: the
  conformance profile and dataset surfaces already exist.
- Pick an engine now. Rejected: no envelope numbers exist.

## Consequences

Host-side transform *definitions* and receipts can be specified without an
engine. #880 implements execution only after measurements. Object identity
stays on sync and Actions.

## Validation

Identity tests must keep transform output out of type-revision object ids. A
later spike must publish incremental rebuild time, memory, a pinned format
version and fallback, and receipt/lineage shape.
