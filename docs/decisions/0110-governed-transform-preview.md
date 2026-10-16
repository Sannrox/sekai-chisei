# ADR 0110: Preview a governed transform without committing governed data

- Status: accepted
- Date: 2026-10-15
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1532
- Issue: #1532
- Supersedes: none
- Superseded by: none
- Related: [ADR 0101](0101-analytical-transform-profile.md),
  [ADR 0102](0102-isolated-process-transform-profile.md),
  [ADR 0074](0074-plane-owned-transforms.md),
  [ADR 0071](0071-rpc-maturity.md)

## Context

`PutGovernedTransform` then `RunGovernedTransform` is the only way to try a
definition. Every run commits an output dataset version, a receipt, and
lineage. Authors need to try an unsaved definition against a bounded sample
without changing governed data. A scratch dataset still commits. Client-side
SQL diverges from the plane engine and skips read policy.

## Decision

1. **Unsaved definition in, result out.** Experimental `PreviewGovernedTransform`
   accepts a full `GovernedTransform` that has not been put. It validates the
   definition the same way Put does, then runs it against a bounded sample of
   each declared input. The caller holds the draft.
2. **Never committed.** A preview creates no dataset version, no run receipt
   in governed run history, no lineage, and no checkpoint. The response
   carries result rows, the output schema, rows read per input, errors, and a
   preview identity that is not a run id.
3. **Read policy on the sample.** Sample rows are read with the caller's
   authority through the same policy entry point as dataset reads. A caller
   who cannot read an input gets that same unavailable answer. Preview output
   never includes a column the caller cannot read.
4. **Same engines, sampled inputs.** `analytical` previews run in-process
   SQLite SQL (ADR 0101) on the sample. `isolated_process` previews reuse the
   dedicated transform claim queue (ADR 0102) with a `preview` mark. A worker
   claims that work, reads only sampled inputs, and returns rows through a
   preview write-back that the plane does not commit. The first Preview
   response carries the preview identity immediately. Calling Preview again
   with that `preview_id` returns the stored rows after write-back.
   `GetGovernedTransformRun` stays unavailable for a preview identity. A
   stale fence returns nothing. A separate preview queue is rejected: it
   would duplicate claim, lease, and fence machinery.
5. **Plane maxima.** Time and memory budgets stay the ADR 0101 / JobSpec
   envelope and may only be lowered. The sample row cap defaults to 256 rows
   per input and cannot exceed the plane maximum of 1024. Over-budget
   previews fail with the existing `transform_budget_time` and
   `transform_budget_memory` codes; an exceeded row cap is
   `transform_preview_row_cap`.
6. **Experimental.** `DiscoverCapabilities` reports
   `sekai.transforms.preview` on the core pack, disabled unless experimental
   RPCs are enabled.

## Alternatives considered

- Run the real transform into a scratch dataset and delete it. Rejected:
  commits governed data and leaves receipts.
- Run the SQL in the client. Rejected: a different engine and no read policy
  on the sample.
- A second, lower-priority claim queue for isolated previews. Rejected:
  duplicates ADR 0102 claim/lease/fence state. A `preview` mark on the
  existing queue is enough to refuse commit.

## Consequences

Authors can iterate on an unsaved definition without publishing. Console
preview panels consume this RPC. Projection, analytical, and isolated-process
Put/Run paths stay unchanged. Preview identity must never be treated as a
run id.

## Validation

Tests on both community backends: a preview returns the expected rows and
schema and leaves dataset versions, run history, lineage, and checkpoints
unchanged. A caller without a marking, property grant, or row access to an
input gets no rows or columns they could not read. Over-budget previews fail
with the existing budget errors; the row cap is enforced. An isolated-process
preview is claimed, read, and returned without a committed output; a stale
fence returns nothing.

## Amendment 2026-10-16

#1553 admits enterprise-scoped contexts (tenant identity assertions) to
`PreviewGovernedTransform`, `ListGovernedTransforms`,
`ListGovernedTransformRuns` and `GetGovernedTransformRun` on
`sekai.SekaiService`. Each checks namespace read access and, like preview, the
caller's tenant context; another tenant's run reads as missing. Preview reads
its samples under the caller's policy, so a scoped session needs only
`sekai.read`. `PutGovernedTransform` and `RunGovernedTransform` stay
unadmitted for scoped contexts: Put requires credential administration, and
admitting it needs its own decision.
