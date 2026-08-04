# Evaluation gate evidence

`GetEvaluationGateEvidence` is the narrow Chisei read contract for a Tenkai
release gate. It is a server-owned projection of existing `EvalSuite` and
`EvalRun` records; it does not replace the separate evaluation-plan and
manifest contracts.

The request binds the read to a suite ID, release digest, artifact digest, and
an upper timestamp bound. Chisei authenticates the caller as an authorized
evaluation reader, loads the suite and its durable run history, computes the
suite digest, and derives the expected `tenkai-gate-v1` configuration reference
from the three digests using length-delimited SHA-256 inputs. It selects the
matching run with the greatest timestamp and then run ID, provided its
timestamp is positive and no later than the requested bound.
Chisei accepts a requested bound no more than 120 seconds ahead of its server
clock: Tenkai uses a 60-second local future window, and the remaining 60
seconds is the explicit inter-host clock-skew allowance.

The response is bounded to the suite ID, the bound digests, the suite digest,
the selected run binding, the expected case IDs, and each result's case ID and
pass/fail bit. It never returns case specifications, assertions, raw result
content, scores, reasons, or caller-provided gate truth. `found` is returned
with the projection, while `suite_not_found` and `no_matching_run` are
non-error statuses. Storage, authentication, validation, and resource-limit
failures are errors so clients fail closed instead of treating an unavailable
plane as a failed or successful evaluation.

The suite digest preserves the pre-migration Tenkai binding by encoding the
same field numbers and values as the former `EvalSuite` wire message. This
allows runs written before the read-contract migration to remain selectable
without retaining the old public suite/run RPCs.

`EvalSuite` and `EvalRun` remain internal/domain persistence types for existing
evaluation producers and capability paths. The three broad public reads
`GetEvalSuite`, `GetEvalRun`, and `ListEvalRuns` are retired in favor of this
purpose-built projection.
