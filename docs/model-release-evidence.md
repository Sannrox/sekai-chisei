# Model-release evidence

Contract: `chisei.model-release-evidence/v1` (ADR 0107, #1396).

Chisei verifies Tenkai-signed `tenkai.model_runtime_evidence.v1` before an
opt-in customer-hosted route is admitted, and signs
`chisei.model_evaluation_evidence.v1` from pinned eval comparisons. It does
not run canaries. Default routes stay unchanged until a hosted profile sets
`require_runtime_evidence` and binds provider, model, profile version,
artifact digest, and endpoint.

## Operator surface

- `sekaictl admin model-release-evidence trust-set|trust-get`
- `sekaictl admin model-release-evidence ingest|get`
- `sekaictl admin model-release-evidence export` (`EvalStore::compare_runs`)
- `sekaictl admin model-release-evidence feedback`
- Experimental RPCs `PutModelReleaseTrust`, `PutModelRuntimeEvidence`,
  `GetModelRuntimeEvidence`, `ExportModelEvaluationEvidence`, and
  `PutModelReleaseFeedback` (enable `SEKAI_EXPERIMENTAL_RPCS=1` or the
  `experimental-rpcs` feature)

Install trust roots, push signed runtime JSON, then opt the hosted profile
in. Export uses `SEKAI_MODEL_EVALUATION_SIGNING_KEY` (32-byte hex). Refusals
are `model_release.missing`, `model_release.stale`, or `model_release.invalid`.
