# Epistemic Kioku context evaluation

The `chisei::epistemic_eval` module provides a report-only comparison between
the claim-only Kioku context and the epistemically framed context. It does not
change the context-expansion gate and it never enables a production default.

## Matched arms

Callers persist two immutable `chisei::eval::Run` values through the existing
`EvalStore` path, prepare one `EpistemicCaseAuthority` map per arm from the
canonical operation receipts and Kioku outcome records, then call
`compare_epistemic_runs`. The baseline run must use
the `claim_only` context variant and the candidate must use
`epistemic_framed`. Their `config_ref` values are retained in the report as the
exact arm identities. The helper also requires:

- the same suite and case IDs;
- all six fixture kinds: supporting-only, contested, insufficient, stale,
  irrelevant, and high-confidence-wrong;
- equal eligible-memory-set, classification-ceiling, source-content,
  calibration-target, and token-capacity bindings for every case; and
- normalized case evidence only. Unknown JSON fields, non-empty free-form
  reasons, raw claim/evidence text, prompts, and provider output are rejected.

Each arm's `receipt_digest` and `outcome_digest` bind its observation to the
existing canonical operation receipt and Kioku outcome evidence. They are
retained separately because the arms are expected to produce different
outcomes. Only those digests and bounded counters are retained in the eval
run, so a report can be reconstructed without retaining raw provider output.
The comparison recomputes both digests from the payload-free authority
projections and checks every task, claim, contradiction, confidence, latency,
and token field against those projections; a syntactically valid digest paired
with different measurements is rejected.

## Metrics and gate

The report includes task success, unsupported-claim rate, contradiction
handling, calibration error, latency, and input/output token usage. Rates are
stored as basis points and confidence/calibration values as integer
micro-units. `EpistemicRegressionPolicy` is explicit and is part of the report;
its default is strict (no required metric regression). A caller may widen a
bound only as part of a documented evaluation plan.

The helper first evaluates the existing generic `EvalStore::compare_runs`
pass-rate gate, then applies the epistemic metric gate. A failed gate is
fail-closed and must keep context expansion disabled. Even a passing report is
evidence for an operator decision, not an automatic rollout or a universal
claim about every domain.

Default CI uses deterministic fixture runs and does not require provider
credentials. Stochastic provider evaluations remain governed by the separate
fixed-trial, variance, egress, budget, and retention contracts documented in
[Evaluation execution](evaluation-execution.md).
