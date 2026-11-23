# ADR 0154: Evaluators report several metrics; plans own each objective and threshold

- Status: accepted
- Date: 2026-11-23
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2629 (#2629)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0011](0011-separate-invariant-facts-and-evaluation-plans.md),
  [ADR 0012](0012-bound-stochastic-evaluation-by-situation.md)

## Context

ADR 0011 makes plans the owner of situation-specific policy, and evaluators
the owner of measurement. A deterministic evaluator returns one `status`,
one `reason_code`, and an opaque `result`. An evaluator that measures several
things at once, such as accuracy and latency, has two options today:

- fold every measurement into one pass or fail inside its own code;
- run as several plan nodes over the same input.

Either way, the threshold lives in evaluator code and not in the plan.

## Decision

- **Result schema.** Add the closed result schema
  `chisei.evaluation-metrics/v1`: a list of 1 to 32 `{name, kind, value}`
  entries. `kind` is `bool` or `integer_micros`. Integer micros keep judging
  independent of floating point.
- **Declaration.** An evaluator definition declares the metrics it reports in
  `declared_metrics`, and lists the schema in `supported_result_schemas`. Each
  one requires the other. Stochastic definitions cannot declare metrics.
- **Objectives.** A plan node binds at most one objective per declared metric
  in `metric_objectives`:
  - `equals` with an expected value, for `bool` metrics;
  - `maximize` or `minimize` with an optional `threshold_micros`, for
    `integer_micros` metrics.

  Thresholds are inclusive: `maximize` passes at `value >= threshold`, and
  `minimize` at `value <= threshold`. Publication refuses an objective on an
  undeclared metric, or one whose kind does not fit the metric.
- **Judging.** The resolved manifest freezes the declarations and objectives.
  The executor derives the step status from them:
  - `fail/metric_objective_unmet` when any bound objective is unmet;
  - `pass/metric_objectives_met` otherwise;
  - `unknown` from the evaluator passes through, because it means the
    evaluator could not measure;
  - a result that breaks the schema or the declaration is
    `error/invalid_result`.
- **Receipt.** The step receipt records `metric_verdicts`: each reported
  metric's name, kind, value, frozen objective, and verdict. The verdict is
  `met`, `unmet`, or `advisory`. A metric is advisory when no objective is
  bound to it, or when its objective has no threshold. The verdicts are part
  of the step receipt digest, and receipt validation recomputes them.
- **Comparison.** Comparisons diff each node's metric verdicts by name, in
  addition to its status.
- **Compatibility.** Every new field is empty for single-status evaluators,
  and empty fields are left out of canonical JSON. Existing definitions,
  plans, manifests, and receipts therefore keep their digests, and resolve
  and compare unchanged.

## Consequences

- One more closed result schema, and new additive fields:
  - definition: `declared_metrics`;
  - plan node and resolved node: `metric_objectives`;
  - resolved evaluator binding: `declared_metrics`;
  - step receipt: `metric_verdicts`.

  Each field has a new protobuf field number.
- A receipt now discloses declared metric values. These are bounded numbers
  and booleans that the definition names. Other evaluator output still enters
  only `result_digest`.
- Stochastic aggregation is unchanged. Per-metric judge rubrics would be a
  later decision.
- A rollback to a build without this ADR still reads every stored document,
  because serde ignores unknown fields. That build would judge a metrics
  node by the evaluator's own status. It would also fail receipt validation
  for steps with verdicts, because the digest includes them, so roll back
  only after such plans are retired.

## Rejected

- **A free-form struct in `result`.** It would be unvalidated and could not
  be compared.
- **Thresholds in evaluator parameters.** This keeps policy in the evaluator.
- **Weighted or composite scores.** These are out of scope. A plan that needs
  them can add nodes.
