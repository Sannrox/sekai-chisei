# Grouping failed eval cases by cause

- Issue: [#2631](https://github.com/Sannrox/sekai-chisei/issues/2631)
- Status: recommendation complete
- Date: 2026-11-24

## Question

After an eval run, should Chisei group the failed cases by likely cause? If it
does, should it also propose prompt, tool, or policy changes that might fix a
group? Which part would be deterministic, and which part would run on a model?

## Recommendation

1. **Deterministic grouping in the plane.** Group a run's failed cases using
   keys the run already records or can record without new trust surface.
   [#3438](https://github.com/Sannrox/sekai-chisei/issues/3438) tracks it.
2. **No model-assisted suggestions in the plane now.** The inputs a useful
   suggestion needs are either missing, or readable only by principals who
   can already read the case. A suggestion is advice that no plane path
   could verify. Clients that want suggestions can assemble them from the
   grouped report and `GetEvaluationRationale`, under their own model and
   egress policy. Revisit this as an ADR only if grouping ships and operators
   still show that the groups are too coarse to act on.
3. **No ADR.** This adds no boundary or long-term rule. Deterministic grouping
   is a projection over results the run already stores.

## Evidence

### What a failed case carries today

A failed case records an `EvalCaseResult` with a `CaseOutcome`
(`crates/chisei-core/src/chisei/eval_run.rs`, read at `d8d6a323`). That case
line carries several candidate grouping keys:

| Key | Source | Cardinality | Useful as a cause? |
| --- | --- | --- | --- |
| Template | `case_id` is `<template>:<object>` | One per dataset template (3 in the `supply-chain-triage` fixture) | Yes: names the kind of question that failed |
| Tags | Dataset case `tags` | Small, author-chosen | Yes, when the author tagged by capability |
| Reason code | `CaseOutcome.reason` | Closed per evaluator | Built-ins: yes; stochastic: no (see below) |
| Policy violation | `CaseOutcome.policy` (`eval_policy.rs`) | 4 kinds | Yes: already counted per run, not joined to failure |
| Unmet metrics | Step receipt `metric_verdicts` (ADR 0154) | Declared metric names | Yes, but not copied to the case line |

The built-in evaluators emit 6 distinct failure reason codes:

- `value_missing`, `value_mismatch`, `value_type_mismatch`;
- `value_out_of_range`, `pattern_not_matched`, `distance_exceeded`.

See `crates/chisei-core/src/chisei/builtin_evaluators.rs`. These already name
the cause of a deterministic failure closely enough to act on.

### Where grouping loses information

- **Stochastic failures collapse.** A failed stochastic step records only the
  aggregate reason `stochastic_acceptance_rule_not_satisfied`, and that is the
  value `CaseOutcome.reason` keeps. The trial-level codes, `criteria_not_met`
  and `insufficient_evidence`, stay on the step receipt's stochastic
  evidence. Grouping on the case line alone therefore puts every failed
  stochastic case into one group. The step receipt already holds the
  trial-code distribution, so the case line can carry the most frequent trial
  code without any new model call.
- **Metric failures are invisible on the case line.** Since ADR 0154, a step
  records which metric objectives were unmet. The case line keeps only
  `metric_objective_unmet`. The names of the unmet metrics are the most
  specific cause available, and they are bounded and declared.
- **Policy outcomes are reported apart from pass or fail.** By design, the
  run response reports violations independently of the verdict. Joining
  them per failed case, for example "failed and had a marking leak", needs no
  new data.

### What a suggestion would need

A suggestion such as "change the prompt so that X" needs to know why each
case failed:

- **Deterministic evaluators.** The reason code and the case input suffice
  to understand the failure. A suggestion beyond "fix the value" restates the
  reason.
- **Stochastic evaluators.** Only `rationale/v1` retention keeps the judge's
  explanation (`docs/evaluation-execution.md`). It is opt-in per
  definition and expires after 30 days. It is readable through the
  experimental `GetEvaluationRationale`, subject to the case's markings.
  Without it, a model would see only reason codes, and could not do better
  than the deterministic groups.

A model call inside the plane that reads rationale and case evidence must:

- follow ADR 0012 egress and budget rules;
- never show a reader evidence the reader cannot read.

Its output could not be checked by any governed path, so it would stay
advice. Every reader allowed to see the input could already pass the same
input to a model of their own choosing. In-plane suggestions therefore add
trust surface (a new model call class, egress, and output marking) and
nothing a client cannot do.

### What exists already

- **Quality trends** (`docs/evaluation-quality-trends.md`) group executions by
  plan, node, evaluator, provider, model, and agent across time. They answer
  "is this series getting worse", not "why did these cases in this run fail".
- **Run comparison** (`eval_compare.rs`) pairs cases against a baseline. It
  reports regressions and policy-violation increases. It names which cases
  regressed, not a cause.

Neither covers grouping within one run. Both are the natural readers of a
grouped report, because a regression list grouped by cause is more useful
than a flat list of case ids.

### Synthetic runs

No recorded failing run exists in the repository. The only dataset fixture,
`tests/fixtures/evaluation/datasets/supply-chain-triage.json`, has 3 templates.
The planned measurement of how many failures land in a useful group could
therefore not be taken on recorded data. The structural result holds anyway:

- a built-in evaluator's failure falls into one of 6 reason codes times the
  template count;
- a stochastic failure falls into 1 group until the case line carries trial
  codes;
- a metrics failure falls into 1 group until the case line carries unmet
  metric names.

## Follow-up

[#3438](https://github.com/Sannrox/sekai-chisei/issues/3438) covers deterministic grouping: a run report that
groups failed cases by:

- template;
- reason code, with the most frequent trial code for stochastic steps;
- unmet metric names;
- policy violation kind.

Each group lists its count and case ids, readable under the run's existing
authorization.
