# ADR 0155: Custom-rubric judges pin their criteria in the evaluator definition

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2633 (#2633)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0012](0012-bound-stochastic-evaluation-by-situation.md),
  [ADR 0013](0013-governed-external-evaluator-adapters.md)

## Context

ADR 0012 freezes a judge's prompt profile and its digest into the immutable
stochastic policy, so a judge cannot drift between runs. The only shipped
model-graded profiles judge against the invariant contract in their input.
Judging against other criteria, such as "the answer cites the source record",
needs a new compiled implementation in the binary. Unlike deterministic
evaluators, stochastic ones have no external adapter path.

## Decision

- **Profile.** Add the compiled prompt profile `chisei.custom-rubric/v1`. It
  runs through the shipped `bounded_rubric_score/v1` implementation, so the
  trial, retry, budget, egress, and threshold handling are unchanged.
- **Rubric.** The stochastic policy carries an optional `rubric`:
  - `text`: plain text, non-empty, at most 4,096 UTF-8 bytes, no control
    characters other than newline and tab, and no `<criteria` or `</criteria`;
  - `digest`: `sha256:` of the UTF-8 bytes of `text`;
  - `scale_max_points`: absent, or 2 to 10.

  A rubric is valid only with this profile, and this profile requires one.
  Definition publication refuses a rubric whose digest does not match its
  text, and the judge re-checks a stored rubric before each trial.
- **Prompt.** The system prompt is fixed and owned by Chisei. The rubric is
  appended between `<criteria>` and `</criteria>`, which it cannot contain,
  and the subject and evidence remain marked as untrusted data. The profile
  digest covers every fixed component, both system prompt variants, the
  delimiters, and both result schemas.
- **Binary by default.** Without a scale, the rubric is one verifiable
  assertion. The judge returns `passed` and `reason_code`, and the trial
  records a score of 0 or 1, which is 0 or 1,000,000 micros in the existing
  result schema. With `scale_max_points = n`, the judge also returns an
  integer `score` in `0..=n`. The trial records `score * 1,000,000 / n`
  micros, and a score above `n` is a schema failure.
- **Versioning.** The rubric and scale are part of the definition's content
  digest. Changing either one is a new definition version. Baseline comparison
  already refuses runs that used different evaluator digests, so runs judged
  by different rubrics are never compared.
- **Retention.** The profile requests no rationale, so it requires
  `raw_response_retention = none/v1`.

## Consequences

- Namespaces can define judges without a binary change. The rubric is
  namespace-authored text that reaches a model. It is bounded, digest-checked,
  and audited with the definition, and it never replaces the system prompt.
- Proto: `StochasticEvaluatorPolicy.rubric` (field 21) and the new
  `EvaluationRubric` message. The domain field is left out of canonical JSON
  when absent, so existing definitions, plans, manifests, and receipts keep
  their digests.
- Stored definitions are JSON bodies, so neither SQLite nor PostgreSQL needs
  a migration.
- A rollback to a build without this ADR still reads every stored document,
  because serde ignores unknown fields. That build drops the rubric, and its
  judge refuses the unknown profile, so such trials fail closed instead of
  being judged without criteria.

## Rejected

- **Rubric as a plan parameter.** The judge would change without the
  evaluator definition changing, which breaks comparability.
- **A free-form system prompt per evaluator.** This weakens the injection
  boundary.
- **An external adapter class for stochastic evaluators.** This is a larger
  trust change, and it can follow later if needed.
- **Rubric rationale and several metrics per rubric.** Retained rationale
  stays with the bounded rationale profile. Per-metric rubrics are a later
  decision (ADR 0154).
