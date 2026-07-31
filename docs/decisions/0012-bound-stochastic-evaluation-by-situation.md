# ADR 0012: Bound stochastic evaluation by situation

- Status: accepted
- Date: 2026-07-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/464
- Issue: https://github.com/Sannrox/sekai-chisei/issues/470
- Supersedes: none
- Superseded by: none

## Context

ADR 0011 deliberately limited production evaluation plans to deterministic
compiled evaluators. That boundary is appropriate for predicates with
bit-identical execution, but some software-quality judgments require a model.
Representing those judgments as deterministic, or retaining one unexplained
score, would overstate reproducibility and hide provider, sampling, variance,
cost, egress, and retention differences.

Evaluation is not generic across situations. A release-quality review, a
documentation assessment, and a policy interpretation need different prompts,
schemas, thresholds, trial populations, and gate authority. Chisei therefore
needs bounded model-based evaluation without adding a generic judge, workflow
engine, model fallback, or tenant-supplied executable code.

## Decision

Add `stochastic_model/v1` as a separate evaluator execution class.
Deterministic and stochastic implementations use different registries and
dispatch paths. A definition cannot declare both classes, and a stochastic
implementation digest is never resolved through the deterministic registry.

Every stochastic evaluator definition contains one immutable,
situation-specific policy binding:

- exact provider and canonical provider-prefixed model;
- exact compiled evaluator implementation, prompt profile and prompt digest;
- exact normalized result schema;
- integer temperature and top-p controls plus a base seed only where the
  provider contract exposes one. V1 admits the OpenAI seed parameter only;
  other providers freeze `seed_supported=false` and seed `0`;
- fixed trial count, per-trial retry limit, token limits, timeout, aggregation
  rule, mean-score threshold, pass-rate threshold, and maximum variance;
- `local_only/v1` or `allowlisted_external/v1` egress; and
- explicit `gate_eligible` and raw-response retention policy.

V1 supports `mean_score_with_variance/v1` over two to 32 stable trial slots.
A retry repeats the same slot and seed. It does not add a trial or silently
change provider, model, profile, schema, or sampling controls. Provider
unavailability, timeout, cancellation, refusal, invalid schema, budget
exhaustion, and incomplete populations are typed non-pass states. A required
plan node may select a stochastic evaluator only when its immutable policy
sets `gate_eligible=true`; otherwise it is advisory-only.

Resolution freezes the complete stochastic policy into the manifest.
Execution records one normalized result digest per fixed slot, aggregate
statistics, token counts, and a deterministic digest over that recorded
evidence. The receipt supports statistical comparison; it never claims
bit-identical model replay.

External provider calls require the exact provider to be in
`CHISEI_SAFE_EGRESS_PROVIDERS`. The execution path reserves the frozen token
ceiling only after the node is ready and its exact evaluator is registered,
immediately before provider execution. Blocked, completed, and unavailable
nodes do not reserve budget.
`ollama` requires `local_only/v1` and is inherently admitted by the local
provider policy. There is no provider or model fallback.

V1 persists no raw prompt, evidence payload, provider response, model
reasoning, or normalized result object. Only bounded reason codes, numeric
statistics, token counts, and digests enter the receipt. The policy value is
therefore currently restricted to `none/v1`. Encrypted raw retention remains
disabled until a dedicated governed encrypted store, authorization model,
redaction contract, and retention lifecycle exist.

The existing request-level executor version remains
`chisei.deterministic-evaluation-executor/v1` for persistence and client
compatibility. It identifies the established manifest execution protocol, not
the node implementation class. The frozen evaluator binding and separate
registry are authoritative for dispatch, so this compatibility identifier
does not allow stochastic execution through the deterministic boundary.

## Alternatives considered

- **Reuse the deterministic class with a seed.** Rejected because a seed does
  not guarantee provider, infrastructure, or model reproducibility.
- **Use one generic evaluation policy.** Rejected because evaluation inputs,
  thresholds, trial counts, egress, and gate authority are situation-specific.
- **Record one score.** Rejected because it omits the fixed population,
  variance, aggregation, and partial-population evidence.
- **Allow automatic fallback.** Rejected because changing provider or model
  changes the evaluated population and invalidates the frozen policy.
- **Persist raw responses by default.** Rejected because model output and
  prompts can reproduce sensitive evidence and require a separate governed
  retention boundary.

## Consequences

The plan and manifest contracts gain additive stochastic policy fields, and
step receipts gain additive statistical evidence. Provider-neutral chat
requests gain internal sampling controls used only by governed stochastic
evaluation; ordinary public LLM requests leave them unset.

Operators must publish different evaluator-definition versions when any
provider, model, prompt, schema, sampling, aggregation, threshold, budget,
egress, retention, or gate decision changes. They must explicitly allowlist
external providers and size token budgets for every fixed trial slot and
bounded retry.

Stochastic execution costs more and provides statistical rather than
bit-identical comparability. Its bounded trials, no-fallback routing,
fail-closed states, and no-raw-retention default are accepted constraints.
Deterministic evaluator semantics and existing immutable receipt digests remain
unchanged when no stochastic policy is present.

## Validation

The implementation must prove:

- class validation and separate registries prevent stochastic-as-deterministic
  registration and execution;
- plan publication and live CLI validation enforce explicit gate eligibility;
- fake providers demonstrate stable retry slots, stable seeds, deterministic
  aggregate digests, visible variance, bounded metrics, and typed non-pass
  failures;
- provider adapters bind supported sampling controls without provider-specific
  types in plan contracts;
- persisted receipts contain no raw prompt, evidence, or provider response;
- SQLite and PostgreSQL apply the same immutable-definition and plan checks;
- an ignored Ollama integration test exercises a live provider without making
  default CI depend on a model; and
- all pre-existing deterministic conformance fixtures retain their meaning.
