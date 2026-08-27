# ADR 0045: Evaluate versioned data-quality rules as content-bound results

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/789
- Issue: https://github.com/Sannrox/sekai-chisei/issues/681 (#681)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0011](0011-separate-invariant-facts-and-evaluation-plans.md),
  [ADR 0012](0012-bound-stochastic-evaluation-by-situation.md)

## Context

Evaluation manifests, receipts, and quality-trend projections exist, but a
versioned quality rule can still be applied to a mutable dataset and look like
pass. Missing digests, partial populations, unknown versions, and unavailable
evaluators must stay distinct from success.

## Decision

A published rule is a `chisei.data-quality-rule/v1` record identified by
`(namespace, rule_id)`. The live revision has a content digest. The rule names
one built-in evaluator (`digest_pin`, `completeness`, or `row_count_bound`) and
a typed dataset identity. The rule never grants write or permit authority.

The subject is a typed dataset revision. Running the rule admits a
`chisei.data-quality-result/v1` record identified by
`(namespace, rule_digest, dataset_revision_digest)`. The record binds rule,
evaluator, dataset revision, evidence receipt, population, optional baseline,
and one closed state: `pass`, `fail`, `missing`, `invalid`, `unavailable`, or
`unknown`.

Missing data, unauthorized data, unknown versions, invalid results, partial
work, cancelled work, and unavailable evaluators stay those states. They never
become `pass`. Hidden and unknown identities return the same unavailable
result. Exact replay returns the prior immutable receipt. Restart completes a
cancelled run without rewriting a closed receipt. Cancellation is durable.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Folding this into quality-trend projections would leave rule evaluation
uninspectable. Caller-selected reducers or implicit pass from a partial
population would manufacture success. Evaluating live rows without a revision
pin would make replay irreproducible.

## Consequences

Operators can publish, evaluate, cancel, and restart a versioned quality rule
against a pinned dataset revision. Follow-up work may add PostgreSQL parity and
gRPC transport.

## Validation

Deterministic tests cover authorized pass and fail, missing and invalid inputs,
unknown versions, hidden versus unknown identities, immutable replay, durable
cancellation, and restart that retains the cancelled receipt digest.
