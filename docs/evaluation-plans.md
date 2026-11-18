# Evaluation plans and evaluator definitions

Evaluation plans are a Chisei evaluation-selection contract in 1.0.
`PutEvaluationPlan` and `ResolveEvaluationPlan` are classified `stable`; their
consumer is [`sekaictl admin evaluation plan`](evaluation-operator-cli.md).
`PutEvaluatorDefinition` stays `experimental` and is rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled, because evaluator definitions are operator-owned deployment
metadata rather than something the CLI publishes. See
[rpc-maturity.md](rpc-maturity.md). Plans are separate from
`EvalSuite`: suites remain reusable test cases, while plans bind exact governed
invariants to trusted deterministic implementations or explicitly bounded
stochastic model evaluators.

The v1 API exposes:

- `PutEvaluatorDefinition` for immutable publication and lifecycle transitions;
- evaluator lifecycle transitions through `PutEvaluatorDefinition`; and
- `PutEvaluationPlan` for immutable publication.

`ResolveEvaluationPlan` is the separate authorized pre-execution boundary that
freezes an exact plan and its situation-specific inputs. See
[Resolved evaluation manifests](evaluation-manifests.md).

All resources are namespace scoped. Definition and plan mutations require a
control-plane administrator with namespace write access. Resolve and execute
are the read paths for exact published resources and fail closed when the
caller cannot read a referenced governed-invariant closure.

## Immutable version identities

An evaluator definition is identified by `(namespace, evaluator_id, version)`.
An evaluation plan is identified by `(namespace, plan_id, version)`. The server
derives stable resource IDs and canonical SHA-256 content digests. Repeating a
put with canonically identical content is idempotent and returns the stored
resource. Reusing the same identity and version with different content fails;
publish a new version instead.

Canonicalization sorts set-like fields, sorts nodes by stable node ID, sorts
bindings and dependencies, and canonicalizes parameter JSON. Creation actor
and time are stored provenance but do not change the content digest.

## Situation-specific evaluation

Each evaluator definition declares:

- an exact implementation digest and one of the
  `deterministic_builtin/v1`, `external_adapter/v1`, or
  `stochastic_model/v1` execution classes. External definitions also bind an
  operator-deployed HTTPS adapter endpoint; they never upload executable code;
- supported predicate, input, and result schemas;
- a closed parameter schema;
- admitted evidence classifications;
- hard timeout, byte, and evidence-item limits; and
- a provenance reference.

Each plan declares accepted subject profiles and a bounded acyclic graph. Every
node names an exact evaluator definition, explicit dependencies, typed
`subject`, `invariant`, or `evidence` bindings, schema-validated parameters,
exact invariant-version coverage, and `required` or `advisory` classification.
Every covered invariant must appear on at least one required node; advisory
nodes may observe the same invariant but cannot provide gate coverage.
Publication also walks each exact invariant and requirement reference closure
and rejects an evaluator whose admitted classifications do not include every
referenced evidence classification. Missing or unknown evidence
classifications fail closed.
Plan publication verifies that every invariant is active, visible, applicable
to all accepted subject profiles, and compatible with the selected evaluator's
predicate and schemas. V1 plans are profile-wide and therefore reject
invariants with non-empty exact `subject_refs`; a later contract would need an
explicit matching plan restriction before admitting subject-specific facts.

V1 accepts only the fixed
`required_all_pass_advisory_observed/v1` reducer. It rejects loops, missing
nodes, unknown evaluators, disabled evaluators, unversioned aliases, dynamic
nodes, arbitrary scripts or expressions, and action/deployment nodes.

External adapter registration is part of the immutable definition metadata. A
successful `PutEvaluatorDefinition` therefore means only that the definition
is published. `EvaluatorDefinitionRecord` separately reports whether the exact
implementation is executable in this process. The adapter contract, signing
headers, endpoint restrictions, and fail-closed availability behavior are
documented in [External evaluator adapters](evaluator-adapters.md).

## Bounded stochastic definitions

A stochastic definition adds one immutable policy for its concrete evaluation
situation. It binds the exact provider, canonical provider-prefixed model,
compiled implementation digest, prompt profile and digest, result schema,
integer sampling controls, fixed trial count, aggregation and acceptance
thresholds, retry and token limits, egress mode, raw-response retention mode,
and gate eligibility.

V1 accepts two to 32 trials and only
`mean_score_with_variance/v1`. `max_total_tokens` must cover every fixed trial
slot and every admitted retry at `max_tokens_per_trial`; retries therefore
cannot expand the population or exceed its declared ceiling. OpenAI-compatible
providers may bind stable per-slot seeds. Anthropic policies cannot claim seed
support. Provider and model prefixes must match exactly.

External model policies require `allowlisted_external/v1`; their provider must
also be configured in `CHISEI_SAFE_EGRESS_PROVIDERS` at execution time.
Ollama policies require `local_only/v1`. There is no route fallback.

A required node may reference a stochastic definition only when
`gate_eligible` is explicitly true. Publication rejects advisory-only
stochastic policy in a required position. Advisory nodes can record the same
statistical evidence without changing the fixed reducer.

Raw prompt and response retention is `none/v1` in this contract. Encrypted
retention is intentionally unavailable until a governed encrypted store and
retention lifecycle exist. Publishing a different retention value fails
closed.

The fixed reducer is fail closed: required failures deny; required
unavailability or execution errors are unavailable; insufficient, stale,
hidden, invalid-waiver, or uncovered inputs are unknown; advisory results are
recorded without changing the gate; and allow requires every applicable
gate-blocking invariant to be covered by a passing required node or exact valid
waiver.

## Parameter-schema subset

`parameter_schema_json` uses a deliberately closed JSON-Schema subset:

- root `type` must be `object`;
- `properties`, `required`, and `additionalProperties: false` are mandatory;
- property types are `string`, `number`, `integer`, or `boolean`;
- properties may use `enum`, numeric `minimum`/`maximum`, or string
  `minLength`/`maxLength`; and
- unknown schema keywords and unknown runtime parameters are rejected.

Integer bounds use exact signed/unsigned JSON integer comparison across the
full supported range. `number` uses finite IEEE-754 comparison and rejects
integer-valued magnitudes above `2^53 - 1`; use `integer` when exact larger
values are required.

This supports situation-specific tuning without admitting executable
expressions or an open-ended schema engine.

## Built-in evaluators

The production registry compiles these parameterized deterministic
evaluators. A definition selects one by naming its exact implementation digest
with `deterministic_builtin/v1`, and its `parameter_schema_json` must equal the
built-in's published schema (below), or publication fails. Plan publication
also checks each node's parameters semantically (the pattern compiles, bounds
are ordered, dates parse), so invalid parameters never reach execution.

Each built-in reads one value from every bound evidence item's content at the
JSON Pointer `path` (`""` is the whole document). The step passes only when
every item passes. No bound evidence is `unknown` (`evidence_missing`); an
absent value is `fail` (`value_missing`), and a value of the wrong type is
`fail` (`value_type_mismatch`). Bounds are inclusive. Optional booleans
default to `false`.

| Kind | Digest | Parameters | Fails with |
| --- | --- | --- | --- |
| `exact_match.v1` | `sha256:0c63c8a1dac4e3a7db0022dcb10aef2154812ecd804fde881d609533dc057bd4` | `path`, `expected` (at most 4096 characters), `ignore_case`, `normalize_whitespace` | `value_mismatch` |
| `regex_match.v1` | `sha256:027d48a71422eba2f48077a1d8d137aac946ef5a67d8a72c48459f469c35902f` | `path`, `pattern` (1 to 1024 characters), `ignore_case` | `pattern_not_matched` |
| `numeric_range.v1` | `sha256:c3138ddbe9bda3dd3aad8e6cf970de103bc5dc868a4ee5d7d4278effa2458a16` | `path`, `minimum`, `maximum` (at least one) | `value_out_of_range` |
| `date_range.v1` | `sha256:b53319ef47f40ea77672a92d18fb38e5311489a4154675ee8639a91e42123429` | `path`, `not_before`, `not_after` (at least one) | `value_out_of_range` |
| `edit_distance.v1` | `sha256:65760e10a0f3b36d1bc718467a4330cd6d4592ca6139a9cf7627e94a924393e0` | `path`, `expected` (at most 4096 characters), `max_normalized_distance` (0 to 1), `ignore_case`, `normalize_whitespace` | `distance_exceeded` |
| `token_overlap.v1` | `sha256:4277adf08bf9649c62d4e166f19c07c574bd28ae373654729a6ff9599881c1ed` | `path`, `reference` (at most 16384 characters, at least `n` tokens), `n` (1 to 4), `min_recall` (0 to 1), `ignore_case` | `overlap_below_minimum` |
| `size_bounds.v1` | `sha256:671f12059f6d74eaff3430fe635fe5d537a4deb41e10b07584c5d9b61472265f` | `path`, `min_items`, `max_items` (at least one, 0 to 1000000), `distinct` | `size_out_of_bounds` |

Each digest is SHA-256 of `chisei.builtin-evaluator/<kind>`. Changed
behavior ships as a new kind version and digest beside the old one; the
published digests stay executable.

- **Text normalization.** `ignore_case` is Unicode lowercase and
  `normalize_whitespace` trims and collapses Unicode whitespace to one space.
  Neither depends on locale.
- **Regular expressions** search the value (anchor with `^` and `$` for a full
  match). The engine matches in time linear in the input and has no
  backreferences or lookaround. A pattern whose compiled program exceeds the
  size or nesting limit is refused at plan publication.
- **Numbers** compare as IEEE-754 doubles. A value must be a JSON number.
- **Dates** are RFC 3339 date-times or `YYYY-MM-DD` calendar dates, which
  compare as midnight UTC. A value must be a string in one of those forms.
- **Edit distance** is Levenshtein distance over Unicode scalar values divided
  by the longer text's length. A value longer than 16384 characters whose
  length alone does not decide the result is an `error` step.
- **Token overlap** splits on non-alphanumeric characters and reports
  clipped recall: the share of the reference's `n`-grams found in the value,
  each counted at most as often as it appears in the value.
- **Size bounds** require a JSON array. With `distinct`, items count once per
  canonical JSON value.

To read the exact schema for a digest, see `builtin_parameter_schema` in
`crates/chisei-core/src/chisei/builtin_evaluators.rs`.

## Availability, disabling, and superseding

Definitions are immutable. Availability is a separate mutable, audited record
keyed by the exact definition identity and implementation digest.
`PutEvaluatorDefinition` accepts lifecycle transitions to `enabled`, `disabled`, or `superseded`
when the immutable definition body is omitted.
Superseding requires the exact successor definition ID in the same namespace.
Each transition requires a request ID; replaying the same canonical request is
idempotent, while reusing it for different content fails.

Disabled or superseded definitions cannot be selected by a new plan. Existing
plans remain durable because the transition does not rewrite their exact
references. Later manifest resolution and re-execution check current
availability.

## Backup, restore, retention, and rollback

SQLite backups must include the four `chisei_evaluator_*` /
`chisei_evaluation_plans` tables together with the Sekai graph, grants, audit,
and temporal-history tables. PostgreSQL migration
`0024_evaluation_plans.sql` creates the equivalent tables; use a transactionally
consistent database backup.

Restore the evaluator-definition, availability, availability-event, and plan
tables from the same snapshot as governed facts. Restoring only one side can
leave exact references unavailable and correctly fail closed.

Do not roll back by editing or deleting an immutable definition or plan.
Publish a new version, disable or supersede the evaluator, and select the prior
known-good plan version at the integration boundary. Retain plans,
definitions, and availability events for at least as long as any operation
receipt or future resolved manifest references them. Physical deletion is not
part of the v1 public API.

`EvalSuite`, `EvalRun`, governed-subject v1 profiles, and operation-receipt
authority are unchanged by these resources.

Execution and recovery semantics are documented in
[Evaluation execution](evaluation-execution.md). The durable rationale is
[ADR 0012](decisions/0012-bound-stochastic-evaluation-by-situation.md).
