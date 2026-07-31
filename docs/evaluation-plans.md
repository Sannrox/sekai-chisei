# Evaluation plans and evaluator definitions

Evaluation plans are Chisei's production evaluation-selection contract. They
are separate from `EvalSuite`: suites remain reusable test cases, while plans
bind exact governed invariants to trusted deterministic evaluator
implementations.

The v1 API adds:

- `Put`, `Get`, and `ListEvaluatorDefinition`;
- `SetEvaluatorAvailability`; and
- `Put`, `Get`, and `ListEvaluationPlan`.

`ResolveEvaluationPlan` is the separate authorized pre-execution boundary that
freezes an exact plan and its situation-specific inputs. See
[Resolved evaluation manifests](evaluation-manifests.md).

All resources are namespace scoped. Definition and plan mutations require a
control-plane administrator with namespace write access. Reads require
namespace access. A plan is hidden rather than partially returned when the
caller cannot read one of its exact governed-invariant reference closures.

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

- an exact implementation digest and the
  `deterministic_builtin/v1` execution class;
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
nodes, arbitrary scripts or expressions, action/deployment nodes, and
stochastic or model-based evaluators.

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

## Availability, disabling, and superseding

Definitions are immutable. Availability is a separate mutable, audited record
keyed by the exact definition identity and implementation digest.
`SetEvaluatorAvailability` accepts `enabled`, `disabled`, or `superseded`.
Superseding requires the exact successor definition ID in the same namespace.
Each transition requires a request ID; replaying the same canonical request is
idempotent, while reusing it for different content fails.

Disabled or superseded definitions cannot be selected by a new plan. Existing
plans remain readable because the transition does not rewrite their exact
references. Later manifest resolution and re-execution must check current
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
