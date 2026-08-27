# ADR 0011: Separate invariant facts from configurable evaluation plans

- Status: accepted
- Date: 2026-07-30
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/464
- Issue: https://github.com/Sannrox/sekai-chisei/issues/461
- Supersedes: none
- Superseded by: none
- Related: [ADR 0045](0045-governed-data-quality-rules.md)

## Context

Evaluation is a core, situation-specific capability. Different subjects and
domains require different evaluator sets, inputs, schemas, parameters,
dependencies, and invariant coverage. The control plane needs that variability
without turning Chisei into a generic workflow engine or allowing evaluation
configuration to redefine Sekai's normative facts.

The existing `EvalSuite` contract describes reusable test cases and assertions,
and `EvalRun` accepts caller-submitted results. The existing governed-subject
profiles are compiled validators for a small fixed catalog. Neither contract
provides production gate authority that binds an exact invariant set to trusted
evaluator implementations and a reproducible decision.

## Decision

Sekai owns immutable requirement and invariant versions, applicability,
verification contracts, provenance, supersession, and governed waiver facts.
An authorization-filtered invariant-set resolution identifies the exact facts
that apply to one subject at an explicit evaluation time.

Chisei owns two first-class, immutable, versioned resources:

- `EvaluatorDefinition` binds a stable evaluator identity and version to an
  exact implementation digest, deterministic execution class, supported input
  and result schemas, parameter schema, evidence classifications, resource
  limits, and provenance.
- `EvaluationPlan` binds accepted subject profiles to a bounded acyclic graph
  of exact evaluator definitions, typed input bindings, schema-validated
  parameters, explicit invariant coverage, required or advisory
  classification, and the fixed v1 reducer.

Evaluator definitions are operator controlled because evaluation needs vary by
situation. The API may register or select deployed evaluator implementations,
but it does not accept tenant-uploaded executable code.

Chisei keeps evaluator availability in a separate mutable, audited resolution
policy record keyed by the exact evaluator identity, version, and
implementation digest. Disabling or superseding that record prevents future
resolution without mutating the immutable definition. Historical plans,
manifests, and receipts retain their exact references and remain readable;
re-execution must pass the current availability check rather than treating a
historical reference as authority.

Resolution freezes the subject, invariant set, plan, evaluator implementation
digests, admitted evidence, valid waivers, authenticated actor, namespace, and
evaluation time into a canonical content-bound manifest. The manifest is
durable execution evidence referenced by the canonical operation receipt; it
does not have an independently managed public lifecycle in v1. Step results are
bounded receipt evidence rather than another top-level resource family.
Resolution remains an internal deterministic phase unless implementation
evidence demonstrates an operator approval or preflight workflow that requires
a separate public operation.

The fixed v1 reducer is fail closed for required nodes:

- a required failure denies;
- unavailable, error, or unsupported execution is unavailable unless another
  required node fails;
- insufficient, stale, inaccessible, invalid-waiver, or uncovered evidence is
  unknown unless another required node fails;
- advisory nodes are recorded but do not affect the gate; and
- allow is possible only when every applicable gate-blocking invariant is
  covered by a passing required node or an exact valid waiver.

V1 permits deterministic typed evaluator nodes with explicit dependencies and
hard bounds. They may use either a compiled operator implementation or the
bounded operator-deployed `external_adapter/v1` contract defined by
[ADR 0013](0013-governed-external-evaluator-adapters.md). It excludes loops,
dynamic nodes, arbitrary scripts or expressions, action, deployment, or
rollback nodes, ambient filesystem or network authority granted to evaluator
code, caller-selected reducers, unversioned aliases, hidden fallback
evaluators, tenant-uploaded executable code, and stochastic or model-based
evaluator semantics in the deterministic class.

The public contract is additive. Existing `EvalSuite`, `EvalRun`,
governed-subject v1 profiles, the internal Chisei decision pipeline, and
canonical operation-receipt authority retain their current meanings.
SQLite and PostgreSQL must implement equivalent storage and authorization
behavior for every new durable resource.

## Alternatives considered

- **Extend `EvalSuite`.** Rejected because test data and caller-submitted run
  results must not acquire evaluator-selection or production gate authority.
- **Compile evaluator definitions into the server.** Rejected because
  situation-specific evaluation requires operators to compose and version
  evaluator definitions independently of a single fixed catalog.
- **Expose a generic workflow engine.** Rejected because evaluation needs a
  closed deterministic vocabulary, not general control flow or effect
  execution.
- **Give manifests and step receipts independent public lifecycles.** Rejected
  because their durable purpose is execution and reconciliation evidence
  already owned by the canonical operation receipt.

## Consequences

The design adds public resources, authorization checks, migrations, retention
dependencies, and SQLite/PostgreSQL conformance work for evaluator definitions
and evaluation plans. That complexity is accepted because it supplies required
evaluation variability while preserving exact provenance and replay.

Canonicalization, resource limits, evaluator availability transitions,
interrupted-execution reconciliation, and historical readability must be
explicit. Availability transitions are audited and idempotent for the same
request. They prevent future resolution but do not rewrite immutable evaluator
definitions, plans, manifests, or receipts.

Implementation proceeds through:

1. #466 — make the existing assertion vocabulary fail closed;
2. #462 — add governed requirement, invariant, waiver, and invariant-set facts;
3. #465 — persist evaluator definitions and evaluation plans;
4. #467 — resolve plans into canonical content-bound manifests;
5. #469 — execute deterministic manifests and record receipt evidence;
6. #463 — add plan-backed governed-subject evaluation; and
7. #468 — add operator authoring and inspection after the API stabilizes.

Stochastic evaluation remains a separate later decision under #470.

## Validation

The implementation must prove:

- two synthetic domains use the same fact and plan contracts without adding
  domain-specific core protobuf fields;
- exact plan, evaluator, invariant, waiver, evidence, subject, and manifest
  identities survive restart and deterministic replay;
- evaluator disable and supersede transitions are audited, survive restart,
  block future resolution, and preserve historical readability;
- every missing, hidden, stale, unknown, unavailable, error, invalid-waiver,
  and uncovered path fails closed without leaking protected evidence;
- SQLite and PostgreSQL pass the same fresh-database, upgrade, restart,
  idempotency, authorization, and backend-conformance fixtures;
- existing eval-suite, governed-subject v1, and operation-receipt fixtures
  remain unchanged; and
- the boundary is reviewed after the deterministic vertical slice in #463
  lands, before any stochastic execution work begins.
