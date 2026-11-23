# Evaluation execution

`ExecuteEvaluationManifest` is a `stable` RPC (consumer:
[`sekaictl admin evaluation plan`](evaluation-operator-cli.md); see
[rpc-maturity.md](rpc-maturity.md)) that executes one exact
`chisei.resolved-evaluation-manifest/v1` through the
established `chisei.deterministic-evaluation-executor/v1` request protocol.
The frozen node execution class selects a separate deterministic or stochastic
registry and execution path; the request identifier is retained for persisted
execution and client compatibility. The manifest digest is the
idempotency identity. `GetOperationReceipt` returns the authoritative
projection, and `CancelEvaluationExecution` (still `experimental`; it needs
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature) durably
requests cancellation. `sekaictl admin evaluation plan compare` diffs two
finished executions from those receipts without executing anything.

This is situation-specific evaluation, not a generic workflow engine. A plan
still chooses different evaluator definitions, schemas, parameters, inputs,
dependencies, and invariant coverage for each subject or domain. The executor
only supplies bounded acyclic scheduling, exact implementation selection,
closed result states, and the fixed reducer.

## Evaluator boundaries

Evaluator definitions register metadata and an exact implementation digest;
they never upload code. A deployable evaluator is either a compiled Rust
`DeterministicEvaluator` or an operator-deployed `external_adapter/v1` endpoint
registered under that exact digest. The shipped server registers the
parameterized output checks listed in
[Built-in evaluators](evaluation-plans.md#built-in-evaluators) and one
subject-identity check:
`subject_content_digest_equals.v1`
(`sha256:fb7617ab821a130efe66c43a22df2923e4648c1cb58ae2d793b958a31e94f155`).
The registry also retains the previously published
`subject_content_digest_equals/v1`
(`sha256:83df0fa4577447ecf2a7817c49d637ab48a018fb2d72a9fd631ce76d89f6e475`)
registration solely so immutable historical manifests remain executable.
It accepts only that invariant predicate and exactly one
`expected_content_digest` parameter, then compares it with the manifest-bound
subject content digest. It is not a fallback and cannot evaluate other
situations. An unregistered implementation digest produces `unavailable`; a
subject content mismatch produces `fail` and therefore a `deny` gate. The
executor never chooses a fallback or a newer definition. External adapters
receive the canonical input document through the bounded authenticated
contract in [External evaluator adapters](evaluator-adapters.md); the adapter
has no Chisei credentials or action authority and its output is validated by
the same closed result contract.

Stochastic definitions use `stochastic_model/v1` and a separate
`StochasticEvaluatorRegistry`. The shipped stochastic implementation is
`chisei.bounded-rubric-score/v1`
(`sha256:1f28a6a6236c2405bcfeffc5730b014280287bf774e669c9f24ce4acb66c8ea9`).
It accepts only its compiled prompt profile and digest, calls the exact frozen
provider/model route, requests one normalized `passed`, `score_micros`, and
bounded `reason_code` result per trial, and has no tools other than that
structured return. It never falls back to another route.

Each implementation receives one canonical input document containing:

- the exact manifest and node identity;
- the opaque subject identity and content digest, without a subject payload;
- canonical parameters and invariant verification contracts;
- exact retained evidence content selected by the manifest; and
- exact dependency result digests.

The deterministic implementation receives no runtime capability object,
network client, clock, randomness, filesystem handle, process environment,
locale, timezone, model/provider client, or action authority. External adapters
receive only the signed canonical request and the input document; they do not
receive Chisei credentials or ambient capabilities. Implementations remain
operator-controlled and must pass the conformance harness.
The harness repeats
golden manifests in child processes with different timezone, locale, and hash
seed settings, and checks identical semantic receipt bytes.

Evaluator output content is ephemeral. It is bounded and hashed, then
discarded. The API and durable receipt expose only status, a bounded reason
code, exact input/parameter/evaluator/evidence/dependency digests, the result
digest, and the step-receipt digest. Evidence or result content is not
returned.

## Function revision gates

An LLM function revision is a governed evaluation subject
(`chisei.function-revision/v1`). The gate invokes the revision over a fixed
fixture set, retains each structured output as evidence, and scores that
evidence with the existing `stochastic_model/v1` rubric
(`chisei.bounded-rubric-score/v1`). A mean score below the manifest threshold
is a `deny` on publish. Invoice extraction uses a labelled fixture set
(`invoice_extraction_fixtures`) with expected vendor `ACME`; a worse
extraction is denied and an unchanged revision publishes (#1327).

Publish is the only way to store a revision with an LLM step: it records an
approval for the revision digest, then stores the revision. `CreateFunction`
refuses an LLM step, and `InvokeFunction` and document extraction refuse an
LLM revision whose digest has no approval ("LLM function revisions require an
allowing evaluation gate"). Revisions stored before approvals existed stay
unapproved until they pass the gate again.

Retained outputs inherit the fixture inputs' markings (the most restrictive
union of the lattice). The evaluator route sees those retained evidence
objects only when its classification ceiling covers the inherited marking;
otherwise the node is `unknown` / `evidence_unavailable` and publish stays
denied. The evaluator still receives only subject identity, content digest,
and retained evidence, never a live function payload.

## Fixed stochastic populations

Each stochastic step executes the frozen two-to-32 trial population in stable
slot order. A supported seed is `base_seed + trial_index`; a retry reuses that
same slot and seed. Retries are bounded per slot and cannot add trials.
When a retryable error cannot report partial provider usage, its full
per-attempt token ceiling is recorded as `retry_accounted_tokens` and included
in aggregate budget evidence.
Provider, model, profile, schema, temperature, top-p, aggregation, thresholds,
token ceilings, egress, and retention remain frozen for every attempt.

The receipt stores each slot's index, seed, attempt count, typed status,
bounded reason, score, token counts, and normalized result digest. It then
stores completed trial count, integer mean score, pass rate in basis points,
population variance, total token counts, and a deterministic aggregate digest
over the recorded slots. Those values support statistical comparison and gate
explanation; they do not claim bit-identical model replay.

The aggregate passes only when every fixed slot completed and all frozen
mean-score, pass-rate, and maximum-variance thresholds are satisfied.
Provider unavailability, timeout, cancellation, refusal, schema-invalid
output, token exhaustion, or any partial population is a typed non-pass state.
Timeout and cancellation drop the in-flight provider future before recording
that terminal state; provider work is not detached from the execution receipt.
An advisory stochastic node remains visible without affecting the reducer. A
required stochastic node can exist only when its frozen policy explicitly
declares gate eligibility.

Seeded trial slots are admitted only for the v1 OpenAI provider contract.
Other provider policies must freeze `seed_supported=false` and seed `0`.
Recorded seeds are sampling provenance, not a claim of bit-identical replay.

Before provider contact, external routes must be in
`CHISEI_SAFE_EGRESS_PROVIDERS`. Once a node is ready and its exact evaluator
implementation is registered, the full frozen token ceiling is reserved
idempotently against the project/node budget scope immediately before the
provider path. Blocked, completed, or unavailable nodes do not reserve it.
Ollama is local-only.
No prompt, evidence payload, raw provider response, reasoning, or normalized
result object is persisted. V1 admits only `none/v1` raw-response retention.
The production evaluator maps output to a closed reason vocabulary
(`criteria_met`, `criteria_not_met`, or `insufficient_evidence`); arbitrary
model-generated strings cannot enter a receipt.

### Retained judge rationale

A node whose stochastic policy declares `rationale/v1` retention, and whose
evaluator uses the `chisei.bounded-rubric-rationale/v1` prompt profile, keeps
the judge's rationale (at most 1024 characters) for each completed trial.
Nothing else from the prompt or provider response is kept. The step receipt
records only `rationale_digest` per trial.

Read a rationale with the experimental `ChiseiService.GetEvaluationRationale`
RPC (enable it with `SEKAI_EXPERIMENTAL_RPCS`), passing the namespace,
manifest digest, node id, and trial index:

- the caller needs namespace read access and clearance for the markings of
  every evidence object the step read; any refusal reads as not found;
- each disclosure records an `evaluation_rationale/read` audit decision first,
  and the read fails if the audit write fails;
- a rationale expires 30 days after it is recorded, and is removed when any
  source evidence is deleted, retracted, rejected, or quarantined. Reads
  enforce both, and a sweep every 10 minutes deletes unread rows.

Retained rationale relies on markings, the TTL, and volume encryption; it is
not encrypted by the application. See ADR 0012.

## Closed execution and reduction

Ready nodes run sequentially in deterministic topological order with
`node_id` as the tie-breaker. V1 has no parallel scheduler, loop, dynamic
node, expression, script, action, deployment, caller-selected provider/model,
or caller-selected reducer.

Step status is exactly one of:

- `pass`, `fail`, or `unknown` from a valid evaluator;
- `unavailable` for an unregistered implementation, timeout, or exhausted
  total execution budget;
- `error` for a panic, invalid result contract, or output-limit violation; or
- `skipped` when a dependency blocks the node or cancellation was requested.

Unknown status, result contract, reason-code shape, implementation digest, or
reducer values fail closed. Required-node precedence is `deny > unavailable >
unknown > allow`. Advisory results remain visible but do not change the gate.
Every invariant must be satisfied by a passing required node or an exact
manifest waiver before `allow` is possible.

Definition limits bound each node's timeout, canonical input bytes, ephemeral
output bytes, and evidence-item count. External adapter HTTP timeouts use the
effective node budget, including the remaining total budget. The first request
may lower total duration; zero selects 60 seconds and the hard maximum is 300
seconds. That
budget is frozen in the initial receipt, includes time across disconnects and
restarts, and cannot be reset by replaying the request. Zero is normalized
before persistence. A reuse request with a tighter bound fails closed when the
existing manifest execution froze a larger bound; the response never
misrepresents the actual execution limit. A timed-out compiled evaluator or
adapter request runs on an isolated thread with no supplied effects or capabilities;
its result is ignored if it returns later. Because Rust threads cannot be
force-killed safely, the registry has a hard global evaluator-thread capacity
(32 by default). A timed-out or cancelled evaluator retains its slot until it
returns; a permanently hung evaluator therefore consumes bounded quarantined
capacity, and new work closes as `unavailable/evaluator_capacity_exhausted`
instead of creating unbounded threads.

## Multi-metric steps

When a node's definition declares metrics (ADR 0154), the evaluator measures
and the frozen plan objectives decide. The executor reads `result` as
`{"contract_version": "chisei.evaluation-metrics/v1", "metrics": [{"name",
"kind", "value"}]}` and handles it as follows:

- **Invalid result.** The step is `error/invalid_result` when the result:
  - is not that exact shape;
  - reports 0 metrics or more than 32;
  - repeats a metric;
  - reports an undeclared metric, or a value of the wrong kind;
  - omits a metric that an objective is bound to.
- **Derived status.** The evaluator's own `pass` or `fail` is ignored. The
  step is `fail/metric_objective_unmet` when any bound objective is unmet, and
  `pass/metric_objectives_met` otherwise. `unknown` from the evaluator still
  means it could not measure, and passes through unchanged.
- **Receipt.** The step receipt adds `metric_verdicts`, one per reported
  metric, sorted by name. Each entry holds the name, kind, value, and frozen
  objective, plus a verdict:
  - `met` or `unmet` when the objective sets a pass condition;
  - `advisory` when no objective is bound or the objective has no threshold.
- **Digests.** The verdicts are part of the step receipt digest. Receipt
  validation recomputes them from the frozen manifest and the recorded
  values. Steps without metrics keep the v1 digest.
- **Comparisons.** Comparing two executions also diffs each node's metrics.
  `unmet` to `met` is `improved`, `met` to `unmet` is `regressed`, and a
  different value or objective under the same verdict is `changed`.

Metric values are bounded, declared numbers. They are the only part of the
evaluator output a receipt records. Other `result` content still enters only
`result_digest`.

## Receipt authority and recovery

The canonical `operation.receipt/v1` record is the execution authority:

1. creation atomically binds the manifest digest to one operation ID and writes
   intent, fixed reducer, topological order, and total-budget events;
2. every completed or closed node appends one content-bound verification
   event;
3. cancellation appends one durable intervention event;
4. the fixed gate decision appends the single terminal outcome event.

`chisei_evaluation_executions` contains only the manifest-to-operation index.
It is not a competing run authority. The query projection is reconstructed
from the receipt and revalidates every step and terminal decision digest.
Evaluation receipts accept only internal executor events: the generic external
reporter-authorization and event-reporting RPCs cannot mutate them.

Repeating execution after a disconnect or restart reads the existing receipt,
skips exact completed nodes, and evaluates only missing topologically ready
nodes. Duplicate concurrent attempts append identical event IDs and content;
different content conflicts instead of overwriting evidence. A durable cancel
event is checked before and after evaluator invocation, so cancellation
survives process and replica boundaries. The current pure evaluator thread is
not force-killed; its output is discarded and the step closes as cancelled.

Disabling or superseding an evaluator blocks new plan publication and manifest
resolution but does not invalidate an already resolved manifest. Historical
execution still requires the exact retained definition and an executable
registry entry with its exact implementation digest. A missing adapter
endpoint, shared secret, or operator deployment fails closed as `unavailable`.

## Operations

SQLite creates the execution index during normal startup. PostgreSQL migration
`0026_evaluation_executions.sql` creates the equivalent table and foreign keys
to manifests and operation receipts. Both backends use one transaction for the
initial index/receipt binding and serialize duplicate creation.

Backups must include execution indexes, operation receipts, manifests, plans,
definitions, governed facts, waivers, evidence submissions and retained
envelopes, grants, and audit history from one consistent snapshot. Restore all
of them together; a missing exact dependency fails closed.

Retention must preserve every referenced definition, manifest, evidence item,
and receipt for as long as the execution or a downstream governed decision is
retained. Physical deletion is not a v1 API.

The read-only [evaluation quality trend](evaluation-quality-trends.md)
projection reconstructs these receipts into authorized quality, variance,
regression, and exact-baseline series. It adds no analytics table and never
changes an execution verdict.

Rollback stops new execution RPC traffic or deploys a prior server containing
the required compiled implementation. It does not edit immutable manifests or
receipts. Partially completed receipts remain resumable by a compatible
executor; otherwise they remain readable evidence and correctly do not produce
`allow`.

Metrics expose only evaluator labels (`subject_digest_equality`, the
built-in kinds `exact_match`, `regex_match`, `numeric_range`, `date_range`,
`edit_distance`, `token_overlap`, and `size_bounds`,
`bounded_rubric_score`, `external_adapter`, or `custom_builtin` /
`custom_stochastic` for unlabelled registrations),
version labels, the closed status vocabulary, and latency. They contain no namespace,
subject, evidence identifier, digest, parameter, or content label.

The provider-fake tests run in default CI. The ignored live path can be invoked
when a local model is available:

```bash
cargo test --test it \
  bounded_stochastic_evaluator_records_live_variance_evidence \
  -- --ignored
```
