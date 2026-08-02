# Evaluation execution

`ExecuteEvaluationManifest` executes one exact
`chisei.resolved-evaluation-manifest/v1` through the
established `chisei.deterministic-evaluation-executor/v1` request protocol.
The frozen node execution class selects a separate deterministic or stochastic
registry and execution path; the request identifier is retained for persisted
execution and client compatibility. The manifest digest is the
idempotency identity. `GetEvaluationExecution` returns the receipt-derived
projection, and `CancelEvaluationExecution` durably requests cancellation.

This is situation-specific evaluation, not a generic workflow engine. A plan
still chooses different evaluator definitions, schemas, parameters, inputs,
dependencies, and invariant coverage for each subject or domain. The executor
only supplies bounded acyclic scheduling, exact implementation selection,
closed result states, and the fixed reducer.

## Evaluator boundaries

Evaluator definitions register metadata and an exact implementation digest;
they never upload code. A deployable evaluator is either a compiled Rust
`DeterministicEvaluator` or an operator-deployed `external_adapter/v1` endpoint
registered under that exact digest. The shipped server registers one deliberately
narrow implementation:
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

Rollback stops new execution RPC traffic or deploys a prior server containing
the required compiled implementation. It does not edit immutable manifests or
receipts. Partially completed receipts remain resumable by a compatible
executor; otherwise they remain readable evidence and correctly do not produce
`allow`.

Metrics expose only evaluator labels (`compiled_builtin` or `external_adapter`),
version labels, the closed status vocabulary, and latency. They contain no namespace,
subject, evidence identifier, digest, parameter, or content label.

The provider-fake tests run in default CI. The ignored live path can be invoked
when a local model is available:

```bash
cargo test --test ollama_e2e \
  bounded_stochastic_evaluator_records_live_variance_evidence \
  -- --ignored
```
