# Deterministic evaluation execution

`ExecuteEvaluationManifest` executes one exact
`chisei.resolved-evaluation-manifest/v1` through the
`chisei.deterministic-evaluation-executor/v1`. The manifest digest is the
idempotency identity. `GetEvaluationExecution` returns the receipt-derived
projection, and `CancelEvaluationExecution` durably requests cancellation.

This is situation-specific evaluation, not a generic workflow engine. A plan
still chooses different evaluator definitions, schemas, parameters, inputs,
dependencies, and invariant coverage for each subject or domain. The executor
only supplies bounded acyclic scheduling, exact implementation selection,
closed result states, and the fixed reducer.

## Compiled evaluator boundary

Evaluator definitions register metadata and an exact implementation digest;
they never upload code. A deployable evaluator is a compiled Rust
`DeterministicEvaluator` registered under that exact digest. The registry
contains only implementations compiled into the server or installed by its
embedding product integration. The shipped server registers one deliberately
narrow implementation:
`subject_content_digest_equals/v1`
(`sha256:83df0fa4577447ecf2a7817c49d637ab48a018fb2d72a9fd631ce76d89f6e475`).
It accepts only that invariant predicate and exactly one
`expected_content_digest` parameter, then compares it with the manifest-bound
subject content digest. It is not a fallback and cannot evaluate other
situations. An unmatched digest produces `unavailable`; the executor never
chooses a fallback or a newer definition.

Each implementation receives one canonical input document containing:

- the exact manifest and node identity;
- the opaque subject identity and content digest, without a subject payload;
- canonical parameters and invariant verification contracts;
- exact retained evidence content selected by the manifest; and
- exact dependency result digests.

It receives no runtime capability object, network client, clock, randomness,
filesystem handle, process environment, locale, timezone, model/provider
client, or action authority. Implementations remain operator-controlled
compiled code and must pass the conformance harness. The harness repeats
golden manifests in child processes with different timezone, locale, and hash
seed settings, and checks identical semantic receipt bytes.

Evaluator output content is ephemeral. It is bounded and hashed, then
discarded. The API and durable receipt expose only status, a bounded reason
code, exact input/parameter/evaluator/evidence/dependency digests, the result
digest, and the step-receipt digest. Evidence or result content is not
returned.

## Closed execution and reduction

Ready nodes run sequentially in deterministic topological order with
`node_id` as the tie-breaker. V1 has no parallel scheduler, loop, dynamic
node, expression, script, action, deployment, model call, or caller-selected
reducer.

Step status is exactly one of:

- `pass`, `fail`, or `unknown` from a valid deterministic evaluator;
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
output bytes, and evidence-item count. The first request may lower total
duration; zero selects 60 seconds and the hard maximum is 300 seconds. That
budget is frozen in the initial receipt, includes time across disconnects and
restarts, and cannot be reset by replaying the request. A timed-out compiled
evaluator runs on an isolated thread with no supplied effects or capabilities;
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
execution still requires the exact retained definition and a compiled registry
entry with its exact implementation digest.

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

Metrics expose only compiled static evaluator labels, compiled static version
labels, the closed status vocabulary, and latency. They contain no namespace,
subject, evidence identifier, digest, parameter, or content label.
