# Domain context

## Schema definition

The **Schema definition lifecycle** loads, repairs, validates, persists, and
converges runtime ObjectType definitions through one private interface. It owns
the process-local registry, global and per-kind load failures, computed-property
function validation, durable writes, and cache repair.

Object mutation, Action execution, ontology mapped-kind ensure, capability
discovery, and the gRPC adapter consume domain snapshots rather than registry
locks. Definitions are refreshed before schema-governed writes so multiple
runtime instances converge on durable state. Schema history and implicit
versioning remain outside this lifecycle.

## Evidence admission

The **Evidence admission lifecycle** admits externally produced Evidence
through one private ordered path. It owns durable admission, execution-evidence
validation and rejection, graph projection, execution recording, and final
durable-state resolution.

Producer adapters own caller authentication and protocol translation. The gRPC
adapter also refreshes its process-local grant cache from the lifecycle outcome.
PostgreSQL community rejection and execution recording remain explicitly
unsupported rather than implying backend parity.

## Ontology definition

The **Ontology definition lifecycle** creates and deletes runtime classes and
relations through one private ordered path. It owns reference visibility,
mapped schema-kind ensure, deterministic definition validation, audited
persistence, and durable plus cached grant cleanup.

The gRPC adapter owns caller authentication and protocol translation. Portable
ontology import/export remains separate. Relation cardinality remains advisory,
and ontology entailment remains bounded at query time.

## Semantic retrieval

The **Semantic retrieval lifecycle** produces one authorization-filtered,
bounded context result from authenticated roots and reasoning constraints. Its
private interface owns retrieval parsing, the immutable visible ontology
snapshot, query-time entailment, denial normalization, computed-property
resolution, epistemic descriptors, and canonical result projection.

The gRPC adapter owns caller authentication, capability-catalog attribution,
namespace-specific expansion and explanation projection, and protocol metadata.
PostgreSQL community retrieval remains asserted-only.

## Policy resolution

The **Policy resolution module** produces one permitted route or denial from
authenticated routing input. Its private interface owns policy-scope
precedence, regression and promoted-capable safeguards, privacy and capability
gates, explicit route overrides, local-free, cheap, and portfolio selection,
runtime canonicalization, and fallback projection.

The gRPC adapter owns caller authentication and protocol translation. Gateway
execution and other authenticated callers cross the same domain seam without
manufacturing transport requests.

## Native execution planning

The **Native execution planning pipeline** produces one executable or denied
plan from authenticated execution input. Its private interface owns Kioku
context enrichment, policy and provider resolution, budget and evaluation
gates, routing, egress and privacy decisions, sampling, audit, and plan
projection.

The gRPC adapter owns authentication, optional Gunshi allocation binding, and
protocol translation. Gunshi allocation precedes planning; Kioku enrichment
remains inside the planning pipeline.

## Evaluation execution

The **Evaluation execution lifecycle** executes and cancels one resolved
Evaluation manifest through one private ordered path. It owns durable creation
and replay, frozen execution budgets, evaluator availability, per-manifest
serialization, cancellation state and persistence, worker dispatch, Evidence
loading, step and gate receipt ordering, recovery, and terminal cleanup.

The gRPC adapter owns caller authentication, namespace authorization, manifest
lookup, and protocol translation. Deterministic and stochastic evaluators keep
their separate execution classes, external evaluators remain behind their
registered adapter seam, and the canonical operation receipt remains the
durable authority.

## Object mutation

The **Object mutation lifecycle** creates, updates, and deletes Objects through
one private ordered path. It owns tenant and namespace admission, optional
generation-fenced lease validation and replay, marking and schema enforcement,
direct or guarded persistence, principal-profile grants, and response
resolution.

The gRPC adapter owns protocol request and response translation. The lifecycle
selects the direct or guarded persistence adapter behind its private interface.

## Handoff

A **Handoff** is a versioned, immutable manifest that transfers bounded context
references between two principals without copying content or granting access.
It binds one namespace scope, receiving principal, purpose, expiry, lineage,
and any references omitted because of policy, retention, or availability.

The **Handoff lifecycle** creates and revokes Handoffs. Creation validates the
creator binding, manifest invariants, replay identity, timestamp window,
reference availability, and predecessor compatibility before durable storage.
Revocation is creator- or administrator-authorized and idempotent.

Resolution is separate: the receiver's current access is rechecked when a
Handoff is resolved. See `docs/architecture.md#governed-context-handoffs`.

## Action Work

**Action Work** is runtime-dispatch work materialized from an admitted governed
ActionInstance effect. Hosts claim it with a generation-fenced lease, heartbeat
that claim, acknowledge completion or failure, or park it with checkpoint
metadata until an authorized continuation is supplied.

The **Action Work lifecycle** lists claimable work, claims and heartbeats
runtime claims, acknowledges terminal or parked outcomes, records host claim
events, projects receipt harvest events, and records audit decisions after
durable persistence.

## Action execution

## Catalog invocation receipt lifecycle

The **Catalog invocation receipt lifecycle** records one capability-catalog
attributed invocation from its pending intent through policy, routing, budget,
approval, action, and terminal outcome events. It preserves the original start
time, records uncovered decision surfaces for early failures, fails closed when
an invocation exits without explicit completion, and continues held invocations
after an approval decision.

The gRPC adapter owns request metadata, caller authentication, live capability
visibility, and response metadata. The receipt lifecycle owns durable event
ordering and completion semantics behind one private interface.
