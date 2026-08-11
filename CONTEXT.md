# Domain context

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

**Action execution** is the ordered lifecycle for one legacy governed Action.
It resolves live targets; enforces target, classification, purpose, namespace,
schema, policy, budget, and blast-radius constraints; and owns dry-run,
approval hold, denial, effect execution, audit, metering, and Catalog invocation
receipt completion.

The gRPC adapter owns caller authentication, capability-catalog correlation,
live capability visibility, and protocol response metadata. Action execution
trusts the authenticated principals, not the actor supplied inside the protocol
request.

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
