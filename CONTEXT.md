# Domain context

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

## Action execution admission

**Action execution admission** is the ordered, pre-effect phase of legacy
governed Action execution. It resolves live targets, enforces target,
classification, purpose, namespace, and schema constraints, and freezes the
governed policy context before dry-run, approval, denial, limit checks, or
effect execution can proceed.

The gRPC adapter owns caller authentication, capability-catalog correlation,
and protocol response metadata. Admission trusts the authenticated principals,
not the actor supplied inside the protocol request.

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
