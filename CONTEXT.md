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
