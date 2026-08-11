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
