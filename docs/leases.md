# Generation-fenced leases

Sekai exposes namespace-scoped leases for coordinating one active owner of a
logical key. Acquire returns both a monotonically increasing `generation` and
a unique `fencing_token`. Release keeps the key and its audit history, so a
later acquire creates a new generation rather than reusing an object identity.

Multi-region write topology is out of scope for the current single-region
lease store. The design freeze for region/site pins and fail-closed foreign
pins is [research/292-multi-region-consistency.md](research/292-multi-region-consistency.md)
(implementation: #293).

## Object-bound lease keys

To coordinate mutations against an **existing object** without letting unrelated
namespace writers squat the coordination identity, use the key form:

```text
object:<object_id>
```

Object-bound keys (see [ADR 0005](decisions/0005-object-bound-coordination-leases.md)):

- must be spelled exactly `object:<object_id>` (no extra whitespace);
- require the target object to exist;
- require the lease namespace to equal the object namespace;
- require **object write** for acquire, refresh, release, and takeover;
- require **object read** for `GetLease`;
- when used as a `LeasePrecondition`, must match the mutation target object id
  (and cannot guard object creation);
- after a successful guarded delete of the target, `ReleaseLease` remains
  authorized with namespace write so the coordination row can be cleaned up
  even though the object identity cannot be recreated.

Free-form keys remain available for non-object coordination and continue to use
namespace authorization only.

Use a unique `request_id` for each intended operation and reuse it unchanged
after an ambiguous transport failure. Reusing it with different input is an
error. Refresh and release require the active fencing token. Expired leases are
not implicitly replaced: takeover requires the exact token and expiry observed
by the caller, and the server decides whether that expiry has passed using its
own clock.

`GetLease` returns the current active or released record to principals with
namespace read access. Contenders use it to observe the exact token and expiry
required by takeover after an owner crash. The fencing token is not a bearer
credential: every mutation still requires namespace write authorization, and
the server verifies that the token names the active generation.

The control plane prevents an old generation from changing current lease state,
but it cannot stop work that has already left the control plane. Clients must
persist the returned generation with their durable attempt and pass it to every
downstream mutation executor. Each executor must remember the highest
generation accepted for the protected resource and reject commands carrying a
lower generation. A fencing token alone is sufficient for Sekai RPCs; the
monotonic generation is the downstream ordering primitive.

Lease transitions and retry results are stored durably with the active record.
Acquire, refresh, release, and takeover are committed atomically with their
transition audit entry. The current server persistence path is SQLite; the
partial PostgreSQL interfaces do not yet implement this API.

## Lease-guarded object mutations

Use `GuardedCreateObject`, `GuardedUpdateObject`, or `GuardedDeleteObject` when
an object transition is owned by a lease generation. Each request includes a
`LeasePrecondition` containing the lease namespace, logical key, opaque fencing
token, and a unique `request_id`. The caller must have write access to both the
target object namespace and the referenced lease namespace; possession of a
fencing token does not grant authorization.

Sekai validates that the token identifies the active, unexpired generation and
commits that validation, the object mutation, normal object-change audit, and
the mutation retry record in one SQLite immediate transaction. This serializes
the mutation against refresh, release, and takeover: either the mutation
commits first, or the lease transition commits first and the mutation fails
with `FAILED_PRECONDITION`. Stale, replaced, released, and expired tokens never
change object state.

Reuse the same `request_id` and identical request after an ambiguous transport
failure. Sekai returns the committed result without repeating the mutation or
its audit rows. Reusing a request ID with different input fails. A new intended
mutation must use a new request ID. Guarded update and delete return `NOT_FOUND`
when the first attempt targets a missing object; a replay of a successfully
committed delete remains successful even though the object is gone.

Guarded mutation audit records the lease namespace, key, generation, actor,
operation, target, and request digest. It does not retain the reusable fencing
token. Unguarded object RPCs retain their existing behavior. The partial
PostgreSQL object interfaces do not expose guarded operations and therefore
fail closed rather than performing a non-atomic lease check.
