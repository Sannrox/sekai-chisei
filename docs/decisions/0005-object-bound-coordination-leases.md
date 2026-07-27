# ADR 0005: Object-bound coordination leases

- Status: accepted
- Date: 2026-07-26
- Owners: @Sannrox
- Discussion: GitHub Discussions unavailable; fallback ADR for #202
- Supersedes: none
- Superseded by: none

## Context

Integrations need to serialize mutations against an existing Sekai object without
weakening object ACLs. Free-form namespace lease keys (ADR-era lease API)
support generation fencing and guarded mutations, but a principal with only
namespace write access could still squat an arbitrary key that collides with a
coordination identity others treat as object-scoped.

Issue #202 requires authorization through the target object: a principal lacking
access must not acquire, inspect, refresh, release, or squat that coordination
identity.

## Decision

1. Keep the existing generation-fenced lease API (`AcquireLease` / `GetLease` /
   `RefreshLease` / `ReleaseLease` / `TakeoverExpiredLease`) and guarded object
   mutations as the coordination primitives.
2. Treat lease keys with the prefix `object:<object_id>` as **object-bound**.
   For those keys:
   - the target object must exist;
   - the lease namespace must equal the object namespace;
   - mutate paths require object write authorization;
   - inspect (`GetLease`) requires object read authorization.
3. Free-form keys remain available for non-object coordination and continue to
   use namespace authorization only.
4. Object-bound checks apply on every backend that implements the lease API
   (SQLite and PostgreSQL community runtimes). Incomplete backends fail closed
   rather than skipping the object-bound checks.

## Alternatives considered

- **New RPC with `target_object_id` field.** Clearer, but duplicates fencing
  semantics already shipped; deferred until a protocol revision needs it.
- **Mutable CAS fields on the object.** Would require `UpdateObject` CAS that
  does not exist and pollutes object audit with coordination noise.
- **Fixed lease object ID.** Conflicts with immutable object-change history after
  delete/recreate (rejected in #202).

## Consequences

- Callers coordinating on object `O` use key `object:O` and must hold write on
  `O` (and matching namespace).
- Squatting is blocked for object-bound keys even for namespace editors who lack
  the object grant.
- Documentation in `docs/leases.md` describes the prefix contract.

## Validation

- gRPC tests: unauthorized acquire/get denied; authorized acquire/release and
  re-acquire after release; missing object fails closed; namespace mismatch
  fails closed; non-canonical keys rejected; object-bound preconditions cannot
  guard a different object.
- Existing lease concurrency, fencing, and guarded mutation tests remain green.

## Residual risk

Object ACL/namespace checks are applied before lease persistence (and acquire
re-checks existence after). Fully atomic ACL+lease mutation would require
folding object authorization into the SQLite lease transaction; that is
follow-up work if concurrent object moves/ACL revocation during acquire become
an observed threat model.
