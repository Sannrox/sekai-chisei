# ADR 0175: The plane stores connector credentials sealed to the runtime fleet key

- Status: accepted
- Date: 2026-11-27
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3553 (#3553)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0148](0148-sources-and-one-connector-runtime.md) decision 4

## Context

ADR 0148 keeps credentials with the connector runtime: handles are a static
map in its configuration, each bound to namespaces and destinations, read
once at start. A slot's value is read per claim, so rotation works, but a new
handle needs a rewritten file and a restart of every runtime. ADR 0148 names
plane-held credentials sealed to a runtime key as a possible later extension.

A key held by one runtime instance does not survive that instance's
replacement, so sealing to a per-instance key would lose every handle on
reprovisioning.

## Decision

1. **A fleet key.** The deployment layer gives every connector runtime the
   same private key (X25519), by file or environment, as it gives any other
   secret. The plane holds only the public half, registered by an operator
   with a key id. Several key ids may be registered at once, for rotation.
2. **Sealed at the client.** `sekaictl` seals each slot value to a
   registered public key before sending it. The plane receives, stores and
   returns only sealed bytes and the key id, so plaintext never reaches the
   plane, its audit or its backups.
3. **Issue and revoke are plane calls.** `IssueCredentialHandle` stores a
   handle: name, binding (namespaces and destinations) and sealed slots.
   `RevokeCredentialHandle` deletes the sealed slots and keeps a tombstone.
   Both require platform admin, not namespace admin, so the binding stays an
   operator bound: a namespace administrator can name a handle but cannot
   create or widen one. Both write an audit event with no slot content.
   Issue is idempotent per handle name and content digest.
4. **Resolved per claim.** When a claim names a plane handle, the claim
   response carries its binding and sealed slots. The runtime checks the
   binding as today and opens the slots with its fleet key. A revoked,
   unknown or unopenable handle is `unavailable`, as in ADR 0148, and is not
   retried in a loop.
5. **Static handles keep working.** A name present both in the runtime's
   configuration and on the plane is refused as ambiguous, fail closed,
   rather than letting either win.
6. **Stored format.** A `sekai_credential_handle` table and a
   `sekai_runtime_fleet_key` table on SQLite and PostgreSQL. Older planes do
   not read them.

## Alternatives considered

- **Runtimes share a handle store outside the plane.** Rejected: a second
  durable system for the operator to run, with its own issuance and audit.
- **Seal to a per-instance runtime key.** Rejected: replacing the instance
  loses every handle.
- **Plane holds plaintext, encrypted at rest with a plane key.** Rejected:
  the plane could read every credential, which ADR 0148 rules out.
- **Namespace admins issue handles for their own namespace.** Deferred: it
  needs an operator-held egress allowance to bound destinations, which does
  not exist yet.

## Consequences

- Adding a handle needs no restart and no file change.
- Losing the fleet private key makes every plane handle unopenable; the
  operator re-issues them under a new key. Backups of the plane alone never
  expose credentials.
- An older runtime in a mixed deploy does not understand plane handles and
  fails those Sources as `unavailable`, visibly; static handles keep working.
- Rollback leaves the tables in place, unread; Sources naming plane handles
  fail as `unavailable` until re-pointed at static handles.

## Validation

On a running plane with two runtimes sharing a fleet key: a handle issued
while a sync is in flight is used by the next claim without a restart;
replacing a runtime mid-claim leaves the handle resolvable; a revoked handle
fails the next claim as `unavailable`; the stored row, audit and claim logs
contain no plaintext; a name defined in both places is refused.
