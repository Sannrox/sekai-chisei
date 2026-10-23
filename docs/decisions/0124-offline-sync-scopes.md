# ADR 0124: Offline sync scopes diff stored members per cursor

- Status: accepted
- Date: 2026-10-23
- Issue: #1632

## Context

Clients that work offline need a bounded, governed replica: a snapshot of a
named object set, then the changes since. The object change feed (ADR 0068)
gives change events without bodies and needs the client to list objects
itself. A replica must also learn when an object leaves its set: it moves
out of the filters, a link to it goes away, or the caller loses access.

## Decision

1. **A scope is a principal's definition.** `PutSyncScope` stores, under the
   caller:
   - one kind with up to four property filters;
   - optionally the objects linked to the matches by one relation, up to two
     hops;
   - an object quota of at most 5000.

   Changing the definition drops its cursors.
2. **Members are computed with the online read checks.** Matches come from
   the marked, policy-filtered object list and are then checked for grants.
   Linked objects join only if they are readable, in the same namespace, and
   not of a reserved kind. More visible members than the quota is
   `RESOURCE_EXHAUSTED`, naming the scope and its `max_objects`.
3. **A cursor names a stored position.** A position holds:
   - an authorization pin: the object policy activation, the caller's
     principals and the scope definition;
   - the visible members, each with a fingerprint of the object as the
     caller read it.

   Its id is a digest of that content. Positions are rows on both backends,
   so any instance can continue a client's sync. A definition change or a
   policy change makes the pin stale.
4. **Snapshots page stored members.** A new snapshot stores the members and
   retires the scope's other cursors in one transaction: one replica per
   principal and scope. Pages walk the members in object id order, so a
   resumed snapshot has no duplicates or gaps. The last page returns the
   cursor. Each page records what it actually delivered, including objects it
   could no longer send. When two answers to the same page disagree, the
   object is marked ambiguous and the next delta resends it.
5. **Deltas diff fingerprints.** A delta read compares what the client holds
   with the current members.
   - Objects that joined or now read differently (a property, a computed
     value, a property grant) are sent whole, up to `limit` changes per read
     counting removals.
   - Objects that left, were deleted or became hidden are listed for
     removal.
   - The first read of a cursor fixes which changes its answer covers, so a
     retry covers the same ones. An object that can no longer be sent
     becomes a removal.
   - Each answer gets its own cursor holding exactly what it sent. Reading a
     cursor retires the cursor it came from and that cursor's other answers,
     never anything newer.
   - A stale pin or an unknown cursor means `resnapshot_required`.

   Deltas do not depend on the change log, so its retention never forces a
   new snapshot.
6. **Objects leave only as an online read shows them.** Every object is
   projected per property for the caller. Hidden objects and properties
   never leave the server.
7. **Versioned.** Every request names `contract_version: sekai.sync/v1`, and
   every response echoes it.

## Consequences

- Each delta read recomputes and projects the members, bounded by the
  quota.
- Link changes and access changes show up as removals at the next delta
  read, even when no object in the scope changed.
- Revocation purge on the device, device binding and client-side policy are
  out of scope.

## Rejected alternatives

- Reusing the change feed's bodiless events: the client would still list
  objects, could not learn about removals through links, and would miss
  computed values that change without their own mutation.
- A client-held membership list: hidden ids would have to leave the server
  for the client to diff.
