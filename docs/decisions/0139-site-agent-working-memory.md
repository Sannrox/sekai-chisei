# ADR 0139: Site agent working memory is governed objects the instance writes

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Issue: #1612, read path in #1968
- Related: [ADR 0136](0136-site-agent-instances.md),
  [ADR 0137](0137-agent-turns-share-the-scheduling-split.md), #1403, #1465,
  #1706

## Context

A site agent instance (ADR 0136) wakes many times. It needs durable notes
across wakes, such as "valve 3 sticks after a restart". Two memories already
exist, and neither fits:

- **Kioku** is epistemic memory Chisei derives from operation outcomes. The
  instance does not write it, and its ceiling is a namespace grant, not a
  marking on each note.
- **Decision memory** (#1465) keeps precedents of parked reviews for
  reviewers. It belongs to a review, not to an agent.

Working memory must be owned by one instance, carry markings like any other
fact, be forgettable with an audit trail, and never let an agent surface a
note the person it acts for cannot read.

## Decision

1. **Working memory items are governed objects** of kind
   `site_agent_memory` (`sekai.site-agent-memory/v1`), bound to one instance
   by `instance_id`. They change only through the governed Actions
   `site_agent.memory.create`, `site_agent.memory.update` and
   `site_agent.memory.forget`, which leave receipts. Direct object writes,
   streaming edits and direct deletes are refused, as for instances, and an
   item a caller may not read answers as a missing object.
2. **Only the instance's own principal writes its memory.** An item never
   moves to another instance. A frozen instance writes none: admission refuses
   its principal's Actions (#1934), and the write itself refuses a frozen
   instance, so a write parked before the freeze does not land after it.
3. **Markings work as for any Action-written object.** An item carries the
   marking its Action was admitted under and can only be raised. The writer's
   clearance gates what it may write (#1706).
4. **Forget is an update.** Actions have no delete mutation, so the forget
   Action empties `content` and sets `forgotten`. A forgotten item is never
   written again and leaves future context. Earlier values stay in the change
   history, where `content` has a restricted (`sensitive`) property
   classification so only object admins read it, and in the parameters of
   the Actions that wrote them, readable by whoever may read those Actions.
   Erasing both needs new store work and is #1969.
5. **Reads intersect the agent and its requester** (#1968). An agent reads its
   memory through an experimental RPC that returns an item only when the
   instance principal and the requester can each read it on their own. The
   requester is the delegating user (`act`) of the calling token, otherwise
   the caller. Operators inspect and export memory through the existing
   object reads and `ExportObjectSet`, which needs the namespace export grant,
   checks markings per row, and writes a receipt.
6. SQLite is the reference store, as for instances (ADR 0136). PostgreSQL
   refuses memory writes until a parity slice.

## Alternatives considered

- **Store working memory in Kioku.** Rejected: Kioku is derived by Chisei, has
  no per-note marking, and no instance owns it.
- **A delete mutation for forget.** Rejected for now: Actions write by create
  and update, and a removed object would also drop the receipt's subject. An
  emptied, flagged item keeps the audit trail.
- **Any principal with namespace write may write an instance's memory.**
  Rejected: another principal could plant notes the agent then trusts.

## Consequences

`install` registers the kind and its Actions, as for instances, and is not yet
wired into boot. The freeze and ownership checks run when a write is planned
and again inside the transaction that commits it (#1970), so a freeze or
principal change committing in between denies the write with a receipt. The
direct-write guards cover both kinds through one helper.
Until #1968 lands, agents have no dedicated read path.

## Validation

Crate tests cover:

- a write by another principal refused, and the instance principal's write
  admitted with a receipt;
- forget emptying the item, refusing a later update, and leaving a receipt,
  with `content` restricted;
- a frozen instance writing no memory, also for a write parked before the
  freeze;
- an item keeping its marking when a lower one is submitted.
