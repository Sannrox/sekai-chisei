# ADR 0083: Two-store cutover and recovery contract

- Status: accepted
- Date: 2026-09-17
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/999 (#999)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0065](0065-workflow-action-postgres-parity.md),
  [ADR 0069](0069-operation-correlation.md),
  [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md)
- Research: [999-two-store-implementation-contracts](../research/999-two-store-implementation-contracts.md)

## Context

[ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md) accepts two durable
stores and a reservation protocol. Combined mode still constructs both
services from one `RuntimeDb`. #999 asks for the cutover rules that make that
split implementable without losing admission, budget, idempotency, or receipt
guarantees.

This ADR does not reopen the two-database architecture. It records ownership
exceptions, the migration style, and the recovery fence. The matrices live in
the research note so this record stays a rule set.

## Decision

1. **Own by lifecycle, not prefix.** A table belongs to the plane that can
   atomically commit its authoritative transition. Prefixes (`sekai_*`,
   `chisei_*`) are hints. Workflow action bindings, callbacks, and command
   replay stay with Sekai because [ADR 0065](0065-workflow-action-postgres-parity.md)
   requires one local transaction with the action commit. `RecordDecision`
   rows stay with Sekai as mutation-adjacent audit. Budget reservations,
   evaluation executions, and Chisei operation receipts stay with Chisei.
   Approvals and external-action permits are Chisei decisions; Sekai stores
   only the admission/effect evidence it rechecks at commit.
2. **Offline, restartable relocation.** Do not dual-write production traffic
   across two physical stores. Quiesce writers, copy each owned family into
   the destination store, validate row counts and generation stamps, then
   raise a writer fence that refuses mixed old/new writers. The copy is
   restartable from the last completed family. Online dual-write is rejected
   as the cutover path.
3. **Existing generation and idempotency are enough.** Do not invent a second
   admission protocol. Chisei reserves and records a decision keyed by the
   caller operation identity ([ADR 0069](0069-operation-correlation.md)).
   Sekai admits through `SubmitActionInstance` and commit idempotency.
   Timeout or a missing lookup is not rejection. A reservation stays pending
   until Sekai reports committed or definitely absent after a bounded
   reconcile, then Chisei finalizes or releases. Provider usage already
   incurred stays attributed even when the mutation is rejected.
4. **Receipts stay plane-specific.** Public responses may project both a
   Chisei decision receipt and a Sekai commit receipt under one
   `operation_id`. Neither store copies the other's receipt body. Collision
   scope is `(namespace, operation_id)` on each plane, not a globally unique
   caller string. Payload digest binds separately from the caller identity.
5. **One-sided restore is fenced.** Restoring one store does not resume
   writes. Each store carries a split generation. Combined or split startup
   compares generations; mismatch keeps both stores read-only for mutating
   RPCs until an operator reconcile restamps them. Independent backups are
   not a paired restore set.
6. **Typed handles only.** Chisei persistence traits may exist, but Chisei
   code must not receive `RuntimeDb`, a SQL connection, or Sekai credentials.
   Combined mode still opens two physical stores and uses the same typed
   contract as split mode.
7. **Configuration.** Target variables are separate Sekai and Chisei paths or
   URLs. `DB_PATH` / `DATABASE_URL` remain migration compatibility until the
   relocation Issue lands, then they become refuse-with-guidance.

## Alternatives considered

- **Online dual-write.** Rejected: two write authorities during cutover
  create exactly the mixed-generation failure the fence is meant to prevent.
- **New cross-store transaction coordinator.** Rejected: a third durable
  owner. Reservation plus idempotent commit plus reconcile is the existing
  contract.
- **Move workflow-action tables to Chisei.** Rejected: it would split the
  ADR 0065 local transaction and make action replay a decision-store fact.

## Consequences

Implementation proceeds as dependency-ordered Issues. The first ready slice
([#1004](https://github.com/Sannrox/sekai-chisei/issues/1004)) introduces
typed store handles so Chisei constructors cannot take `RuntimeDb`. Later
slices open two physical stores (#1005), relocate tables behind the writer
fence (#1006), wire reserve/commit/finalize across the typed boundary
(#1007), and add subprocess isolation (#1008) plus one-sided restore tests
(#1009).

Public `SubmitActionInstance` stays the admission RPC. Gateway remains a
fail-closed translator and does not own a third store.

## Validation

- Shared SQLite and PostgreSQL conformance for each store after relocation.
- Combined and split modes pass the same public-API and receipt tests.
- Fault tests: crash after reserve, response loss after Sekai commit,
  duplicate admission, reservation expiry, and one-sided restore fence.
- Startup refuses mutating RPCs when split generations disagree.
