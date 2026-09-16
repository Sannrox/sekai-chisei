# ADR 0081: EvaluateObjectSet dual-reads an in-process object-log library

- Status: accepted
- Date: 2026-09-16
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/941 (#941)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0076](0076-compiling-policy-entry.md),
  [ADR 0080](0080-dual-community-runtime-storage.md)

## Context

`EvaluateObjectSet` today reads the SQL `object_type_index*` projection and
its hop-projection engine. [ADR 0073](0073-source-and-action-objects.md)
already says that index is rebuildable and is not object identity.
[ADR 0066](0066-object-set-evaluate.md) already says a descriptor, page, or
cached set is not authority.

The object log that should own identity lives in
[Sannrox/mikura](https://github.com/Sannrox/mikura). Tag `v0.1.0` is an
in-process Rust library (`Store`, `ObjectSet::evaluate`, property deny-list,
Action append). It is not published to crates.io. A hosted ingest/evaluate
process is mikura's destination, not the current crate.

This clerk owns tenants, policy compile, Action admission, receipts, and the
public `EvaluateObjectSet` RPC. It must not become the object log, and it
must not vendor mikura. The open question is how evaluate should start
reading that log.

`SEKAI_OBJECT_INDEX_DUAL_READ` compares nested-loop and hop-projection
**SQL plans**. That gate is a different surface from a clerk-versus-object-log
comparison.

## Decision

1. **Keep the clerk/object-log split.** This repository remains the clerk.
   Object identity and generations belong to a tagged mikura `Store`. Receipts,
   tenants, and policy compile stay here.
2. **Depend, do not copy.** Take mikura by git tag (`v0.1.0` or a later
   published tag), or by crates.io if that publish exists. No git submodule,
   no nested `crates/mikura`, no path dependency into another checkout.
3. **Library client first.** The first evaluate integration is the in-process
   mikura client. A hosted mikura process is a later operational profile. It
   is not a gate on correctness and is not selected by this ADR.
4. **Fail-closed dual-read before authority moves.** Until a later cutover
   ADR, SQL index writes continue. Evaluate grows an operator-visible
   comparison of the SQL projection against mikura on the same fixture.
   Hop counts, members, and aggregates must match. A mismatch is an error, not
   a silent SQL-only answer. Hidden members stay absent on both sides.
5. **Policy stays compiled here.** [ADR 0076](0076-compiling-policy-entry.md)
   remains the decision point. The clerk projects grants into mikura's
   in-process deny-list. Denied properties stay absent or fail closed; they
   are never guessed. mikura is not principal-aware in `v0.1.0`.
6. **Do not treat mikura as a third clerk store.** Dual community
   control-plane backends stay [ADR 0080](0080-dual-community-runtime-storage.md).
   The mikura log is a different database from `data/sekai.db` /
   `DATABASE_URL`.
7. **Map only what the tagged API can answer.** mikura `v0.1.0` evaluates
   kind hops plus count/sum under a deny-list. Dual-read is valid only for
   that expressible subset. If the descriptor uses grammar mikura cannot
   evaluate, do not compare and do not return a mikura answer: keep the SQL
   path with the comparison gate off, or fail closed. Filters must not be
   dropped to force a match.
8. **This ADR does not cut over writes.** Dual-read is #942. Admitted Action
   apply through `mikura-ingest` is #943. Stopping SQL `object_type_index`
   writes is #944 and needs its own accepted ADR after soak.

## Alternatives considered

- **Library client first (chosen).** The published tag is an in-process
  store. Dual-read can start without inventing a hosted protocol. Hosting can
  wait until mikura publishes that profile.
- **Hosted only.** Rejected: mikura `v0.1.0` is not a service, and hosted
  research is not a substitute for a tagged evaluate API. Waiting would leave
  the SQL projection as the live graph.
- **Keep SQL as the live graph.** Rejected: that contradicts
  [ADR 0066](0066-object-set-evaluate.md) and
  [ADR 0073](0073-source-and-action-objects.md). An explicit no-action would
  freeze a projection as identity.

## Consequences

#941 closes with this read-path rule. #942 may add the git-tag dependency
and the fail-closed dual-read. #943 may write admitted Actions through
`mikura-ingest` without moving admission here. #944 may retire SQL object
authority only after soak evidence and its own ADR. Query-engine flags
(`SEKAI_OBJECT_INDEX_ENGINE`, `SEKAI_OBJECT_INDEX_DUAL_READ`) stay SQL-plan
gates until #942 documents a distinct object-log comparison.

## Validation

- This repository has no nested mikura tree and no path dependency on one.
- When #942 lands, a forced member/hop/aggregate mismatch fails closed and
  hidden rows appear on neither side.
- Clerk storage selection remains `SEKAI_DB_BACKEND=sqlite|postgres`.
- Revisit a hosted profile only after mikura publishes a hosted tag or API
  that preserves fail-closed property absence on the wire.
