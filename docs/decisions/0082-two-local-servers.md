# ADR 0082: Two local servers, one Sekai database

- Status: accepted
- Date: 2026-09-16
- Owners: @Sannrox
- Discussion: none
- Issue: https://github.com/Sannrox/sekai-chisei/issues/956
- Supersedes: the one-process / do-not-split-servers clauses of
  [ADR 0081](0081-chisei-depends-on-sekai.md)
- Superseded by: none
- Related: [ADR 0008](0008-gateway-is-a-fail-closed-translator.md),
  [ADR 0081](0081-chisei-depends-on-sekai.md),
  [research 443](../research/443-kernel-extension-boundary.md)

## Context

Sekai is the Foundry-shaped clerk (objects, Actions persist, ACL, audit).
Chisei is the AIP-shaped platform (policy, model route, admit/deny). ADR 0081
broke the import cycle and kept one process so admission and persist could
commit together. The product cut is now two local monoliths: Chisei routes;
Sekai only reads and notes new data. Palantir AIP is a feature on a Foundry
enrollment, not a standalone operational store. Chisei without a Sekai
endpoint is a model mesh, not AIP’s effect.

Discussion 906 still rejects a hosted mesh. Both servers default to loopback.

## Decision

1. **Two local gRPC servers.** `sekai` serves `SekaiService`. `chisei` serves
   `ChiseiService`. Combined `sekai-chisei` remains the compatibility process.
2. **One Sekai database.** Chisei has no SQLite or PostgreSQL. Durable policy,
   receipts, evals, budget counters, and learnings are Sekai facts.
3. **Chisei is a gRPC client of Sekai.** `CHISEI_SEKAI_ENDPOINT` is required in
   the Chisei plane. Sekai never calls Chisei.
4. **Routing is Chisei.** AI and Action-invoke traffic hits `ChiseiService`
   first (`InvokeActionInstance`, plan/execute). Sekai
   `PersistAdmittedAction` commits instance, effect, audit, and receipt in one
   transaction. `SubmitActionInstance` stays as the in-process compatibility
   path.
5. **Reads then notes.** Chisei asks Sekai for objects and Action types on the
   request, then writes outcomes back. Model choice is recomputed on each
   request from policy, live providers, budget, and adopted learnings.

## Alternatives considered

- **Keep one process forever (ADR 0081).** Rejected for product independence.
  The one-way facts seam remains the in-crate rule until extract.
- **Two databases.** Rejected: a second SoR.
- **Chisei without Sekai.** Rejected: that is k-LLM, not AIP.
- **Hosted mesh.** Rejected: Discussion 906.

## Consequences

- Operators start Sekai, then Chisei with `CHISEI_SEKAI_ENDPOINT`.
- Combined mode still opens one `RuntimeDb` and both services.
- This repository remains the implementation SoR. `sekai` and `chisei`
  binaries prove the two-process cut; compose is the operator map.
- Client-facing Action invoke moves to Chisei. Persist stays on Sekai.

## Validation

- `tests/two_process_planes.rs` starts both loopback servers, reads an object
  menu, invokes through Chisei, and reads the receipt from Sekai-backed
  storage.
- Layering tests from ADR 0081 still pass in this tree.
- Chisei plane must not open `RuntimeBackend`.
