# ADR 0081: Keep Chisei depending on Sekai in one process

- Status: accepted
- Date: 2026-09-16
- Owners: @Sannrox
- Discussion: none
- Issue: none
- Supersedes: none
- Superseded by: the one-process / do-not-split-servers clauses in
  [ADR 0082](0082-two-local-servers.md)
- Related: [ADR 0008](0008-gateway-is-a-fail-closed-translator.md),
  [research 443](../research/443-kernel-extension-boundary.md)

## Context

Sekai owns durable facts. Chisei owns governed decisions. Those are separate
items connected by a one-way composition: Chisei sits on Sekai. Several
admission and lifecycle modules lived under `src/sekai` while importing
budget, receipt, and permit types from Chisei, so the items were conceptually
separate and cyclically coupled.

Extracting two crates or processes while that cycle remains would freeze the
tangle as a public contract. Research 443 already rejected moving `sekai/*`
and `chisei/*` into two crates while sharing DB and gRPC.

## Decision

1. **One published product, one-way facts seam.** `sekai-chisei` remains the
   in-tree control plane while the extract lands. ADR 0082 splits the local
   servers; this ADR still forbids reverse `src/sekai` → `crate::chisei`
   imports and Chisei sibling `sekai::*` imports.
2. **One-way module direction.** Chisei may import Sekai only through
   `sekai::facts`. `src/sekai` must not import `crate::chisei`. Wiring
   (`src/grpc`, `src/db`, CLI) may use both. Shrink `facts.rs`; do not add
   sibling `sekai::*` imports from Chisei.
3. **Admission is a Chisei decision.** Action instance admission, Action Work
   lifecycle, workflow-action bridging, object-bound describe/preview, and
   host execution-evidence helpers live under `src/chisei`. They persist
   through Sekai facts.
4. **Shared parameter-schema validation is a Sekai contract.** The closed v1
   JSON subset used by Action types and evaluation plans lives in
   `sekai::parameter_schema` so type persistence does not import Chisei.
5. **Chisei without a facts seam is out of scope.** A later adapter may
   implement the same Sekai facts interface (including a future Mikura-backed
   clerk). Chisei does not become a standalone policy sidecar.

## Alternatives considered

- **Two crates or repos now.** Rejected: same cycle plus lockstep versions and
  shared migrations. A workspace crate is a rename after this DAG is true.
- **Two gRPC processes.** Deferred to [ADR 0082](0082-two-local-servers.md)
  once persist is one Sekai transaction. ADR 0081 only required the one-way
  module DAG first.
- **Leave reverse imports.** Rejected: that is the maintainability defect.

## Consequences

- In-crate Rust paths such as `sekai_chisei::sekai::workflow_action` move to
  `sekai_chisei::chisei::workflow_action`. gRPC, receipts, and persistence
  contracts are unchanged.
- `src/sekai/mod.rs` carries a layering test that fails if Sekai imports
  Chisei. `src/chisei/mod.rs` fails if Chisei imports Sekai except through
  `sekai::facts`.
- A future crate split still requires the extraction gates in research 443.

## Validation

- `sekai_modules_do_not_import_chisei` and
  `chisei_imports_sekai_only_through_facts` must pass.
- Action admission, Action Work, workflow-action, describe/preview, and
  execution-evidence tests continue to cover the moved modules.
- Public proto and receipt bytes stay unchanged.
