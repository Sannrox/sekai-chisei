# ADR 0096: Sekai runs without Chisei; Chisei requires Sekai

- Status: proposed
- Date: 2026-10-07
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1293 (#1293)
- Supersedes: [ADR 0092](0092-chisei-builds-without-sekai.md)
- Superseded by: none
- Related: [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md),
  [ADR 0083](0083-two-store-cutover-and-recovery.md),
  [ADR 0084](0084-system-one-action-function.md)

## Context

ADR 0092 made Chisei the base layer: Chisei builds and runs without Sekai, and
Sekai may import Chisei. The product direction is the reverse. Sekai holds
durable facts, ontology, and governed Actions, and is useful on its own.
Chisei governs decisions about context, policy, budgets, routing, and
evaluation; its distinctive value (context admission with provenance,
governed Actions, receipts tied to Sekai facts) depends on Sekai. A
Chisei-only offering would mostly overlap existing LLM gateways.

Supporting Chisei without Sekai has a recurring cost: a `NotAttached` outcome
in `SekaiFactReader`, handling for it in the gRPC service, composition, and
pipeline, a Chisei-only configuration in the plane test matrix, and shared
vocabulary owned by Chisei that Sekai re-exports.

Requiring Sekai is cheap here. Combined mode is one binary that already opens
both stores.

## Decision

1. **Sekai never depends on Chisei.** Code under `src/sekai` does not name
   `crate::chisei::*`, Chisei store handles, or Chisei SQL.
2. **Sekai owns the ports Chisei fills.** Cross-plane behavior Sekai needs
   (budget on Action admission and workflow steps, System One fill
   provenance, Chisei decision fields on receipts) goes through Sekai-owned
   traits. Chisei implements them; composition wires them. An absent port
   reports an explicit outcome, such as budget `not_configured`; it never
   allows silently.
3. **Chisei may depend on Sekai's code, not on Sekai's state.** Chisei uses
   Sekai types and pure functions directly. Chisei never opens the Sekai
   store (ADR 0082). Sekai state reaches Chisei through a trait with an
   in-process implementation for combined mode and an authenticated remote
   implementation for a separate Chisei process.
4. **Chisei requires Sekai.** A Chisei process without an attached Sekai
   refuses to boot. Chisei code has no not-attached branch. A gateway-only
   deployment is combined mode with an otherwise empty Sekai.
5. **Shared vocabulary lives in Sekai.** The decision record and filter, the
   hash-chained decision-ledger append, `RiskClass`, `ActionPolicy`, the
   object schema, evidence and capacity vocabularies, the parameter schema
   validator, and the duplicate-key JSON check move from `src/chisei` to
   `src/sekai`. There is no neutral kernel.
6. **Adapters live on the dependent side.** Mapping Sekai roles, grants,
   Action types, and evidence into Chisei types is Chisei or composition
   code. `src/sekai/chisei_principal.rs` and `src/sekai/chisei_projection.rs`
   move out of Sekai.

### Disposition of current Sekai -> Chisei edges

| Sekai use of Chisei | Disposition |
| --- | --- |
| `decision_ledger`, `risk_class`, `action_policy`, `capacity`, `evidence_vocabulary`, `object_schema`, `json`, `evaluation_plan` parameter schema validation, `external_permit::DEFAULT_SITE_ID` | Move into Sekai (rule 5). |
| `budget::BudgetTracker` in Action admission, describe preview, and workflow steps | Sekai-owned budget port, implemented by Chisei (rule 2). |
| `system_one_action` fill provenance and proposed parameters | Sekai-owned proposal port; System One stays a Chisei Function (rule 2, ADR 0084). |
| `receipt`, `external_action`, `external_permit` in admission, work lifecycle, execution evidence, peer import, and workflow steps | Sekai receipts and permits stand alone; Chisei decision fields attach through a Sekai-owned extension (rule 2). |
| `principal`, `epistemic_descriptor` in `chisei_principal.rs` and `chisei_projection.rs` | Move to Chisei or composition (rule 6). |

`tests/sekai_chisei_import_ratchet.rs` holds today's edges as an allowlist
that may only shrink.

## Alternatives considered

- **Keep ADR 0092 (Chisei is the base).** Rejected: it keeps a Chisei-only
  mode with little product value and makes Sekai, the standalone product,
  depend on Chisei.
- **Neither plane depends on the other.** Both run alone and connect through
  composition, with shared vocabulary in a neutral kernel crate. Rejected: it
  keeps the Chisei-only mode and its not-attached paths, and adds a kernel
  crate plus ports in both directions to serve a deployment nobody needs.

## Consequences

- Sekai builds, tests, and ships without Chisei. A later crate split places
  `sekai-core` below `chisei-core`; `sekai-core` has no Chisei crate in its
  dependency tree.
- The `NotAttached` outcome, its handling, and the Chisei-only plane
  configuration are deleted. `chisei-plane` requires `SEKAI_ENDPOINT`.
- Vocabulary that #1240 and #1242 moved into Chisei moves back to Sekai.
  Comments citing ADR 0092 are updated as each piece moves.
- Sekai is the more frequently edited plane, so after a crate split most
  Sekai edits also rebuild Chisei. This is accepted in exchange for removing
  a deployment mode.
- Sekai keeps rechecking current authorization on commit; a Chisei decision
  is never a substitute (ADR 0082).
- Open question: whether a separate `chisei-plane` process is worth keeping.
  Without it, the Chisei-side traits over Sekai state become direct calls and
  the remote lookup goes away. Decided in #1300.

Follow-up work: require Sekai in Chisei and delete not-attached paths
(#1296); move shared vocabulary into Sekai (#1297); add the Sekai-owned
budget, proposal, and receipt ports (#1298); move the adapters out of Sekai
(#1299); decide on the separate `chisei-plane` process (#1300).

## Validation

- The ratchet allowlist reaches zero and becomes a hard rule.
- No `src/chisei` code handles a missing Sekai.
- Combined and split configurations pass the existing plane tests; a Chisei
  process without `SEKAI_ENDPOINT` refuses to boot.
