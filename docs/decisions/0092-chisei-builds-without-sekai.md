# ADR 0092: Chisei builds without Sekai; Sekai may build on Chisei

- Status: accepted
- Date: 2026-10-03
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1236 (#1236)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md),
  [ADR 0083](0083-two-store-cutover-and-recovery.md),
  [ADR 0084](0084-system-one-action-function.md)

## Context

ADR 0082 gives decision state to Chisei and durable mutation state to Sekai,
and ADR 0083 splits their stores. The Chisei process already runs without
Sekai: it attaches `SekaiCommitLookup` only when a Sekai endpoint is
configured. The code does not match. In one crate, `src/chisei` imports
`crate::sekai::*` in about 80 places, and 7 files in `src/sekai` import
`crate::chisei::*`. Nothing says which direction is allowed, so neither plane
can be built, tested, or shipped alone.

The target is a Chisei that is usable on its own, with Sekai as an optional
layer that adds governed facts, ontology, and Actions on top of it.

## Decision

1. **Chisei never depends on Sekai.** Code under `src/chisei` does not name
   `crate::sekai::*`, Sekai store handles, or Sekai SQL. When Chisei needs a
   Sekai fact or commit, it calls a Chisei-owned port trait
   (`SekaiCommitLookup` is the template). Each port has an in-process
   implementation for combined mode, a gRPC implementation for the Chisei
   plane, and an explicit "not attached" outcome when no Sekai is
   configured. Missing Sekai is never a silent miss or a silent allow.
2. **Sekai may depend on Chisei's code, not on Chisei's state.** Sekai may
   use Chisei types and pure functions. A Sekai process never opens the
   Chisei store. Chisei state reaches Sekai only through the composition
   layer or Chisei RPCs, as Action admission already does with
   `Option<&BudgetTracker>` (absent means `deferred`).
3. **No neutral kernel.** Primitives both planes need live in Chisei, which
   is the base layer: the decision record and filter, the hash-chained
   decision-ledger append, and small helpers such as duplicate-key JSON
   checks. Sekai audit uses them for its own rows in its own store.
   Introducing a third shared module is deferred until a concrete need
   appears.
4. **Composition code lives outside both planes.** Code that holds both store
   handles, such as `cross_store_admission::CrossStoreAdmission` and the
   in-process port implementations, moves out of `src/chisei` into a
   composition module next to the gRPC wiring. The port traits themselves
   (`SekaiCommitLookup`, `SekaiCommitRef`) stay in Chisei.
5. **Adapters live on the dependent side.** Mapping Sekai roles, grants, and
   classification results into a Chisei principal context is Sekai-side or
   composition code, because only that side may name both types.

### Disposition of current Sekai → Chisei edges

| Sekai use of Chisei | Disposition |
| --- | --- |
| `budget::BudgetTracker` in Action admission and describe preview | Keep. Optional handle supplied by the composition layer (rule 2). |
| `evaluation_plan::validate_parameter_schema` / `validate_parameters` in Action types and admission | Keep. Parameter schemas are the Chisei schema language that System One fills (ADR 0084). |
| `receipt::*` in Action work lifecycle and admission | Keep. Public receipts project Chisei decision fields (ADR 0083, rule 4). |
| `system_one_action::fill_provenance_json` / `proposed_parameters` | Keep. System One is a Chisei Function (ADR 0084). |
| other `crate::chisei` uses in `execution_evidence`, `peer_import`, `workflow_action` | Keep while they use types or pure functions; move to composition code if they need Chisei state. |

Rule 2 for workflow steps (#1270): `workflow_action::submit_step` takes
`Option<&BudgetTracker>` from the caller, the same contract as Action
admission. Combined callers pass a tracker over the Chisei store; Sekai-only
callers pass `None` (budget `not_configured`).

### Disposition of current Chisei → Sekai edges

| Chisei use of Sekai | Disposition | Issue |
| --- | --- | --- |
| `audit::Decision`, `DecisionFilter`, `ledger::insert_chained_decision` | Move into Chisei (rule 3); Sekai audit imports them. | #1240 |
| `security::{Role, Grant}`, `classification_lattice`, `object_security` | Chisei principal context; Sekai-side adapter (rule 5). | #1241 |
| Object, link, grant, and object-type reads | Chisei-owned Sekai read port (rule 1). | #1234 |
| `schema`, `ontology`, `governed_action_type`, `action_instance*`, `action_policy`, `action::RiskClass`, `evidence*`, `governed_facts`, `retrieval`, `learning` | Port per family, or move pure helpers into Chisei (rules 1 and 3). | #1242 |
| `json::contains_duplicate_object_keys`, `lease::DEFAULT_SITE_ID` | Move into Chisei (rule 3). | #1242 |
| `cross_store_admission` (holds both stores) | Move to composition code (rule 4). | #1242 |

The import ratchet from #1235 enforces rule 1 as the allowlist shrinks.

## Alternatives considered

- **Neither plane depends on the other.** Sekai would expose admission and
  budget hooks for Chisei to implement. Rejected for now: it adds traits for
  edges that only carry types and pure functions, and Sekai has no standalone
  user yet.
- **Plane-neutral shared kernel.** Rejected for now: a third module or crate
  for a handful of primitives adds a layer without a consumer that needs it.
  Revisit if Sekai must ship without Chisei.
- **Chisei depends on Sekai.** Rejected: it is the opposite of a standalone
  Chisei and keeps the current coupling.

## Consequences

- Chisei can be built and tested without Sekai once #1240, #1241, #1242, and
  #1234 land.
- A later repository or crate split moves Chisei out first; Sekai then
  depends on a published Chisei crate.
- Sekai-backed Chisei features return an explicit not-attached outcome in a
  Chisei-only deployment.
- Sekai keeps rechecking current authorization on commit; a Chisei decision
  is never a substitute (ADR 0082).

## Validation

- The #1235 ratchet allowlist reaches zero and becomes a hard rule.
- No `src/sekai` code opens or wraps a `ChiseiStore`, including
  `workflow_action::submit_step`.
- Combined, split, and Chisei-only configurations pass the existing plane
  tests.
