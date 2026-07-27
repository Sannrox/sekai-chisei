# Research: governed what-if simulation over graph projections

Issue: [#148](https://github.com/Sannrox/sekai-chisei/issues/148)  
Related: [#143](https://github.com/Sannrox/sekai-chisei/issues/143) (closed → ADR 0001 / #144),
[#146](https://github.com/Sannrox/sekai-chisei/issues/146) (closed → ADR 0004 / #225–#228),
[#145](https://github.com/Sannrox/sekai-chisei/issues/145) (closed),
[#282](https://github.com/Sannrox/sekai-chisei/issues/282) (closed policy dry-run),
[#362](https://github.com/Sannrox/sekai-chisei/issues/362) (implementation vertical)  
Date: 2026-07-27  
Status: **recommendation complete**

## Decision question

Can Sekai-Chisei provide useful isolated what-if analysis over graph projections
without becoming a domain-specific digital twin or workflow engine?

## Product posture

What-if analysis is a natural next layer after:

- **Asserted graph** as sole durable truth (`VISION.md`, architecture);
- **Query-time entailment** that never persists or promotes derived facts
  (ADR 0001, `src/sekai/retrieval.rs`);
- **Selective bitemporal history** for as-of and correction questions
  (ADR 0004, `docs/temporal-history-storage.md`) — which explicitly leaves
  “future projections and simulation” to #148;
- **Policy dry-run** for *route-policy* counterfactuals over receipts
  (`docs/policy-dry-run.md`), which explicitly excludes “graph world-state
  counterfactuals (#148)”.

The product already answers “what is believed / was believed under
authorization.” #148 asks whether core should also answer “what *would*
change if these hypothetical deltas held,” without inventing twin physics
or a second write path into the canonical graph.

Exit must **not** be “defer forever” if a minimal, domain-neutral overlay
fits existing authority, bounds, and non-promotion rules. A full digital
twin, DES engine, or workflow simulator is out of product boundary.

## Evidence collected (today’s plane)

### Authority and write paths

| Surface | Behavior | Implication for what-if |
| --- | --- | --- |
| Current objects/links | Canonical compact graph; normal RPC mutations | Hypotheses must not land here without a separate governed action |
| Guarded mutations | Lease-fenced create/update/delete with digest-bound idempotency (`src/db/guarded_mutation.rs`, `src/sekai/lease.rs`) | Any “apply scenario” path would need the same fencing + audit — do not invent silent promote |
| Entailment results | Derived only at query time; not persisted (ADR 0001) | Overlay deltas should follow the same “projection ≠ fact” rule |
| Evidence → graph | Source retained; projections rebuildable; conflicts not auto-merged (`docs/architecture.md`) | Scenario outputs are another non-authoritative projection class |
| Policy dry-run | No provider calls, no policy activation, audited (`docs/policy-dry-run.md`) | Closest *governance* analog: candidate input, bounded sample, no side effects |

### Read / projection surfaces that scenarios would compose

| Surface | Location | Strengths | Gaps for what-if |
| --- | --- | --- | --- |
| `GraphQuery` / `traverse` | `src/sekai/query.rs` | Bounded BFS (depth ≤ 10), kind/property filters | Single-frontier expansion; no overlay merge |
| `RetrieveContext` | `src/sekai/retrieval.rs` | Asserted/entailment modes; ACL deny non-disclosure; hard bounds | Read-only over canonical + ontology; no hypotheticals |
| Temporal as-of / diff | `src/sekai/temporal.rs`, historical RPCs | Bitemporal coordinates; `outcome=not_retained` non-synthesis | History is truth-at-time, not counterfactual |
| Lineage | `src/sekai/lineage.rs` | Explicit `derived_from` / revision edges | Time order is not causality (ADR 0004 constraint) |
| Capability catalog | #106/#107, #151 | Governed invocation composition | No scenario capability yet |

### Hard bounds already proven in retrieval (reuse, do not invent a second budget model)

From `src/sekai/retrieval.rs` (clamp ceilings):

| Bound | Default | Hard max |
| --- | --- | --- |
| Depth | 0 (caller opt-in) | 3 |
| Objects | 20 | 100 |
| Links | 40 | 200 |
| Source rows | 200 | 1000 |
| Derived rows | 100 | 500 |
| Derivation steps | 12 | 32 |
| Wall time | 100 ms | 1000 ms |
| Explanation bytes | 1 MiB | 16 MiB |

Temporal append budget (`TEMPORAL_ASSERTION_BUDGET` = 500_000 versions) shows
the plane already fail-closes local growth. Scenario storage and expansion
must adopt the same fail-closed culture.

### Isolation / threat analysis (analytical)

| Threat | Failure mode | Required control |
| --- | --- | --- |
| Accidental promotion | Overlay write merges into `sekai_objects` / links | No API that mutates canonical graph from scenario apply; promote only via separate governed action (out of v1 scope or explicit non-goal) |
| Inference leak | Denied object shapes expansion or counts | Same deny non-disclosure as retrieval: filter seeds, intermediates, impact rows, explanations, truncation metadata |
| Hypothesis as fact | Clients treat impact set as asserted | Explicit `epistemic_class=hypothesis` (or equivalent) on every scenario artifact; never reuse evidence/forecast kinds without labeling |
| Unbounded fan-out | One seed relation floods the graph | Per-request expansion budget (depth/rows/time/memory) + optional relation allow-list; fail closed with non-sensitive truncation reasons |
| Domain twin creep | Core grows shipment/revenue simulators | Core emits domain-neutral impact sets only; domain rules live in adapters/schemas |
| Time-as-causality | “after X therefore Y” from timestamps | Propagation only along explicit overlay rules / lineage edges supplied by the scenario or adapter — never inferred from temporal order alone |
| Retention / concurrency | Scenarios accumulate forever or thrash | TTL + retention for persisted scenarios; concurrency limit per namespace; ephemeral session option with no durable store |
| Cross-plane import | Remote scenario treated as local truth | Import is verify-only evidence (#288/#290 posture); local recompute under local authz |

### External-adapter comparison (qualitative)

| Option | Isolation | Authz consistency | Domain neutrality | Local-first ops | Fit |
| --- | --- | --- | --- | --- | --- |
| **Core ephemeral overlay** | Strong if read-only merge | Can re-check ACL every hop | Yes (deltas + impact IDs) | Yes | **Core v1** |
| **Persisted non-authoritative scenario objects** | Strong if storage is separate table/kind and never current-state | Same + grant on scenario resource | Yes | Yes with retention | **Optional durability layer** |
| External domain simulator only | Depends on export discipline | Risk of ACL stripping at export | Simulator owns domain | Medium (extra process) | **Adapter for physics** |
| Full core DES / twin engine | Weak product isolation | Large attack surface | No | High cost | **Reject** |
| Adapter primitives only (export snapshot APIs) | Weak governance | Caller must reimplement | N/A | Low core cost | Incomplete alone |

Policy dry-run (#282) proves the control-plane pattern for *candidate evaluation
with audit and no side effects*. Graph what-if needs the same pattern over
**graph projections**, not over route receipts.

## Options (from #148)

| # | Option | Verdict |
| --- | --- | --- |
| 1 | Ephemeral hypothetical overlays | **Core of v1** (session-scoped, non-durable by default) |
| 2 | Persisted non-authoritative scenario objects | **Optional phase-1.5** for audit/share; never authoritative |
| 3 | External domain simulator consuming authorized snapshots | **Supported composition**, not a substitute for core overlay merge |
| 4 | No core engine; adapter primitives only | **Reject as terminal exit** — loses consistent authz, bounds, and epistemic labeling |

Option 4 alone is rejected as a *terminal* research exit: without a shared
overlay/impact contract, every adapter reimplements deny non-disclosure and
promotion hazards differently. Snapshot export helpers may still exist as
composition tools, but they are not the product answer to #148.

A full digital twin / workflow engine is rejected: it violates domain-neutral
foundation (plan 24 / VISION), duplicates domain executors, and expands core
beyond control-plane scope.

## Recommendation

Ship a **minimal, non-authoritative scenario overlay** in Sekai, composed with
existing authorized reads (current graph, optional temporal as-of, optional
entailment). Domain-specific propagation stays in **adapters** that produce
overlay deltas; core merges deltas and returns **domain-neutral impact sets**.

### Direction (v1 freeze)

1. **Scenario session (ephemeral by default)**  
   - Inputs: namespace, actor, optional base coordinates
     (`current` or temporal `valid_at` + `recorded_revision`), seed object/link
     ids, and a bounded list of **hypothesis deltas** (add/remove/replace
     property or link; all labeled hypothesis).  
   - Storage: process/request scoped; no write to current objects/links.  
   - Optional later: persist scenario metadata + deltas as a non-authoritative
     resource with TTL/retention and ACL — still never current-state.

2. **Overlay merge semantics**  
   - Read path = authorized base projection ⊕ ordered deltas.  
   - Conflicts among deltas are explicit (last-write-wins within the session
     only after ordered apply, or fail closed — pick one and document; prefer
     **fail closed on conflicting same-key deltas** for determinism).  
   - Entailment, if requested, runs **after** overlay merge on the
     authorization-filtered view, still without persisting derived facts
     (ADR 0001).

3. **Impact set output (domain-neutral)**  
   - Touched object ids, link ids, property keys, delta ops, and derivation
     steps (source fact ids + hypothesis delta ids + ontology revision when
     entailment used).  
   - No shipment/customer/revenue fields in core types.  
   - Epistemic class always `hypothesis` (distinct from fact, evidence,
     forecast).

4. **Authorization**  
   - Namespace grant required.  
   - Seed and every expansion hop re-check object/link visibility
     (`SecurityChecker` / grant model).  
   - Denied material must not appear in impact rows, counts, explanations, or
     truncation reasons (retrieval non-disclosure pattern).  
   - Scenario create/read/list (if persisted) is a separate grant surface.

5. **Bounds**  
   - Reuse retrieval-class ceilings for depth, rows, time, explanation size.  
   - Add scenario-specific caps: max deltas per session, max concurrent
     sessions per namespace, optional max expansion work units.  
   - Fail closed with non-sensitive truncation metadata.

6. **Causality**  
   - Propagation rules are explicit (adapter-supplied delta lists or a tiny
     closed set of structural expansions such as “incident edges of seed”).  
   - Temporal order and audit sequence never invent causal edges.

7. **Promotion**  
   - **v1 non-goal:** no “apply scenario to canonical graph” API.  
   - Future promote would be a separate governed action with lease fencing,
     policy, audit, and explicit actor consent — never automatic from impact
     computation.

8. **Composition with external simulators**  
   - Core may expose an **authorized snapshot cursor** (bounded, ACL-filtered)
     for adapters.  
   - Adapters return hypothesis deltas; core re-validates authz and bounds
     before merge.  
   - Adapters never write the control-plane graph directly for “what-if.”

### Explicit non-actions

- Do not build a discrete-event, Monte-Carlo, or digital-twin engine in core.
- Do not treat scenario results as evidence, forecasts, or asserted facts.
- Do not mutate `sekai_objects` / `sekai_links` / temporal assertions from
  scenario evaluation.
- Do not infer causality from time order alone.
- Do not expand policy dry-run (#282) into graph world-state simulation; keep
  those surfaces separate (receipt route policy vs graph hypothesis).
- Do not require PostgreSQL parity for the first SQLite vertical.
- Do not invent priority or multi-issue roadmaps beyond the single vertical
  below.

### Threat-model acceptance for the vertical

| Control | Acceptance evidence |
| --- | --- |
| No canonical mutation | Integration test: after scenario run, object/link digests/revision unchanged |
| Deny non-disclosure | Fixture: denied intermediate does not appear in impact or metadata |
| Bound enforcement | Each cap independently triggers truncation without hang |
| Epistemic labeling | Response and any persisted row carry hypothesis class |
| Adapter isolation | Domain fixture produces deltas only; core types remain neutral |

## Implementation issue (single vertical)

Opened: **[#362](https://github.com/Sannrox/sekai-chisei/issues/362)** —
`feat(sekai): non-authoritative scenario overlay and bounded impact projection`

Deliver a session-scoped overlay merge over authorized current (and optional
temporal as-of) projections, hypothesis-labeled deltas, domain-neutral impact
sets with explanations, ACL re-check at every hop, retrieval-class bounds,
and fixtures for isolation / deny / bound / no-mutation. No promote-to-graph
API. No domain physics. SQLite-first gRPC surface; document capability-catalog
composition later (#151).

Acceptance sketch:

1. Warehouse-style **domain adapter fixture** that only emits overlay deltas
   (e.g. “if link X removed, adapter proposes Y”) — core remains neutral.
2. Isolation tests: concurrent scenarios; no cross-talk; no current-state write.
3. Bounded propagation cost tests (depth/rows/time).
4. Inference-leak and accidental-promotion negative tests.
5. Comparison note: external simulator path uses the same delta + impact
   contract.

## Relationship to closed dependencies

| Dependency | Status | Effect on #148 |
| --- | --- | --- |
| #143 / ADR 0001 | Closed / accepted | Derived ≠ asserted; bounds + authz patterns reusable |
| #146 / ADR 0004 | Closed / accepted | As-of base for scenarios; simulation owned here |
| #144 retrieval | Closed | Concrete bound constants and deny non-disclosure |
| #282 policy dry-run | Closed | Governance analog for side-effect-free candidates; graph counterfactuals left here |
| #145 pattern query | Closed | Future multi-hop IR can *read* overlays; not a blocker |

## Conclusion

**Recommend a minimal non-authoritative scenario overlay** (option 1 as core,
option 2 as optional durability, option 3 as adapter composition) and **reject
a core twin engine or adapter-only terminal exit**. Close research #148 with
this freeze; implement **#362** when scheduled.
