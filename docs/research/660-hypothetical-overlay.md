# Governed hypothetical overlay after 1.0

[Issue #660](https://github.com/Sannrox/sekai-chisei/issues/660) asked when, if
ever, a Chisei-gated hypothetical overlay may return after `EvaluateScenario`
was removed, without becoming a system of record.

## Decision

Keep the 1.0 removal. Scenario overlay stays design history. Close #660 with
no implementation follow-up, no Design Discussion, and no feature Issue.

Do not restore a request-scoped overlay. Do not persist hypothetical objects
into the graph. `origin_class=hypothesis` and
`EpistemicDescriptor::from_hypothesis` remain vocabulary and test helpers;
they are not a live producer.

## Evidence

### Why #362 was removed

[#148](148-what-if-simulation.md) recommended a session-scoped,
non-authoritative overlay. [#362](https://github.com/Sannrox/sekai-chisei/issues/362)
shipped `EvaluateScenario` as that vertical. The 1.0 interface freeze in
[#383](383-core-product-interface.md) then classified
`sekai.scenario.evaluate` as research/lab surface and removed it with the
other experimental retrieval verticals.

[CHANGELOG 1.0.0](../../CHANGELOG.md) records the deletion of
`EvaluateScenario`, its request/response types, capability catalog entry, and
in-memory evaluator. No `EvaluateScenario` RPC, proto message, or
`src/sekai/scenario.rs` module remains. VISION names simulation only in the
long-term horizon; near-term and mid-term milestones do not.

### What still mentions the overlay

| Remainder | Role |
| --- | --- |
| `EpistemicDescriptor::from_hypothesis` | Constructor used by descriptor and context-admission tests. It never writes graph rows. |
| `origin_class=hypothesis` in proto and [epistemic-descriptor.md](../epistemic-descriptor.md) | Closed vocabulary value. Graph retrieval emits `asserted` or `derived` only. |
| Context-admission example rule for `origin_classes: ["hypothesis"]` | Governs use of an already-labeled projection. It cannot mint overlay rows. |
| [docs/research/148-what-if-simulation.md](148-what-if-simulation.md) | Design history; status already says the operator guide was retired. |

No unit or integration test still invokes `EvaluateScenario`. The only
hypothesis tests construct a descriptor in memory and check that it does not
mint support or assertion.

### ADR 0001 traces are not what-if

[#658](658-query-time-entailment-constructs.md) kept the query-time profile:
subclass, equivalence, and marked transitivity over authorization-filtered
asserted facts. Those traces answer "what does the current ontology entail?"
They do not accept hypothesis deltas, merge a second world, or expire with an
operation.

Policy dry-run remains the supported counterfactual: route-policy candidates
over receipts, with no graph mutation. [policy-dry-run.md](../policy-dry-run.md)
already excludes graph world-state hypotheses.

### Promotion paths

Receipts record descriptor version and bounded aggregate counts. They do not
store descriptor payloads or overlay rows
([epistemic-descriptor.md](../epistemic-descriptor.md)). Object sync,
write-back, and export operate on asserted graph and evidence authorities.
With no EvaluateScenario producer, there is no overlay row that those paths
could promote. The portable descriptor ontology no longer defines
`SekaiScenarioHypothesisReference` or
`projects_scenario_hypothesis_reference`. `origin_class=hypothesis` remains a
closed vocabulary value for the leftover constructor.

Restoring option 2 would reintroduce a public RPC, capability, evaluator,
bounds, and an SQLite-only or dual-backend snapshot path. That is a new
product, not a documentation fix.

## Alternatives rejected

- **Restore a non-authoritative overlay now (option 2).** 1.0 just deleted
  that vertical. VISION does not ask for it in the near or mid term. There is
  no open operator Issue that asserted retrieval, ADR 0001 traces, and policy
  dry-run cannot answer. A return requires a Design Discussion and a later
  feature Issue; this research does not open them.
- **Persist hypothetical objects (option 3).** Out of scope. It would recreate
  a second world and contradict ADR 0001 and the #502 projection-only freeze.

## Reopening criteria

Reopen only when all of the following are true:

1. VISION or an accepted mid-term milestone names governed graph simulation as
   a current product job, not only a long-term horizon.
2. At least one named operator or integrator question cannot be answered by
   asserted retrieval, ADR 0001 traces, and policy dry-run.
3. The proposal is request-scoped, labeled `hypothesis`, cannot be synced or
   written back, expires with the operation, and cannot let hidden facts affect
   results, counts, explanations, or truncation.

A reopened proposal must start as a Design Discussion. It must not persist
hypothetical objects or treat `from_hypothesis` as proof that the overlay
already exists.

## Validation

```bash
rg -n 'EvaluateScenario' proto src tests
cargo test --locked --lib chisei::epistemic_descriptor
cargo test --locked --lib chisei::policy
```

The first command must find no runtime producer. The tests cover the leftover
hypothesis constructor and context-admission qualification. This page records
the research outcome and does not restore a scenario RPC.
