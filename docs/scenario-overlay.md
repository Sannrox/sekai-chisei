# Non-authoritative scenario overlay

Issue: [#362](https://github.com/Sannrox/sekai-chisei/issues/362).  
Research freeze: [148-what-if-simulation.md](research/148-what-if-simulation.md).

## Purpose

Operators and agents can evaluate **what-if graph hypotheses** without mutating
canonical objects, links, or temporal assertions, and without turning the
control plane into a domain digital twin.

## Guarantees

- **Non-authoritative**: every response carries `epistemic_class = hypothesis`.
- **No canonical mutation**: evaluation only reads the graph; overlay state is
  request-scoped memory.
- **Authorization re-check**: namespace grant plus object ACL and classification
  for every seed, expansion hop, and delta target. Denied material never
  appears in impact rows, explanations, or truncation reasons.
- **Fail-closed conflicts**: two deltas that target the same property key or
  link id in one request fail with `FAILED_PRECONDITION`.
- **Bounded**: reuses retrieval-class ceilings (depth/objects/links/time/
  explanation bytes) plus scenario caps (`max_deltas`,
  `max_expansion_work_units`). Each bound truncates with a non-sensitive reason
  name.
- **Domain-neutral core**: impact rows name object/link ids, property keys, ops,
  and explanation steps only. Domain physics stay in adapters that emit deltas.

## gRPC

```text
EvaluateScenario
  namespace, base_mode=current
  seed_object_ids, deltas[]
  max_depth, max_objects, max_links, max_time_ms, max_explanation_bytes
  max_deltas, max_expansion_work_units
  request_id (optional correlation)
```

Delta ops: `set_property`, `remove_property`, `add_link`, `remove_link`.

Response: hypothesis-labeled impact rows (`target_kind`, ids, op, delta ids,
before/after values, explanation steps), truncation metadata, applied delta
count, and an ephemeral `scenario_id`.

Optional catalog binding uses capability
`sekai.scenario.evaluate` with the same receipt metadata contract as semantic
retrieval (`x-sekai-capability`, `x-sekai-namespace`, `x-sekai-operation-id`).

## Base coordinates

v1 supports `base_mode = current` only. Temporal as-of fields
(`valid_at_ms`, `recorded_revision`) are reserved and rejected so history wiring
does not expand this vertical. Future work can compose ADR 0004 as-of reads as
an authorized base without changing impact-set semantics.

## Adapter composition

Adapters (or agent runtimes) produce ordered hypothesis deltas from authorized
snapshots or local rules. Core re-validates authorization and bounds, merges
the overlay, and returns the impact set. Adapters must not write the control-
plane graph for what-if analysis.

A warehouse-style fixture in `src/sekai/scenario.rs`
(`warehouse_release_capacity_deltas`) shows the contract: emit deltas only.

## Capability catalog (#151)

`DiscoverCapabilities` advertises `sekai.scenario.evaluate` with:

- scopes `namespace:read`, `object:read`;
- decision points `namespace_access`, `object_acl`, `classification`;
- limits including retrieval-class ceilings, `max_deltas`,
  `max_expansion_work_units`, and `mutates_canonical_graph=0`;
- evidence requirements for hypothesis labeling, domain-neutral impact rows,
  truncation metadata, and no canonical mutation.

Catalog composition with broader package manifests remains a follow-on (#151);
this surface is already discoverable and invocable.

## Non-goals

- Promote / apply scenario results to canonical `sekai_objects` / `sekai_links`
  / temporal assertions
- Domain physics (shipment, revenue, customer simulators) in core
- Discrete-event, Monte-Carlo, or digital-twin engine
- Inferring causality from temporal order alone
- PostgreSQL parity for the first SQLite vertical
- Expanding policy dry-run into graph counterfactuals
