# 0007: Provisional classification markings and purpose gates

## Status

Accepted for v1 (#301). Vocabulary remains the default ceiling for unmarked
data and namespaces that never publish a lattice. Activated namespaces may
replace the single ordinal with a namespace-local lattice; see
[ADR 0032](0032-hierarchical-classifications.md).

The `ActionTypeDef.required_purpose` portion was retired when the pre-1.0 graph
Action DSL was removed. Object markings and authoritative principal profiles
remain accepted.

## Context

Operators need optional classification on artifacts and purpose constraints on
actions without replacing namespace isolation. Evidence already uses
`public|internal|confidential|restricted`.

## Decision

1. Reuse the evidence classification lattice as object access markings
   (`properties.access_marking`).
2. Store principal clearance and purpose allow-lists on
   `principal:<actor>` profile objects.
3. Fail open when unmarked; fail closed when marked and the principal lacks
   authority.
4. Record applicable decisions in the audit ledger.

## Consequences

- Additive; unmarked deployments behave as before.
- Principal profile objects are operator-managed graph data.
- Future lattice changes should migrate property values and document
  compatibility.
