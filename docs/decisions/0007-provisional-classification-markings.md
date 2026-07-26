# 0007: Provisional classification markings and purpose gates

## Status

Accepted for v1 (#301). Vocabulary remains provisional pending a later
design discussion if residency/federation needs a richer lattice.

## Context

Operators need optional classification on artifacts and purpose constraints on
actions without replacing namespace isolation. Evidence already uses
`public|internal|confidential|restricted`.

## Decision

1. Reuse the evidence classification lattice as object access markings
   (`properties.access_marking`).
2. Store principal clearance and purpose allow-lists on
   `principal:<actor>` profile objects.
3. Add optional `ActionTypeDef.required_purpose`.
4. Fail open when unmarked / no purpose required; fail closed when marked or
   purpose-gated and the principal lacks authority.
5. Record applicable decisions in the audit ledger.

## Consequences

- Additive; unmarked deployments behave as before.
- Principal profile objects are operator-managed graph data.
- Future lattice changes should migrate property values and document
  compatibility.
