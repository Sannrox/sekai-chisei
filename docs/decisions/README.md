# Architecture decisions

Architecture Decision Records (ADRs) preserve accepted choices whose rationale
will still matter after the originating Issue or Discussion closes.

Proposed ADRs may accompany an open Design Discussion, but do not become
project policy until the discussion is resolved and their status is accepted.

Create an ADR only when a decision changes a durable boundary, public contract,
trust model, persistence strategy, or difficult-to-reverse technical direction.
Routine implementation detail stays in its Issue and pull request.

## Process

1. Resolve meaningful alternatives in a GitHub Design Discussion. In a
   solo-maintained repository, the accountable maintainer may instead resolve
   them in the source Issue and proposed ADR pull request.
2. Copy `0000-template.md` to the next zero-padded number and a short slug.
3. Open the ADR and implementation in the same PR when practical.
4. Set the status to `accepted` when merged.
5. Never rewrite the history of a superseded decision. Add a new ADR and link
   both records.

## Index

- [ADR 0001: Evaluate bounded ontology entailment at query time](0001-query-time-ontology-entailment.md)
- [ADR 0002: Identify prompt variants by immutable versioned names](0002-versioned-prompt-variant-identity.md)
- [ADR 0003: Inspect ontology through authenticated static artifacts](0003-authenticated-static-ontology-inspection.md)
- [ADR 0004: Add selective bitemporal history to the current graph](0004-selective-bitemporal-history.md)
- [ADR 0005: Object-bound coordination leases](0005-object-bound-coordination-leases.md)
- [ADR 0006: Capability package ed25519 trust](0006-capability-package-ed25519-trust.md)
- [ADR 0007: Provisional classification markings and purpose gates](0007-provisional-classification-markings.md)
- [ADR 0008: Keep the gateway a fail-closed protocol translator](0008-gateway-is-a-fail-closed-translator.md)
- [ADR 0009: Group expert `sekaictl` operations under `admin`](0009-sekaictl-administration-hierarchy.md)
- [ADR 0010: Retire deprecated `sekaictl` aliases at `0.2.0`](0010-retire-sekaictl-aliases-at-0.2.0.md)
- [ADR 0011: Separate invariant facts from configurable evaluation plans](0011-separate-invariant-facts-and-evaluation-plans.md)
