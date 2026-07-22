# Architecture decisions

Architecture Decision Records (ADRs) preserve accepted choices whose rationale
will still matter after the originating Issue or Discussion closes.

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
