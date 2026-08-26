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
- [ADR 0004: Add selective bitemporal history to the current graph (retired for 1.0)](0004-selective-bitemporal-history.md)
- [ADR 0005: Object-bound coordination leases](0005-object-bound-coordination-leases.md)
- [ADR 0007: Provisional classification markings and purpose gates](0007-provisional-classification-markings.md)
- [ADR 0008: Keep the gateway a fail-closed protocol translator](0008-gateway-is-a-fail-closed-translator.md)
- [ADR 0009: Group expert `sekaictl` operations under `admin`](0009-sekaictl-administration-hierarchy.md)
- [ADR 0010: Retire deprecated `sekaictl` aliases at `0.2.0`](0010-retire-sekaictl-aliases-at-0.2.0.md)
- [ADR 0011: Separate invariant facts from configurable evaluation plans](0011-separate-invariant-facts-and-evaluation-plans.md)
- [ADR 0012: Bound stochastic evaluation by situation](0012-bound-stochastic-evaluation-by-situation.md)
- [ADR 0013: Govern external evaluator adapters outside the Chisei process](0013-governed-external-evaluator-adapters.md)
- [ADR 0015: Apply Gunshi allocation before native execution planning](0015-gunshi-allocation-precedes-native-planning.md)
- [ADR 0016: Publish a dedicated versioned Rust core-loop client](0016-versioned-rust-core-loop-client.md)
- [ADR 0017: Return the repository to Apache 2.0](0017-return-to-apache-2.0.md)
- [ADR 0018: Keep ontology relation cardinality advisory in 1.x](0018-ontology-relation-cardinality.md)
- [ADR 0019: Keep native discovery and the HTTP provider matrix as separate catalogs](0019-dual-capability-catalogs.md)
- [ADR 0020: Keep shared type revisions, inbound object sync, and permit-backed external mutation separate](0020-shared-type-revisions-and-object-sync.md)
- [ADR 0021: Defer a second object-sync source until GitHub Issue/PR admission is live](0021-defer-second-object-sync-source.md)
- [ADR 0022: Admit inbound records as plane-committed source batches](0022-source-batch-transactions.md)
- [ADR 0023: Fence ordered source change feeds by synchronization generation](0023-generation-fenced-source-change-feeds.md)
- [ADR 0024: Evolve governed definitions through branches with immutable revision history](0024-governed-definition-branches.md)
- [ADR 0025: Enforce activated object security in storage queries](0025-storage-enforced-object-security.md)
- [ADR 0026: Publish change sets as governed branch proposals](0026-governed-branch-proposals.md)
- [ADR 0027: Deny property access without an explicit grant](0027-explicit-property-grants.md)
- [ADR 0028: Execute approved checkpointed fact migration](0028-checkpointed-fact-migration.md)
- [ADR 0029: Share namespaces through grant-scoped signed snapshots](0029-signed-namespace-snapshots.md)
- [ADR 0030: Apply one compiled row predicate to every public query path](0030-row-scoped-query-access.md)
