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
   Numbers `0006` and `0014` were skipped and remain unused.
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
- [ADR 0031: Require a scoped purpose authorization for governed reads](0031-purpose-bound-reads.md)
- [ADR 0032: Evaluate markings against a namespace-local classification lattice](0032-hierarchical-classifications.md)
- [ADR 0033: Generate revision-pinned TypeScript ontology clients](0033-revision-pinned-typescript-ontology-clients.md)
- [ADR 0034: Preserve an immutable provenance chain on imported assertions](0034-cross-site-import-provenance.md)
- [ADR 0035: Admit signed source webhooks as object-sync transport](0035-source-webhook-transport.md)
- [ADR 0036: Query registered Iceberg and Parquet snapshots as projections](0036-open-table-projections.md)
- [ADR 0037: Project typed events with durable stream checkpoints](0037-event-stream-projections.md)
- [ADR 0038: Authorize property-level reads before every public query surface](0038-property-level-reads.md)
- [ADR 0039: Govern documents as objects with digest-bound renditions](0039-governed-documents.md)
- [ADR 0040: Generate revision-pinned Python ontology clients](0040-revision-pinned-python-ontology-clients.md)
- [ADR 0041: Preserve concurrent federation assertions as governed conflicts](0041-governed-federation-conflicts.md)
- [ADR 0042: Revoke shared federation authority as governed objects](0042-governed-federation-revocation.md)
- [ADR 0043: Keep learned changes inspectable and reversibly superseding](0043-reversible-learning-changes.md)
- [ADR 0044: Query governed geospatial properties after property authorization](0044-governed-geospatial-queries.md)
- [ADR 0045: Evaluate versioned data-quality rules as content-bound results](0045-governed-data-quality-rules.md)
- [ADR 0046: Expose bounded source health as an authorized projection](0046-bounded-source-health.md)
- [ADR 0047: Push bounded virtual-table predicates with governed equivalence](0047-virtual-table-predicate-pushdown.md)
- [ADR 0048: Expose governed event subscriptions with versioned cursors](0048-governed-event-subscriptions.md)
- [ADR 0049: Enforce value-instance access as a cell grant](0049-value-instance-access.md)
- [ADR 0050: Govern image assets with digest-bound renditions and annotations](0050-governed-images.md)
- [ADR 0051: Publish versioned client packages with protocol and provenance pins](0051-versioned-client-packages.md)
- [ADR 0052: Certify capability packages against an immutable digest](0052-capability-package-certification.md)
- [ADR 0053: Exchange federation traffic through bilateral network contracts](0053-federation-network-contracts.md)
- [ADR 0054: Map workflow steps through ActionInstance admission](0054-workflow-action-bridge.md)
- [ADR 0055: Certify connectors against an immutable digest](0055-connector-certification.md)
- [ADR 0056: Export warehouse projections with security-metadata pins](0056-warehouse-projections.md)
- [ADR 0057: Export partitioned lakehouse snapshots with schema evolution](0057-lakehouse-snapshots.md)
- [ADR 0058: Certify model-platform adapters against evaluation evidence](0058-model-platform-certification.md)
- [ADR 0059: Admit autonomous actions only inside a signed current envelope](0059-autonomous-envelopes.md)
- [ADR 0060: Admit later object-sync kinds through additive registered descriptors](0060-additive-source-type-descriptors.md)
- [ADR 0061: Inspect and preview quarantined source repairs without a second admission plane](0061-quarantine-repair-preview.md)
- [ADR 0062: Expose quality trends as an authenticated read projection](0062-quality-trend-read-api.md)
- [ADR 0063: Describe and preview object-bound Actions without a second admission plane](0063-object-action-describe-preview.md)
- [ADR 0064: Persist event projections and subscriptions on PostgreSQL without a second authority plane](0064-event-stream-postgres-parity.md)
- [ADR 0065: Persist workflow bindings and callbacks on PostgreSQL without a second admission plane](0065-workflow-action-postgres-parity.md)
- [ADR 0066: Evaluate revision-bound ObjectSet descriptors without a query language](0066-object-set-evaluate.md)
- [ADR 0067: Report consumer impact from registered declarations only](0067-definition-consumer-impact.md)
- [ADR 0068: Deliver object-change subscriptions from committed facts](0068-object-change-subscriptions.md)
- [ADR 0069: Stamp one caller operation identity on spans, receipts, and object changes](0069-operation-correlation.md)
- [ADR 0070: Publish a compatibility matrix as a projection of shipped metadata](0070-compatibility-matrix.md)
- [ADR 0071: Classify public RPCs by backend and consumer evidence](0071-rpc-maturity.md)
- [ADR 0072: Keep ontology functions on an in-process host API](0072-in-process-function-host.md)
- [ADR 0073: Typed objects are source-backed and Action-written](0073-source-and-action-objects.md)
- [ADR 0074: Governed transforms are plane-owned and write datasets](0074-plane-owned-transforms.md)
- [ADR 0075: HTTP/JSON ontology is a projection of stable gRPC](0075-http-ontology-projection.md)
- [ADR 0076: One compiling policy decision point over shipped v1 vocabularies](0076-compiling-policy-entry.md)
- [ADR 0077: Action types declare closed criteria and receipt-bound effects](0077-action-type-criteria.md)
- [ADR 0078: Audience-bound assertions fill existing AuthenticatedContext](0078-audience-bound-assertions.md)
- [ADR 0079: Bound evaluation suites gate promotion on existing certification](0079-evaluation-promotion-gate.md)
- [ADR 0080: Keep dual community control-plane storage](0080-dual-community-runtime-storage.md)
- [ADR 0081: EvaluateObjectSet dual-reads an in-process object-log library](0081-evaluate-reads-mikura-library.md)
- [ADR 0082: Separate Chisei and Sekai durable stores](0082-separate-chisei-and-sekai-durable-stores.md)
- [ADR 0083: Two-store cutover and recovery contract](0083-two-store-cutover-and-recovery.md)
- [ADR 0084: Bind System One as an Action-filling Function](0084-system-one-action-function.md)
- [ADR 0085: A pinned governed learning changes context only](0085-governed-learning-changes-context-only.md)
- [ADR 0087: Enforce ontology relation maximum cardinality; keep the minimum advisory](0087-enforce-relation-cardinality-maximum.md)
