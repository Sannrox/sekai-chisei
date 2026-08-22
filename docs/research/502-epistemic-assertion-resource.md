# Durable `EpistemicAssertion` resource decision

[Issue #502](https://github.com/Sannrox/sekai-chisei/issues/502) asked whether
the work in #492, #493, #494, #496, #498, #499,
#500, and #501 leaves an unresolved need for a domain-neutral durable
`EpistemicAssertion`, or whether epistemic state is already reconstructable as
an authorized projection over existing authorities.

## Decision

Keep epistemic state projection-only in the core. Do not add an
`EpistemicAssertion` class, table, public RPC, or reserved resource family in
v1. Close #502 with no implementation follow-up.

When a domain needs a durable assertion, it should use the existing authority
that owns the fact and its lifecycle. An ordinary namespace-scoped typed graph
object or link may represent a domain assertion when that domain needs one; it
may be mapped to an ontology class or relation and use selective temporal
history when needed, but it must still use the existing graph, authorization,
audit, lineage, retention, and receipt contracts. A separate core resource is
not justified by the convenience of giving several projections one common
label.

## Evidence

The completed work already separates the responsibilities that a proposed
resource would otherwise duplicate:

| Need | Existing authority | Existing projection or reference |
| --- | --- | --- |
| Asserted domain facts and links | Sekai graph objects, links, and ontology facts | `RetrieveContext`, `ExpandRelations`, and bounded query-time entailment |
| External evidence identity, content digest, and lifecycle | `EvidenceSubmissionRecord` and the evidence store | Authorized evidence responses and `EpistemicDescriptor::from_external_evidence` |
| Governed derived memory and reassessment | Versioned `KiokuMemory` plus evidence basis and lifecycle events | `EpistemicDescriptor::from_kioku` |
| Evaluation definition, plan, manifest, and step evidence | Chisei evaluation resources and the canonical operation receipt | Evaluation and receipt projections; step evidence has no independent lifecycle |
| Request-scoped hypotheses | No live `EvaluateScenario` producer after 1.0; see [#660](660-hypothetical-overlay.md) | `EpistemicDescriptor::from_hypothesis` remains a test and vocabulary helper; no durable assertion is minted |
| Cross-source status metadata | `chisei.epistemic-descriptor/v1` | Additive, bounded, source-neutral fields with explicit `unknown` values |

The descriptor constructors take values from already-authorized source
projections. They do not copy protected payloads, assign a trust score, merge
identities, or promote derived/model-generated content into asserted facts.
`tests/epistemic_metadata_conformance.rs` and the replication, federation, and
RDF/OWL/PROV-O conformance fixtures exercise these boundaries. The existing
descriptor contract is additive in `proto/sekai.proto` and `proto/chisei.proto`;
older clients can ignore it and no new endpoint is needed.

This follows the existing architecture decisions:

- [ADR 0001](../decisions/0001-query-time-ontology-entailment.md) keeps the
  asserted graph authoritative and forbids persisted derived closure.
- [ADR 0011](../decisions/0011-separate-invariant-facts-and-evaluation-plans.md)
  keeps manifests and step results under evaluation and receipt authority
  rather than creating another top-level resource family.
- [ADR 0012](../decisions/0012-bound-stochastic-evaluation-by-situation.md)
  keeps statistical evidence bounded and receipt-owned instead of adding a
  generic judge or evidence store.
- [#500](500-epistemic-federation.md) and [#501](501-epistemic-rdf-owl-prov-o.md)
  show that federation and edge standards mapping compose with existing
  receipts, provenance, evidence, and bounded projections without a second
  authority.

## Complexity and impact

An `EpistemicAssertion` would not be a metadata-only addition. It would need a
new identity and lifecycle model, namespace/object authorization, classification
and egress rules, audit and lineage coupling, retention and erasure behavior,
SQLite and PostgreSQL schemas and migrations, reconciliation semantics,
backend-conformance fixtures, public protobuf/CLI discovery, and a rule for
which source wins when the new row disagrees with a graph fact, evidence
submission, receipt, or Kioku memory. It would also invite callers to treat a
cross-source projection as a new source of truth.

Those costs are not supported by current evidence. The repository has one
replication fixture and several consumers of the same projection contracts,
but no independent domain requirement that cannot be reconstructed within the
existing bounded identity, lifecycle, authorization, and query surfaces.

## Reopening criteria

Reopen the decision only when at least two independent domains or consumers
demonstrate all of the following with deterministic evidence:

1. an independent assertion identity that cannot safely be represented by an
   existing graph object, evidence submission, Kioku version, evaluation
   resource, or operation receipt;
2. a distinct lifecycle and authorization contract that cannot be reconstructed
   from those authorities within current bounds; and
3. a query, retention, or reconciliation requirement that needs a durable
   cross-source record rather than a read-only projection.

Any reopened proposal must first specify the authority relationship and the
SQLite/PostgreSQL migration, audit, lineage, retention, and rollback plan. It
must not introduce a write path merely to make projections easier to consume.

## Validation

The decision is supported by the existing deterministic suites:

- `cargo test --locked --test epistemic_metadata_conformance`
- `cargo test --locked --test epistemic_replication_example`
- `cargo test --locked --test epistemic_federation_conformance`
- `cargo test --locked --test epistemic_interop_conformance`
- the SQLite/PostgreSQL Kioku and evaluation backend conformance fixtures

The portable ontology already defines `ChiseiEpistemicDescriptor` as a
read-only projection with provenance to the descriptor implementation and
guide (`docs/ontology/epistemic-descriptor-v1.json`). This decision adds no
`EpistemicAssertion` class or relation. The maintained descriptor guide remains
the usage contract; this page records the research outcome and its reopening
test.
