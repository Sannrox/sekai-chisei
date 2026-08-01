# Epistemic profiles at an RDF, OWL, and PROV-O boundary

Issue #501 asked whether the versioned epistemic replication profile could be
exchanged with RDF, OWL, and PROV-O without changing Sekai's authority or
reasoning model. The deterministic proof is in
[`tests/epistemic_interop_conformance.rs`](../../tests/epistemic_interop_conformance.rs).
It uses the [#499 profile package](../../examples/epistemic-replication/profile-v1.json)
and a canonical, parser-neutral triple representation. It does not add an RDF
parser or a reasoner to the control plane.

## Decision

Support a deliberately small edge-interoperability subset, with explicit loss
metadata. Do not build a generic RDF/OWL engine, SPARQL or Cypher surface, or a
second persisted inference store.

An eventual adapter may translate a validated external document into this
bounded representation and then compile only the supported terms to the
existing `OntologyRegistry`, object/link, evidence, provenance, and receipt
contracts. The adapter remains outside the core authority boundary. The core
continues to use the asserted graph and its fixed query-time entailment profile
as the only source of truth.

This research issue closes with a mapping contract and conformance evidence.
A separate implementation issue is justified only when a concrete consumer
needs the exchange boundary; it must not be created merely to advertise
standards compatibility.

## Supported projection

The mapping is intentionally narrower than the standards:

| Source vocabulary | Bounded mapping | Preserved Sekai meaning |
| --- | --- | --- |
| RDF named classes | `rdf:type owl:Class` | Versioned ontology class name and profile namespace |
| RDF properties | `rdf:type rdf:Property`, `rdfs:domain`, `rdfs:range` | Existing relation/property metadata |
| Profile property constraints | bounded Sekai mapping fields for required flag, description, and scalar range | #499 schema validation metadata |
| OWL entailment constructs | `rdfs:subClassOf`, `owl:equivalentClass`, `owl:disjointWith`, `owl:inverseOf`, transitive-property typing | Explicit loss in v1; no imported closure or relation mutation |
| PROV-O entities and activities | `prov:Entity`, `prov:Activity`, `prov:used`, `prov:wasGeneratedBy`, `prov:wasDerivedFrom`, `prov:wasAssociatedWith` | Evidence and assessment source digests plus operation/producer identity and PROV type references |
| Sekai epistemic metadata | bounded mapping fields for assertion mode, lifecycle, observation time, source digest, producer confidence, and `producer_input` basis | Asserted-versus-derived, contradiction/retraction, temporal, and provenance state |

The #499 package contributes all eight named classes. Its generic graph and
evidence contracts supply representative `evidence_for` and `derived_from`
links; supporting versus contradicting polarity is carried by the separate
`evidenceStance` field. These links carry named identities and digests, not raw
evidence payloads. The fixture keeps profile, claim, evidence, assessment,
activity, and producer identities distinct. Protocol and artifact are proven
as schema classes and properties only; this issue does not invent instance
records or digests for them.

The #499 package happens not to declare a class hierarchy, equivalence,
disjointness, inverse, or transitive relation. Those OWL entailment terms are
explicitly outside the v1 import subset, rather than being invented assertions
in this fixture. A future local-registry projection would require a separate
mapping and bounded-reasoning decision.

## Identity and lifecycle rules

- A local mapping is keyed by `(source format, source identity, source IRI,
  mapping version)`. Envelope bindings are only authenticated local
  self-bindings; an external IRI is an opaque reference and is loss-recorded.
  An edge adapter may resolve an external IRI through the existing
  authorization-filtered identity path before constructing this envelope, but
  the envelope cannot self-authorize a new local object or silently reconcile
  an existing one.
- Blank-node identity is unsupported and is rejected by the import contract.
  The fixture also records external IRIs as loss rather than inventing local
  object IDs.
- `asserted` and `derived` are assertion modes; `supported`, `contested`,
  `insufficient`, and `unknown` are evidence statuses; and `supporting`,
  `contradicting`, and `unknown` are evidence stances. `current`, `stale`,
  `retracted`, and `superseded` are lifecycle states. A PROV edge does not
  promote a derived fact into the asserted graph, and a retraction does not
  delete its source identity.
- Source/profile/ontology/receipt digests, observation time, producer
  confidence with the closed `producer_input` basis, mapping version, and
  unsupported-feature codes are mandatory envelope data.
  The adapter carries references and digests only; raw protected content stays
  behind the existing evidence and authorization paths.

## Loss and security contract

The following constructs are deliberately unsupported and must produce a
stable loss record or a bounded rejection: `rdfs:subClassOf`,
`owl:equivalentClass`, `owl:disjointWith`, `owl:inverseOf`, transitive-property
typing, `owl:imports`, restrictions, property chains, cardinality/inference
axioms, SWRL or unknown rule language, `owl:sameAs` identity reconciliation,
blank nodes, unbounded collection structures, and arbitrary external ontology
dereferencing. An external
reasoner cannot add persisted facts or bypass ACL, namespace, classification,
retention, evidence-lifecycle, residency, or non-disclosure checks.

The adapter verifies a bounded canonical document before interpretation: a
maximum triple count and canonical serialized size, bounded identifier lengths,
allowlisted vocabulary IRIs, deterministic ordering, and no remote fetches.
The typed conformance importer checks the canonical size after deserialization;
an eventual byte-stream adapter must enforce the raw input-size limit before
parsing as well.
Exports are built only from an already authorization-filtered snapshot. The
fixture proves that hidden or disallowed records do not appear in the
serialized output; production export must use the authenticated existing
snapshot path.

## Complexity dividend

This choice removes a new core parser, query language, inference engine,
database projection, migration, and cross-team trust boundary. One future edge
mapper and one mapping document are easier to audit than a standards-shaped
second ontology product. The trade-off is intentional loss for unsupported
semantics and a small amount of adapter-side validation. If a consumer later
requires exact OWL entailment or identity reconciliation, that is a new trust
and product decision, not an implementation detail of this mapping.
