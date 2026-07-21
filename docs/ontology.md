# Ontology definitions

Sekai's ontology layer adds semantic definitions above the existing typed
object graph. It does not replace graph objects, links, or schema validation,
and it does not persist inferred facts. The initial reasoning direction is a
fixed, opt-in, query-time profile; see
[ADR 0001](decisions/0001-query-time-ontology-entailment.md).

The native `SekaiService` API exposes ontology classes and relations. Classes
can declare superclasses, equivalent classes, disjoint classes, and typed
properties. Relations declare domain and range classes plus metadata that later
validation and reasoning work can consume. Names are stable external
identifiers suitable for mapping in future RDF or OWL adapters; this release
does not claim RDF, OWL, GraphQL, SPARQL, or Cypher compatibility.

## Schema projection

`ProjectSchemaToOntology` projects the current `ObjectType` and interface
registry into ontology classes. `mapped_kind` records the source object kind.
The schema registry remains authoritative for object validation: changing an
ontology class does not change an `ObjectType`, and callers refresh the
projection after schema changes. Projection does not rewrite graph objects.

Domain concepts such as customers, incidents, repositories, or invoices stay
in schemas and adapters rather than becoming built-in ontology concepts.

## Authorization and audit

Ontology calls require an authenticated principal. Definitions use the normal
ACL model with these object identifiers:

- `ontology` for ontology administration;
- `ontology:class:<name>` for one class; and
- `ontology:relation:<name>` for one relation.

Definitions without an ACL entry follow the existing world-readable ACL
default. Once grants exist for a definition, list operations omit it for
unauthorized principals. Mutations require ontology, schema, or definition
administration and append a decision to the tamper-evident audit ledger in the
same SQLite transaction as the definition change.

## Validation and deletion

Definitions reject missing references, inheritance cycles, invalid
cardinality, and direct equivalence/disjointness contradictions. A class cannot
be deleted while another class or relation references it. A relation cannot be
deleted while another relation names it as an inverse.

Mapped relation domain and range constraints are enforced on new links and
relevant object-kind updates. Existing links are not rewritten. Cardinality,
inverse, and transitivity metadata do not synthesize links or facts.
