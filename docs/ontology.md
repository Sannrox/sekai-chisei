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

## Read-only inspection artifact

Generate a browser-readable snapshot through the same authenticated gRPC path:

```bash
export SEKAI_AUTH_TOKEN='<operator token>'
cargo run --bin sekaictl -- ontology inspect \
  --target https://127.0.0.1:50051 \
  --root <object-id> \
  --authorization-context '<non-secret access-scope label>' \
  --output ontology-inspection.html
```

The default lifetime is one hour. Use `--ttl-seconds` to select a value from 1
second through 24 hours. Generation refuses to overwrite an existing path and,
on Unix, creates the file with mode `0600`. The generated HTML contains only
ontology definitions and entailment trace data returned by the API to the
current caller. It has no remote assets, service worker, browser storage,
bearer token, or live database connection.

Generation reads the complete authorized ontology lists before and after the
trace, computes a stable revision over both list responses, and fails if they
changed during the snapshot. The artifact labels this authorized snapshot
revision separately from the entailment revision. Retry the command after
concurrent ontology mutations finish.

The command also fails rather than exporting a trace when bounded retrieval is
truncated. Narrow the selected root or reduce the surrounding graph before
retrying; a partial provenance trace is never presented as complete.
An absent, deleted, or unauthorized root returns the same generic unavailable
error and does not create an empty artifact.

The inspection command accepts HTTPS endpoints and Unix sockets. It rejects
plaintext HTTP so the shared client cannot transmit an operator bearer token
without transport encryption.

The file is disclosed data after generation: later grant revocation cannot
remove data already exported. Check the prominent expiry status before relying
on it, choose an authorization-context label that describes the access scope
without containing a credential, and protect or delete the file according to
local handling and retention policy. Local filtering, counts, and detail
expansion operate only over the authorized snapshot and do not refresh it.

This first inspection surface is intentionally not an ontology editor or a
general administration console. See
[ADR 0003](decisions/0003-authenticated-static-ontology-inspection.md) for the
trust-boundary decision.
