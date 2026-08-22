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
The bounded interoperability research in [#501](research/501-epistemic-rdf-owl-prov-o.md)
defines what a future edge projection may preserve without changing that
boundary. Research [#658](research/658-query-time-entailment-constructs.md)
keeps the ADR 0001 evaluation profile; inverse and disjointness stay
authoring and inspection metadata.

## First-run product loop (`sekaictl`)

Research [#383](https://github.com/Sannrox/sekai-chisei/issues/383) defines the
supported product loop as **define ontology → seed facts → plan/execute →
receipt**. The CLI implements that loop without raw gRPC:

```bash
# Start the control plane (example: local insecure loopback).
SEKAI_INSECURE=1 cargo run

# Optional: create a principal credential when not using insecure mode.
# cargo run --bin sekaictl -- admin access credential create operator

# Apply a domain document (classes + relations). Non-builtin mapped_kind values
# are ensured as ObjectTypes before the ontology class is created.
export SEKAI_CREDENTIAL='<token-if-required>'
cargo run --bin sekaictl -- ontology apply \
  --file tests/fixtures/product_loop/domain-v1.json

# Seed objects and links (kinds must already exist: builtin or ensure_kind).
cargo run --bin sekaictl -- ontology seed \
  --file tests/fixtures/product_loop/seed-v1.json

# One governed operation (lookup-first resolve_ref — no external model required
# when the object is visible to the principal).
cargo run --bin sekaictl -- ontology run \
  --namespace demo \
  --task-type sekai.semantic.resolve_ref \
  --spec '{"object_id":"svc-api"}'

# Or chain apply → seed → lookup-first resolve → receipt hint:
cargo run --bin sekaictl -- ontology first-run \
  --domain tests/fixtures/product_loop/domain-v1.json \
  --seed tests/fixtures/product_loop/seed-v1.json \
  --resolve-object svc-api

# Inspect receipt (after a run that recorded one):
cargo run --bin sekaictl -- receipt <request-id> --request-id
```

**Kind materialization (#387):** creating an ontology class with a non-empty
`mapped_kind` **ensures** the ObjectType when missing (schema admin required;
ontology admin already implies schema admin). Builtin kinds such as `component`
already exist. `sekaictl ontology apply` may still call `CreateSchemaType`
proactively via `ensure_kind` for clarity; the server path is the durable
guarantee. Interface registry CRUD and schema-to-ontology projection are
internal implementation facilities rather than public 1.0 API. Use
ontology-first authoring.

Document versions:

- Domain: `sekai.ontology-product/v1` (`tests/fixtures/product_loop/domain-v1.json`)
- Seed: `sekai.seed/v1` (`tests/fixtures/product_loop/seed-v1.json`)

### Reference lookup-first domain pack

The maintained reference pack under
`tests/fixtures/lookup_first/reference_domain/` exercises the complete
structured lookup surface with a multi-hop reliability graph. It is loaded
through the same CLI path as any user-owned domain document:

```bash
PACK=tests/fixtures/lookup_first/reference_domain
cargo run --bin sekaictl -- ontology apply --file "$PACK/domain-v1.json"
cargo run --bin sekaictl -- ontology seed --file "$PACK/seed-v1.json"
```

The offline expected-path table is checked by
`ontology_product_cli::tests::reference_domain_pack_validates_versions_graph_and_lookup_paths`
and is also recorded in `lookup-first-v1.json`:

| Step | Expected `answer_path` | Expected refusal |
| --- | --- | --- |
| Resolve `service:checkout-api` | `lookup_hit` | — |
| Expand checkout dependencies to depth 2 | `lookup_hit` | — |
| Retrieve checkout context in both directions | `lookup_hit` | — |
| Explain checkout → ledger derivation | `lookup_hit` | — |
| Resolve unknown service | `model_path` | `incomplete` |

The four complete cases are S1/S2 structured hits with no provider call. The
unknown-service case demonstrates the fail-closed fallback boundary. This is
an example domain, not product ontology: the classes, custom kinds, relations,
and objects exist only in the checked-in pack and are not server built-ins.

Domain concepts stay in **your** fixtures, not in core protos. ADR 0003
`ontology inspect` remains a separate static HTML snapshot path.

## Schema and interface boundaries

The schema registry remains authoritative for object validation, and its
interface registry remains an internal validation substrate for built-in and
stored schema definitions. The public 1.0 API does not expose interface CRUD or
schema-to-ontology projection. Changing an ontology class does not change an
`ObjectType`, and ontology authoring never rewrites graph objects. For product
onboarding, use ontology-first apply (above).

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
same transaction as the definition change. On the community SQLite runtime that
transaction is local SQLite; on community PostgreSQL the public audited
mutation RPCs fail closed until dual-backend audit parity lands (see
[architecture.md](architecture.md#persistence) and
[postgres-sekai-parity.md](postgres-sekai-parity.md)).

## Validation and deletion

Definitions reject missing references, inheritance cycles, invalid
cardinality, and direct equivalence/disjointness contradictions. A class cannot
be deleted while another class or relation references it. A relation cannot be
deleted while another relation names it as an inverse.

Mapped relation domain and range constraints are enforced on new links and
relevant object-kind updates. Existing links are not rewritten. Cardinality is
advisory metadata in the 1.x contract: its declaration shape is validated, but
it does not reject links or relation-definition updates, count graph state, or
synthesize, repair, or delete facts. See [ADR 0018](decisions/0018-ontology-relation-cardinality.md).
Inverse and transitivity metadata do not synthesize links or facts.

## Read-only inspection artifact

Generate a browser-readable snapshot through the same authenticated gRPC path:

```bash
# Default target is ./data/sekai.sock (or CHISEI_GRPC_URL / SEKAI_SOCKET).
export SEKAI_CREDENTIAL='<operator token>'
cargo run --bin sekaictl -- ontology inspect \
  --root <object-id> \
  --authorization-context '<non-secret access-scope label>' \
  --output ontology-inspection.html
# TCP example: --target https://127.0.0.1:50051
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

## Evidence-driven definition proposals

The evidence-driven proposal workflow was retired from the 1.0 runtime
contract. Define and review ontology classes and relations directly through
the authenticated ontology mutation APIs; evidence projection remains
available for instance facts.
