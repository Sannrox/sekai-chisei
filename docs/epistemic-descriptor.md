# Epistemic descriptor

Existing Chisei planning and execution references and Sekai graph/evidence
projections carry an additive, source-neutral projection named
`chisei.epistemic-descriptor/v1`. It does not create a new RPC, durable
resource, or source of truth. Older protobuf clients ignore the new fields and
continue to read the original reference fields.
The [#502 resource decision](research/502-epistemic-assertion-resource.md)
records why this projection remains sufficient and when that boundary may be
reopened.

Each descriptor keeps three closed dimensions independent:

| Dimension | Values | v1 authority |
| --- | --- | --- |
| `origin_class` | `asserted`, `derived`, `hypothesis`, `unknown` | An admitted external evidence envelope or asserted graph fact is `asserted`; an authorization-filtered ontology entailment is `derived`; a scenario impact is `hypothesis`; Kioku is `derived` only for the explicit `verified_binary_outcomes/v1` derivation contract. Other producer labels remain `unknown`. |
| `evidence_status` | `supported`, `contested`, `insufficient`, `unknown` | Kioku supporting/contradicting link stances. Graph facts, ontology derivations, scenarios, and external evidence do not encode an authorized polarity in this projection and remain `unknown`. |
| `lifecycle_status` | `current`, `stale`, `retracted`, `superseded`, `unknown` | The authoritative source lifecycle. An active Kioku memory and an asserted graph fact are `current`; a rejected Kioku memory is `retracted`; and available, stale, retracted, or superseded evidence rows preserve their source state. Scenario projections have no durable lifecycle and remain `unknown`. |

Missing or non-authoritative information is explicit `unknown` or omitted; it
is never guessed. `producer_confidence_bps` is carried as an upstream input
with `confidence_basis=producer_input`. It is not a Sekai trust score.

The descriptor may carry only bounded structural provenance after the normal
namespace, classification, and source authorization checks have succeeded:

- at most 8 source references and 8 source digests;
- at most 128 source rows, with a truncation flag;
- each source identifier or digest is at most 256 bytes;
- one derivation reference of at most 128 bytes;
- optional supporting/contradicting row counts; and
- one observation timestamp in the non-negative v1 range through 2100-01-01.

The internal descriptor is capped at 4 KiB. Digests, identifiers, lifecycle
labels, counts, and timestamps are metadata; source payload, claims, evidence
envelope content, and uncertainty text are not copied. The existing
`content_digest`, `evidence_operation_ids`, and evidence disclosure fields
remain subject to their existing authorization and egress rules.
If the independent list caps would still exceed the aggregate byte bound, the
projection trims only the tail of the admitted source lists before serialization;
authoritative scalar dimensions are retained.
Kioku-linked evidence digests are omitted in v1 because memory authorization
does not independently authorize each underlying receipt; admitted external
evidence may expose its own digest only through its existing source check.

## Sekai projections

`RetrieveContext` and `ExpandRelations` attach one descriptor to each returned
candidate after object, namespace, classification, and ontology ACL checks.
Asserted candidates use their bounded source fact IDs. Entailed candidates use
`origin_class=derived`, carry `derivation_ref=ontology_revision:<revision>`,
and retain the complete authorized ontology revision and derivation steps in
the existing explanation fields. The descriptor's source list is only a
bounded summary; it never replaces the exact explanation. `ExplainDerivation`
returns the same projection when a path is found.

`EvaluateScenario` attaches a descriptor to each impact row. Its origin is
always `hypothesis`, evidence status is `unknown`, and its lifecycle is
`unknown`; completion, delta evaluation, or a confidence-like input cannot
promote it to an assertion or supported evidence. Hidden seeds, endpoints,
links, and deltas are rejected before a row or descriptor is built.

Admitted evidence submission records and retained content responses attach the
external-evidence projection. Lifecycle transitions remain source-authoritative
and source identities are never reconciled or collapsed. Existing content and
ACL checks run before the descriptor is returned.

The graph retrieval path is reusable on SQLite and PostgreSQL for asserted
mode. Query-time ontology entailment depends on the authorization-filtered
ontology snapshot, which is currently a SQLite-only reusable surface; the
PostgreSQL runtime fails closed with an explicit unavailable capability rather
than returning a partial or unbounded projection. Scenario graph reads and
evidence submission metadata use the backend-neutral reusable surfaces; an
unsupported backend-specific content projection continues to fail closed.

`PipelineRunResult`, `ExecutionPlan.evidence_references`, and
`ExecutionPlan.memory_references` carry the descriptor additively. The run
result also returns the contract version so a caller can negotiate projection
semantics without a new endpoint. The gateway invokes the same `RunPipeline`
path and therefore receives the identical descriptor projection; it does not
interpret or reconstruct the metadata.

Receipt context metadata records the descriptor version and bounded aggregate
counts (descriptor, source rows, source refs, source digests, and truncation).
Receipts never store descriptor payload or raw context. The project ontology
records the read-only descriptor boundary and its source-to-projection
relations for Chisei references, Sekai graph facts, admitted evidence,
ontology derivations, and scenario hypotheses. These are provenance statements
about existing projections, not durable epistemic authority.
