# Epistemic descriptor

Existing Chisei planning and execution references carry an additive,
source-neutral projection named `chisei.epistemic-descriptor/v1`. It does not
create a new RPC, durable resource, or source of truth. Older protobuf clients
ignore the new fields and continue to read the original reference fields.

Each descriptor keeps three closed dimensions independent:

| Dimension | Values | v1 authority |
| --- | --- | --- |
| `origin_class` | `asserted`, `derived`, `hypothesis`, `unknown` | An admitted external evidence envelope is `asserted`; Kioku is `derived` only for the explicit `verified_binary_outcomes/v1` derivation contract. Other producer labels remain `unknown`. |
| `evidence_status` | `supported`, `contested`, `insufficient`, `unknown` | Kioku supporting/contradicting link stances. External evidence does not encode polarity in this projection and remains `unknown`. |
| `lifecycle_status` | `current`, `stale`, `retracted`, `superseded`, `unknown` | The authoritative source lifecycle. An active Kioku memory is `current`, a rejected Kioku memory is `retracted`, and an available evidence row is `current`. Candidate/other states remain `unknown`. |

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

`PipelineRunResult`, `ExecutionPlan.evidence_references`, and
`ExecutionPlan.memory_references` carry the descriptor additively. The run
result also returns the contract version so a caller can negotiate projection
semantics without a new endpoint. The gateway invokes the same `RunPipeline`
path and therefore receives the identical descriptor projection; it does not
interpret or reconstruct the metadata.

Receipt context metadata records the descriptor version and bounded aggregate
counts (descriptor, source rows, source refs, source digests, and truncation).
Receipts never store descriptor payload or raw context. The project ontology
records `ChiseiEpistemicDescriptor` as a read-only projection boundary related
to existing `ChiseiContextReference`; it is not durable epistemic authority.
