# Capability catalog

The native capability catalog lets an authenticated runtime learn which
governed Sekai and Chisei surfaces are visible in one namespace without
hard-coding every object kind or action name. Call
`SekaiService.DiscoverCapabilities` with a canonical namespace and the same
authenticated principal metadata used for invocation.

The catalog contract is currently version `1.0`. An empty `contract_version`
negotiates that version; an unsupported version fails with
`FAILED_PRECONDITION`. Responses contain a content-derived `catalog_version`.
Pass that value with `page_token` on later pages. If visible schemas, actions,
or effective action policy change, the old snapshot fails with `ABORTED`
instead of mixing entries from different snapshots.

Catalog entries are ordered by capability name and describe:

- lifecycle and compatibility state;
- canonical protobuf input and output message names;
- required namespace/object scopes and policy decision points;
- bounded query, retrieval, or mutation limits;
- action risk and effective approval behavior;
- evidence requirements for Kioku candidate retrieval; and
- bounded epistemic-descriptor projection limits and backend capability
  metadata where a reusable surface differs by SQLite versus PostgreSQL; and
- the existing `ObjectType` or `ActionTypeDef` where a schema applies.

`ObjectType` and `ActionTypeDef` remain the schema sources of truth. The
catalog does not define another JSON Schema or tool-schema vocabulary. Because
the built-in `create_object` action accepts schema properties as top-level
parameters, discovery projects a separate create capability for each visible
object type and copies that type's canonical property types, requirements, and
enum values into the existing `ActionTypeDef` parameter vocabulary.

## Authorization and caching

Discovery first authenticates the caller and checks namespace membership. It
then removes schema types hidden by schema ACLs, action types hidden by action
ACLs or referenced hidden schemas, and actions currently denied by effective
action policy. Denials use generic errors and do not include hidden names,
schemas, lifecycle data, policy rules, or replacements. Discovery itself does
not create audit decisions or receipts.

Every response has `cache_scope = "authorization_context"`. Cache entries only
for the exact authenticated principal set, namespace, contract version, and
catalog version. Never share a response or page token across callers.

Visibility is descriptive, not an authorization grant. Invocation rechecks
namespace membership, object ACLs, policy, budgets, approval, object state, and
current schema. A previously visible action can therefore be denied or held
for approval later.

## Governed invocation binding

The v1 receipt-attributed binding covers typed object-query entries,
governed-action entries, and the semantic retrieval capabilities below. Invoke
those entries through the canonical RPC named by `input_type` and send
`x-sekai-capability` with the discovered capability name. Action and semantic
calls also send `x-sekai-namespace`; object-query calls use the namespace in
their existing filter. An optional `x-sekai-operation-id` supplies caller
correlation and is atomically reserved before an effectful action. The server
generates one when omitted and returns the effective identifier on successful
response metadata. Callers that need to correlate a refused or failed RPC must
supply the header, because generic gRPC error propagation does not guarantee
generated response metadata. Traverse and Kioku candidate entries continue to
use their canonical governed RPCs but do not yet participate in this
receipt-attribution metadata contract.

The binding is deliberately not a generic execution endpoint. Before entering
the normal query, retrieval, or action implementation, the server rebuilds the
catalog for the authenticated authorization context and verifies that the named
entry is still visible and matches the requested object kind, action type, or
semantic capability. A revoked credential, removed grant, changed action
policy, or unavailable capability is therefore enforced even when the caller
cached an older catalog.

## Semantic retrieval capabilities

Agent runtimes should compose the following discoverable capabilities instead
of hard-coding graph RPC sequences. Natural-language planning and summarization
stay with the runtime or a governed model call; Sekai returns structured
results, truncation metadata, evidence references, and receipts only.

| Capability | RPC / input type | Product tier | Purpose |
| --- | --- | --- | --- |
| `sekai.semantic.expand_relations` | `ExpandRelations` | **core** | Expand authorized relations from one root in `asserted_only` or `entailment` reasoning mode with hard bounds. |
| `sekai.context.retrieve` | `RetrieveContext` | **core** | Retrieve bounded context candidates with per-candidate provenance. Catalog binding requires `x-sekai-namespace`. |
| `sekai.semantic.explain_derivation` | `ExplainDerivation` | **core** | Return the authorized derivation explanation from `from` to `to` without hidden policy inputs. Denied intermediates yield `found=false`. |

### Product tier filter (core pack)

RPC inventories and catalog entries use `product_tier`: `core` | `advanced` |
`experimental`. This is **orthogonal** to backend completeness
(`complete_*_surfaces` in the RPC inventories).

Agents should start with the **core pack**:

```text
DiscoverCapabilitiesRequest {
  namespace: "...",
  product_tier_filter: "core",
}
```

Empty `product_tier_filter` returns the stable core catalog. Use `all` to
request the full authorized catalog, or name `advanced` or `experimental`
explicitly. Each `CapabilityEntry` also carries `product_tier` for client-side
filtering.

Each entry advertises:

- protobuf input and output types;
- required scopes and policy decision points (`namespace_access`, `object_acl`,
  `classification`, `ontology_acl` as applicable);
- hard bounds (`max_depth`, `max_objects`, `max_links`, source/derived row caps,
  time, explanation size);
- `reasoning_profile_version` and `ontology_contract_version`; and
- evidence requirements such as derivation steps, source fact ids, and ontology
  revision.

A typical compose order is resolve → expand → retrieve → explain. Each step
rechecks authorization independently; a cached catalog version is observational
provenance on the receipt (`reported_catalog_version`), not a grant.

The graph retrieval capabilities advertise
`epistemic_descriptor_projection` and bounded descriptor source-list limits.
Asserted graph retrieval is available on both reusable community backends.
Query-time ontology entailment is currently SQLite-only; PostgreSQL advertises
the unsupported backend value and the RPC fails closed with
`FAILED_PRECONDITION` rather than returning a partial ontology snapshot.
Scenario graph reads advertise both backends while remaining request-scoped
and non-durable.

## Lookup-first answers (S1 / #281)

When `ChiseiService.ExecutePlanStream` is invoked with
`ExecutionInput.task_type` set to an **allow-listed** semantic capability id
and `spec` holding that capability's fixed structured JSON input, Chisei may
short-circuit **after** namespace authorization and **before** provider routing:

| Capability | Lookup-first short-circuit |
| --- | --- |
| `sekai.semantic.resolve_ref` | S1 full hit returns structured JSON with **zero provider tokens** (`provider=lookup`, `answer_path=lookup_hit`). |
| `sekai.semantic.expand_relations` | S2 full authorized hit returns the native candidate/link response shape with zero provider tokens; any ACL miss, unresolved root, schema miss, or truncation falls back to the model. |
| `sekai.context.retrieve` | S2 full authorized hit returns the native candidate/link/explanation/descriptor response shape with zero provider tokens; any ACL miss, unresolved root, schema miss, or truncation falls back to the model. |
| `sekai.semantic.explain_derivation` | S2 full authorized hit returns the native explanation/evidence/descriptor shape with zero provider tokens. A complete authorized `found=false` result is also a hit; incomplete or truncated traversal falls back to the model. |

Fail closed: incomplete graph state, ACL miss, cross-namespace object, or
schema miss records `lookup_refusal` on the operation receipt and continues on
the normal model path (`answer_path=model_path`). The S2 traversal path also
refuses PostgreSQL entailment because the native community runtime has no
authorization-filtered ontology snapshot there; callers may use asserted-only
retrieval. Lookup evaluation occurs after execution namespace authorization and
before provider selection, residency, egress, or model payload preparation.
Free-form natural-language substitution is out of scope. Fixture suite (hit /
incomplete / cross-namespace / ACL / truncation) and dual-run structural
equality live under
`tests/fixtures/lookup_first/` and `chisei::lookup_first`. No fleet-wide spend
percentage is claimed from this surface.

The deterministic promotion boundary is the separate
[lookup-first promotion gate](lookup-first-promotion-gate.md). Its v1 suite
requires structured golden answers, rejects free-form NL and cheap-model arms,
records bounded `lookup_first.gate` audit evidence, and never applies route
policy automatically.

Attributed invocations write a canonical `operation.receipt/v1` record with
intent, live policy, native routing, budget-check, and outcome events. Receipt
and audit evidence contain principal identifiers and opaque approval or permit
references, never bearer tokens, token hashes, provider secrets, or request
authorization metadata.

Runtime authentication continues to use scoped principal credentials. Tokens
are returned only when issued, stored as hashes, resolved to the runtime
principal by the transport interceptor, and revocable through the existing
credential administration RPCs. Host-executed effects use the narrower signed
permit and delegation-chain contracts documented in
`external-action-execution.md`; catalog discovery does not mint or extend
either form of authority.

## Related capability surfaces

### MCP and SDK projections

`ProjectedCapability` is the replaceable projection boundary for MCP tools and
thin Rust, TypeScript, and Python clients. It is constructed only from an
authorization-filtered native catalog entry and records the exact namespace,
principal, contract version, and catalog snapshot that produced it.

The MCP projection exposes the canonical capability name as the tool name. Its
`_meta` field carries the complete projected contract, including native input
and output types, embedded object or action schemas, required scopes, decision
points, limits, lifecycle state, and compatibility bounds. MCP annotations are
only descriptive hints and never grant authority. Tool calls require an
explicit `operation_id` and are rebound to the native RPC rather than executed
by an independent MCP policy path.

The SDK bindings under `sdk/` consume the same serialized projection. Every
binding fails closed on version drift and binds these native metadata fields:

- `x-principal`
- `x-sekai-namespace`
- `x-sekai-capability`
- `x-sekai-operation-id`
- `x-chisei-work-unit` (the same operation ID, for approval and budget correlation)
- `x-sekai-catalog-version`

The catalog version is observational provenance rather than authority. The
server records it as the runtime-reported catalog version in the operation
receipt so an operator can distinguish what the runtime says it discovered
from the capability that it selected; live policy and authorization are still
rechecked at invocation time.

The server still rechecks live namespace access, object ACLs, action policy,
budget, and approval state. A cached projection is therefore discovery data,
not a credential or authorization token. Shared conformance fixtures verify
that Rust, TypeScript, and Python preserve authority, error codes, attribution,
and operation correlation.

`GET /v1/chisei/capabilities` describes effective provider protocol features
for the compatible gateway. It is distinct from this namespace-scoped native
ontology catalog. Provider-owned tools are not projected into the native
catalog unless a future contract can prove both an effective provider profile
and explicit policy permission.
