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
not create audit decisions, receipts, or exported assurance records.

Every response has `cache_scope = "authorization_context"`. Cache entries only
for the exact authenticated principal set, namespace, contract version, and
catalog version. Never share a response or page token across callers.

Visibility is descriptive, not an authorization grant. Invocation rechecks
namespace membership, object ACLs, policy, budgets, approval, object state, and
current schema. A previously visible action can therefore be denied or held
for approval later.

## Governed invocation binding

The v1 receipt-attributed binding covers typed object-query entries and
governed-action entries. Invoke those entries through the canonical RPC named
by `input_type` and send `x-sekai-capability` with the discovered capability
name. Action calls also send `x-sekai-namespace`; query calls use the namespace
in their existing filter. An optional `x-sekai-operation-id` supplies caller
correlation and is atomically reserved before an effectful action. The server
generates one when omitted and returns the effective identifier on successful
response metadata. Callers that need to correlate a refused or failed RPC must
supply the header, because generic gRPC error propagation does not guarantee
generated response metadata. Traverse, context retrieval, and Kioku candidate
entries continue to use their canonical governed RPCs but do not yet
participate in this receipt-attribution metadata contract.

The binding is deliberately not a generic execution endpoint. Before entering
the normal query or action implementation, the server rebuilds the catalog for
the authenticated authorization context and verifies that the named entry is
still visible and matches the requested object kind or action type. A revoked
credential, removed grant, changed action policy, or unavailable capability is
therefore enforced even when the caller cached an older catalog.

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

## Capability packages

The `sekai.capability-package/v1` manifest groups declarative schema, relation,
action, policy-default, evaluation-suite, retrieval-rule, and adapter
declarations into one immutable package version. Package content is data only
and uses closed, kind-specific schemas with no free-form payload, executable,
credential-value, or authority-grant fields. Identifier validation also rejects
common credential shapes before storage. Installation cannot widen authority;
normal namespace, action-policy, approval, retention, and audit boundaries
still apply when packaged declarations are consumed.

Lifecycle RPCs require namespace write access and action-admin authority. The
server derives the actor from authenticated metadata and records install,
evaluate, upgrade, rollback, disable, and uninstall events atomically with
lifecycle state. Request IDs are actor- and namespace-scoped and bound to
canonical input, so an ambiguous retry cannot apply different content.

Uninstall removes only the active installation. Immutable manifests and the
append-only event stream remain as evidence. Package state is namespace-scoped,
so neither installation nor removal mutates another namespace. The manually
authored versions under `examples/capability-packages/` are the single proving
package; they are not a registry or distribution mechanism.

Lifecycle persistence is covered by shared SQLite/PostgreSQL conformance for
the reusable Sekai surface. This catalog still does not claim automatic
authoring, remote distribution, or executable plugin installation, and it does
not activate community PostgreSQL runtime selection by itself.
