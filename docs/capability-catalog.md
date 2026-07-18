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

## Related capability surfaces

`GET /v1/chisei/capabilities` describes effective provider protocol features
for the compatible gateway. It is distinct from this namespace-scoped native
ontology catalog. Provider-owned tools are not projected into the native
catalog unless a future contract can prove both an effective provider profile
and explicit policy permission.
