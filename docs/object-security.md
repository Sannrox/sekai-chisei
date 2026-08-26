# Object security policy

`sekai.object-security-policy/v1` is an immutable, namespace- and object-kind
scoped read policy. Operators install canonical JSON through
`PutObjectSecurityPolicyRevision`, then atomically activate a complete
kind-to-revision map through `ActivateObjectSecurityPolicies`. Inspection
RPCs (`GetObjectSecurityPolicyRevision`, `GetObjectSecurityActivation`,
`PutPurposeAuthorization`, `RevokePurposeAuthorization`) use the same
credential-admin boundary as mutation. The server computes the content digest;
generic object mutation cannot edit policy or purpose-authorization state.

Inactive namespaces preserve existing ACL, team-namespace, and classification
marking behavior. Activated namespaces fail closed when policy is absent,
invalid, unsupported, or does not match. An intentionally broad rollout uses
an explicit `allow_all` rule.

The v1 vocabulary is deliberately small. Rules are ORed and predicates in each
rule are ANDed:

- `allow_all` (the only predicate in its rule);
- `subject_equals_property` with a validated object-property key;
- `required_scope_equals` with a fixed scope;
- `property_equals` with a validated key and fixed value.

Rules name an operation. Seeing an object (`read`) does not grant mutation.
Writes use `create`, `update`, and `delete` rules and reauthorize the locked
current row plus the proposed object before commit. Traversal, linked-object
reads, lineage, property search, and list pagination consume the same read
relation. Synchronization uses `sync` rules. A `page_token` binds principal
context, namespace, activation digest, query digest, and expiry; changed
authority or policy rejects the cursor.

Optional `property_grants` further restrict property visibility and mutation
after object access succeeds. Omitting the field keeps v1 behavior: every
property on an authorized object remains visible and writable under the
object-level rules. When the field is present, including as an empty array,
unmentioned properties have no grant. Hidden properties are omitted from
authorized reads, context, export, lineage, and synchronization projections;
they are never fetched for client-side masking. Filters, ordering, and
aggregation that name an ungranted property fail closed without distinguishing
hidden from absent properties. Creates and updates require a `write` grant to
set or change a property; omitted unreadable properties are preserved from the
stored object. Inbound synchronization requires a `write` grant for each source
property. Unknown grant attributes or access tokens deny the policy.

Only the trusted authenticated context supplies subjects and scopes. Request
metadata is not authority. SQLite and PostgreSQL apply one compiled read
predicate in SQL before a direct row, `FindByExternalId`, `FindByProperty`,
`ListObjects` total, ordering, filter, limit, offset, adjacency, traversal hop,
or lineage expansion is materialized. PostgreSQL parses property documents through `sekai_jsonb_object`, so
malformed or jsonb-rejected values are indeterminate and denied instead of
aborting the query. Unauthorized direct reads are returned as absent. Markings
and existing ACLs remain narrowing layers. When an activated policy names
`required_purpose`, public reads must present a live
`sekai.purpose-authorization/v1` through `x-sekai-purpose`. The authorization
is actor-bound, scoped, time-bounded, and pinned to the current activation
digest; it is not an object grant. Missing, incompatible, expired,
wrong-actor, stale, or out-of-scope purpose omits the row. List cursors bind
the presented purpose with the existing authority digest. Credential admins
issue and revoke authorizations through `PutPurposeAuthorization` and
`RevokePurposeAuthorization`. SQLite stores them; PostgreSQL fails closed as
unavailable. Generic object writes reject NUL
property keys and values so new rows cannot poison PostgreSQL policy casts.

`ListObjects` may span activated and unactivated namespaces. Its storage
predicate applies each activated namespace's kind policy per row while
preserving legacy behavior for unactivated rows; no global activation state
changes an unactivated namespace's request shape.

## Unsupported follow-ups

Policy namespace and kind identities stay ASCII tokens (`[A-Za-z0-9_.:/-]`).
Open-taxonomy kinds with spaces or other characters cannot be activated until
a later identity migration. The v1 predicate vocabulary is unchanged; operation
context, entitlements, and additional operators remain out of scope.
Value-instance grants remain a later issue.
