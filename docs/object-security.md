# Object security policy

`sekai.object-security-policy/v1` is an immutable, namespace- and object-kind
scoped read policy. Operators install canonical JSON through
`PutObjectSecurityPolicyRevision`, then atomically activate a complete
kind-to-revision map through `ActivateObjectSecurityPolicies`. Inspection
RPCs (`GetObjectSecurityPolicyRevision`, `GetObjectSecurityActivation`) use
the same credential-admin boundary as mutation. The server computes the
content digest; generic object mutation cannot edit policy state.

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

Only the trusted authenticated context supplies subjects and scopes. Request
metadata is not authority. SQLite and PostgreSQL apply policy in SQL before a
direct row, `FindByExternalId`, or `ListObjects` total, ordering, filter,
limit, and offset is materialized. PostgreSQL parses property documents through `sekai_jsonb_object`, so
malformed or jsonb-rejected values are indeterminate and denied instead of
aborting the query. Unauthorized direct reads are returned as absent. Markings
and existing ACLs remain narrowing layers. Generic object writes reject NUL
property keys and values so new rows cannot poison PostgreSQL policy casts.

`ListObjects` may span activated and unactivated namespaces. Its storage
predicate applies each activated namespace's kind policy per row while
preserving legacy behavior for unactivated rows; no global activation state
changes an unactivated namespace's request shape.

## Unsupported follow-ups

Policy namespace and kind identities stay ASCII tokens (`[A-Za-z0-9_.:/-]`).
Open-taxonomy kinds with spaces or other characters cannot be activated until
a later identity migration. The v1 predicate vocabulary is unchanged; operation
context, entitlements, and additional operators remain out of scope. Property
and value-instance grants remain later issues.
