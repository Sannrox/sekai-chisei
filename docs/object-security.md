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

Only the trusted authenticated context supplies subjects and scopes. Request
metadata is not authority. SQLite and PostgreSQL apply policy in SQL before a
direct row, `FindByExternalId`, `ListObjects`, property search, linked-object
read, traversal hop, retrieval load, or mutation snapshot is materialized.
PostgreSQL parses property documents through `sekai_jsonb_object`, so
malformed or jsonb-rejected values are indeterminate and denied instead of
aborting the query. Unauthorized direct reads and hidden current objects are
returned as absent. Markings and existing ACLs remain narrowing layers. Generic
object writes reject NUL property keys and values so new rows cannot poison
PostgreSQL policy casts.

`ListObjects` may span activated and unactivated namespaces. Its storage
predicate applies each activated namespace's kind policy per row while
preserving legacy behavior for unactivated rows; no global activation state
changes an unactivated namespace's request shape. Page tokens bind principal
context, namespace, active policy revisions, query digest, and expiry. A
changed authority or policy rejects the token instead of continuing under mixed
authority. Offset remains accepted; a presented token overrides offset.

Activated writes reauthorize inside the mutation transaction. Creates authorize
the proposed object. Deletes authorize the current object. Updates require
authority over both current and proposed snapshots. Unauthorized proposed state
fails closed without disclosing protected values. Successful and denied writes
record a value-free audit row with the exact policy revision and a bounded
reason (`allow`, `deny_current`, or `deny_proposed`).

## Unsupported follow-ups

Policy namespace and kind identities stay ASCII tokens (`[A-Za-z0-9_.:/-]`).
Open-taxonomy kinds with spaces or other characters cannot be activated until
a later identity migration. The v1 rule language is unchanged: writes reuse the
landed read relation rather than adding operation-specific operators. Property
and property-value visibility, row-query extensions, purpose-bound access, and
hierarchical classifications remain later stages.
