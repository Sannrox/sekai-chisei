# Object security policies

Sekai can activate an immutable, namespace-scoped policy revision for every
advertised object type. Once a namespace profile is active, an object is
available only when its bound policy contains a matching rule. Missing,
revoked, malformed, stale, or unsupported policy state denies access.

Policies are an OR of rules; conditions within a rule are an AND. An empty
policy denies all objects. An empty rule is the explicit, audited compatibility
grant and is the only way to preserve broad access after activation.

## Supported policy vocabulary

Operands may reference:

- trusted principal attributes: `credential_kind`, `issuer`, `subject`,
  `tenant_id`, and enterprise allowlisted `x_*` attributes;
- mandatory-control entitlements supplied by authenticated enterprise
  composition;
- canonical scalar object properties declared by the object type;
- fixed policy values; and
- the operation (`read`, `query`, `traverse`, `create`, `update`, `delete`,
  `action`, `export`, or `sync`).

Supported operators are `equals`, `not_equals`, and entitlement `contains`.
Unknown inputs and computed, link, or struct properties are rejected or deny.
Policy evaluation never accepts request metadata or object discovery as
authority.

## Activation and rollback

1. Create immutable revisions with `CreateObjectSecurityPolicy`.
2. Bind exactly one valid, unrevoked revision for every advertised,
   non-governance object type.
3. Atomically activate the complete profile with
   `ActivateObjectSecurityProfile`. Replacements must provide the current
   profile digest. Activation revalidates every bound policy against the
   current advertised schema.
4. Roll back by activating a prior valid revision or a separately reviewed
   replacement. Revocation never restores implicit access.

Policy writes are idempotent per namespace, actor, and key. Exact replay returns
the recorded result; conflicting replay fails. Policy, idempotency result, and
bounded value-free audit metadata commit together on SQLite and PostgreSQL.
Properties referenced by any active policy cannot be removed or changed.
Unreferenced properties and type-level metadata may continue to evolve.

## Query and mutation behavior

Direct lookup and object list/query predicates combine namespace access, object
ACLs, and the active object policy in storage. Counts, ordering, filters,
offsets, and page limits therefore operate on the authorized relation. Opaque
list cursors bind the principal-context digest, namespace, active profile
including revocation state, query digest, and expiry; changed authority,
policy, or revocation rejects the cursor. The
cursor HMAC key is generated once and retained in shared database state, so
unexpired cursors remain valid across process restarts and replicas using the
same database.

Read and traversal adapters additionally remove unauthorized endpoints and
links before response shaping. Create evaluates the proposed object; update
evaluates current and proposed state; delete evaluates current state. Changing
a property used by policy also requires object-admin authority. Deletion audit
records retain a hidden authorization snapshot; object-change history evaluates
that snapshot and denies legacy orphan history that cannot be authorized.

## Migration from classification markings

Namespaces without an active profile retain ADR 0007 classification-marking
behavior. Operators should:

1. inventory all advertised types and policy-driving properties;
2. create and review one policy per type;
3. use an explicit empty-rule compatibility policy where broad access is
   temporarily required;
4. activate the complete profile atomically; and
5. replace compatibility policies with narrowing rules, using profile digests
   for compare-and-swap.

After activation, the object policy supersedes `access_marking` for that
namespace. Existing objects are not rewritten.

## Explicitly later layers

This foundation does not grant property/value visibility, purpose-bound access,
hierarchical classification, backing-dataset access, or action approval.
Property policies (#676, #687), richer row-query policy (#677), purpose (#678),
classification hierarchy (#679), and value-instance access (#695) remain
separate narrowing layers.
