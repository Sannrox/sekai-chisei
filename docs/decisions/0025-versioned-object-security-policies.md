# 0025: Versioned object security policies

## Status

Accepted for the object-policy foundation (#667). This decision supersedes ADR
0007's fail-open rule after a namespace activates an object security profile.

## Context

Namespace ACLs and optional classification markings cannot define one complete
authorized object relation. Filtering after reads also risks leaking counts,
ordering, pagination state, traversal endpoints, or action targets.
Per-object ACL fan-out would be difficult to review and query consistently.

## Decision

1. Store immutable policy revisions scoped by namespace and object type.
2. Activate one complete namespace profile atomically. Every advertised
   non-governance type must have exactly one valid, unrevoked binding.
3. Treat rules as explicit grants and deny when no rule matches. An empty rule
   is the explicit broad compatibility grant; missing policy is never a grant.
4. Restrict rules to trusted principal context, mandatory entitlements,
   canonical scalar object properties, fixed values, and operation context.
5. Compile the same supported vocabulary into SQLite and PostgreSQL predicates
   so list filters, ordering, totals, and pagination operate on the authorized
   relation.
6. Bind opaque query cursors to principal context, namespace, active profile,
   query, and expiry, and retain their signing key in shared durable state.
7. Keep policy administration, idempotency evidence, and bounded audit durable.
   Enterprise composition may supply trusted inputs but cannot bypass policy.
8. Layer policy after credential and namespace scope and before later property,
   value, purpose, mutation, action, or effect controls.
9. Revalidate every binding at activation and prevent properties referenced by
   active policies from being removed or changed. Deleted-object history
   retains a private authorization snapshot; history without sufficient
   authorization state denies.

## Consequences

- Activation is explicit and may intentionally use a reviewed broad policy.
- Revocation or profile replacement affects subsequent requests immediately.
- Schema changes unrelated to active policy operands remain available.
- Unauthorized and absent identities use non-disclosing read behavior.
- Existing objects and wire shapes remain intact; list requests and responses
  gain additive cursor fields.
- ADR 0007 remains the compatibility behavior only for namespaces without an
  active profile.
- Property/value security and richer policy stages remain separate decisions.
