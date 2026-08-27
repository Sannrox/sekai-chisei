# ADR 0027: Deny property access without an explicit grant

- Status: proposed
- Date: 2026-08-25
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/724
- Issue: https://github.com/Sannrox/sekai-chisei/issues/676 (#676)
- Supersedes: none
- Superseded by: none

## Context

ADR 0025 activates namespace- and kind-scoped object security and compiles
object-level rules into storage queries. After an object is authorized, every
property on that object remains visible and writable. Query filters, exports,
lineage, synchronization, and mutation can therefore observe or change values
the caller should not see. Discussion 724 records that property policies apply
after object access and that a hidden property is omitted or represented by the
public redaction state, never fetched for client-side masking.

## Decision

Keep `sekai.object-security-policy/v1`. Add an optional `property_grants`
array of `{property, access}` where `access` is `read` or `write`. Omitting
the field preserves existing activations. When the field is present, including
empty, only listed grants apply.

Authorized reads, context, export, lineage, and synchronization projections
omit properties without a `read` grant. Filters, ordering, and aggregation
that name an ungranted property fail closed and do not distinguish hidden from
absent data. Creates, updates, and inbound source properties require a
`write` grant to introduce or change a value. Omitted unreadable properties
are preserved from stored state. Unknown grant attributes or access tokens
deny the policy. Object-level rules, markings, and ACLs still have to allow
the object first.

## Alternatives considered

Requiring property grants on every v1 policy would silently hide properties in
already-activated namespaces. Client-side masking after fetch leaks values to
the process and to filters. Per-property ACL rows recreate the grant fan-out
ADR 0025 rejected.

## Consequences

Operators who want property hiding install a new policy revision that includes
`property_grants` and activate it atomically. Cross-surface property-level
reads are recorded in ADR 0038. Value-instance access remains a separate
Issue.

## Validation

Pure domain tests cover digest stability when grants are omitted, unknown
access denial, omission of hidden properties, and fail-closed mutation.
Shared backend conformance covers authorized get/list projection and denial of
ungranted property filters on SQLite and PostgreSQL.
