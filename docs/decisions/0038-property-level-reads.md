# ADR 0038: Authorize property-level reads before every public query surface

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/769
- Issue: https://github.com/Sannrox/sekai-chisei/issues/687 (#687)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0027](0027-explicit-property-grants.md),
  [ADR 0030](0030-row-scoped-query-access.md),
  [ADR 0044](0044-governed-geospatial-queries.md),
  [ADR 0049](0049-value-instance-access.md)

## Context

ADR 0027 added optional `property_grants` and omitted hidden values from
authorized get/list projections. ADR 0030 compiled the row predicate into every
public query operator. Named property predicates, sorts, traversal filters, and
computed properties could still observe a hidden value before the response
projector ran.

## Decision

Keep `property_grants` as the only property-level read relation. Every public
query operator authorizes named property predicates and sorts before count,
match, sort, traverse, export, or response materialization. Hidden properties
are omitted from the authorized projection after object, marking, and purpose
checks. They do not participate in filter, sort, aggregation, or traversal
matching. Computed properties evaluate only on that projection. Function pipeline
candidates are projected before filter, transform, or aggregate steps, and
named pipeline predicates or aggregate fields without a read grant fail closed.

Naming a hidden property and naming an unknown property produce the same
denial. Objects that differ only in hidden properties are indistinguishable on
authorized surfaces. Revocation applies on the next statement. Schema-restricted
redaction remains an additional post-grant layer.

SQLite is the reference store. PostgreSQL applies the same deny-before-query
and projection rules on the reusable graph surface.

## Alternatives considered

Client-side masking after fetch was rejected because filters and computed
fields would still see the values. A second property ACL was rejected because
ADR 0027 already owns the grant. Projecting inside
`get_object_with_policy_context` was rejected because marking evaluation reads
`access_marking` on the stored object first.

## Consequences

Operators who want property hiding install a policy revision that includes
`property_grants`. Value-instance access is recorded in ADR 0049.

## Validation

Pure tests cover hidden/unknown equivalence. Shared backend conformance covers
find, list sort, traverse, lineage, and revocation. SQLite runs in normal CI.
PostgreSQL follows the ignored isolated-database convention.
