# ADR 0049: Enforce value-instance access as a cell grant

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/796
- Issue: https://github.com/Sannrox/sekai-chisei/issues/695 (#695)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0027](0027-explicit-property-grants.md),
  [ADR 0030](0030-row-scoped-query-access.md),
  [ADR 0038](0038-property-level-reads.md)

## Context

ADR 0030 compiles the authorized object set into every public query. ADR 0038
authorizes named property predicates before count, match, sort, traverse, or
export. After those checks, two authorized objects can still share a property
name while only one cell should be visible. Client masking, a second ACL, or a
historical grant would leak the twin cell through filter, sort, count, or
derived evaluation.

## Decision

Keep `sekai.object-security-policy/v1`. Add an optional
`value_instance_grants` array of `{object_id, property, value_digest, access}`
where `access` is `read` or `write` and `value_digest` is the canonical
`sekai.value-instance/v1` hex digest of the cell value. Omitting the field
preserves existing activations. When the field is present, including empty,
only listed cells apply.

Row predicates and property grants still run first. Every public query
operator authorizes the named cell before the value is examined. Hidden and
unknown cells share one unavailable result. Get, list, find, traverse, export,
and derived projections omit ungranted cells. Property sorts and non-equality
filters fail closed while cell grants are enforced, because storage ordering
and range matches would observe hidden cells. Objects that differ only in
hidden cells are indistinguishable on authorized surfaces. Computed and
geospatial evaluation run only on that authorized cell projection. Creates,
updates, and inbound synchronization require a `write` grant to introduce or
change a cell. Audit records operator, object, property, and outcome — not
the value.

Revocation applies on the next statement. Cursors cannot cross principals or
policy revisions. SQLite is the reference store. Reusable PostgreSQL shares
the same deny-before-query and in-process projection rules on the graph
surface.

## Alternatives considered

Client-side masking after fetch was rejected because filters and computed
fields would still see the cell. A second ACL was rejected because object
rules and property grants already own those layers. Treating a historical
grant as current authority was rejected because revocation must apply on the
next statement.

## Consequences

Operators who want cell hiding install a policy revision that includes
`value_instance_grants`. Property-level reads remain ADR 0038. Row-scoped
query access remains ADR 0030.

## Validation

Pure tests cover hidden/unknown equivalence and omission of twin cells. Shared
backend conformance covers get, list, find, filter, sort, traverse, and
revocation. SQLite runs in normal CI. PostgreSQL follows the ignored
isolated-database convention.
