# ADR 0044: Query governed geospatial properties after property authorization

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/787
- Issue: https://github.com/Sannrox/sekai-chisei/issues/680 (#680)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0027](0027-explicit-property-grants.md),
  [ADR 0030](0030-row-scoped-query-access.md),
  [ADR 0038](0038-property-level-reads.md)

## Context

Objects can store location claims, but spatial comparison is not a write or
permit surface. Client-side filtering, a second geospatial ACL, or a first
spatial index would invent a parallel authorized relation beside ADR 0027 and
ADR 0038.

## Decision

A stored geometry is a `sekai.geospatial-value/v1` JSON claim on a named object
property. Version 1 admits `point` and `polygon` in `EPSG:4326` only. The claim
stays on the object. There is no spatial index table and no second ACL.

A spatial comparison is a `sekai.geospatial-query/v1` effect identified by
`(namespace, kind?, property, operator, geometry, max_distance_m?)`. Operators
are `point`, `distance`, `contains`, and `intersects`. The named property is
authorized before count, match, sort, or materialization. Hidden and unknown
property names return the same unavailable result. Hidden and absent objects
are indistinguishable in hits and totals.

Invalid query CRS, geometry, operator, or version fails as a query error before
any object is examined. Invalid or foreign stored geometry is a non-match.
Cross-namespace queries are denied before access. Counts and pages cover only
the authorized match set. Audit records operator, property, namespace, and
total — not coordinates.

SQLite and the reusable PostgreSQL graph surface share the same in-process
evaluator after the existing object-security list.

## Alternatives considered

Client-side filtering would leak hidden values. Adding distance or intersects
to `PropertyFilter.op` would overload the grant-checked equality surface.
Making a spatial extension the first store would introduce a second persistence
contract. A second geospatial ACL would compete with ADR 0027 and ADR 0038.

## Consequences

Operators can compare authorized location claims without expanding write or
permit authority. Follow-up work may add a gRPC transport or later CRS and
geometry kinds.

## Validation

Deterministic tests cover authorized point, distance, contains, and intersects
fixtures; invalid query errors before object examination; invalid stored
geometry as a non-match; hidden ≡ unknown property names; hidden ≡ absent
objects; revocation on the next query; counts and pages over the authorized
match set; and the shared evaluator after the object-security list.
