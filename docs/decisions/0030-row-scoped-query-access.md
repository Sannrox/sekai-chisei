# ADR 0030: Apply one compiled row predicate to every public query path

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/753
- Issue: https://github.com/Sannrox/sekai-chisei/issues/677
- Supersedes: none
- Superseded by: none

## Context

ADR 0025 compiles activated `sekai.object-security-policy/v1` read rules into
storage for direct get and `ListObjects`. Other public query operators still
loaded candidate rows and filtered them in process. That left a second
authorized relation: property search, adjacency, traversal, and lineage could
observe hidden rows while computing counts, hops, or totals.

## Decision

Treat the authorized object set as one storage relation. The plane compiles the
caller's trusted subjects and scopes into the same read predicate used for get
and list. Every public query operator applies that predicate in SQL before
count, sort, filter, limit, offset, or graph expansion:

- `GetObject` / `FindByExternalId`
- `ListObjects`
- `FindByProperty`
- `GetLinks` / `GetLinkedObjects`
- `Traverse` / `GetLineage`

A hidden row is omitted and is observationally identical to an absent row.
Missing, stale, unknown, or cross-namespace authority denies before access.
Revocation applies on the next statement. List cursors remain bound to
principal context, activation, and query digest.

Signature, discovery, and client filters are not authority. ACL, team-namespace,
and markings remain additional narrowing layers. Property-level grants stay a
later issue.

## Alternatives considered

Application post-filtering keeps one code path but reconstitutes count, order,
and hop side channels. Distinct per-operator predicates would drift. Compiling
ACL and markings into the same SQL clause is a later tightening, not required
to close the object-security leak.

## Consequences

SQLite is the reference store. PostgreSQL applies the same predicate on the
reusable graph surface. Graph expansion does not walk hidden intermediates, so
a visible descendant reachable only through a hidden hop stays omitted.
Internal control-plane readers that are not public query operators may still
use unscoped graph helpers.

## Validation

Shared backend conformance covers property search, external-id lookup, adjacency,
traversal, and lineage against the same owner predicate. SQLite runs in normal
CI. PostgreSQL follows the ignored isolated-database convention.
