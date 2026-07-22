# ADR 0004: Represent graph history as bitemporal assertions

- Status: proposed
- Date: 2026-07-22
- Owners: @Sannrox
- Source: [Issue #146](https://github.com/Sannrox/sekai-chisei/issues/146)
- Discussion: this proposed ADR pull request is the solo-maintainer
  decision-review surface because GitHub Discussions are disabled
- Supersedes: none
- Superseded by: none

## Context

Sekai needs to answer both “what was believed to be true at domain time V?” and
“what did the control plane know at transaction time T?”. Current objects and
links expose only mutable state plus creation/update timestamps. Audit records
explain mutations, but an audit event is not evidence that a domain assertion
was true. External evidence also has its own source observation time, which can
precede admission and can arrive late.

The model must preserve corrections, conflicting sources, unknown interval
bounds, authorization, retention, legal holds, erasure, and lineage. It must be
practical on the complete SQLite runtime without pretending that the partial
PostgreSQL interfaces already provide graph parity. Future projections and
simulation remain owned by issue #148.

Temporal database literature distinguishes valid time (when a fact holds in
the modeled domain) from transaction time (when a version is present in the
database). PostgreSQL range documentation also uses half-open application-time
ranges because adjacent ranges then meet without overlapping. W3C PROV treats
derivation and revision as explicit provenance relationships rather than
inferring them from timestamp order.

## Decision

Sekai will add immutable, versioned **graph assertions** and derive current
object/link views from them. Each assertion version has these independent
dimensions:

- `valid_from` and `valid_to`: domain-validity bounds, each represented as one
  of `known(timestamp)`, `unbounded`, or `unknown`. Two known bounds form a
  half-open interval `[from, to)`. Unknown is never encoded as unbounded or
  “now”.
- `recorded_from` and `recorded_to`: a half-open interval over monotonic commit
  revisions assigned by Sekai and paired with system-recorded timestamps.
  Revisions, not millisecond timestamp order, select an exact database state
  and cannot be supplied by a caller. An open `recorded_to` identifies a
  currently recorded version.
- `source_observed_at`: optional provenance describing when a source observed
  or produced its evidence. It does not change valid or transaction time.
- `assertion_id` and `version`: stable logical identity and monotonic version.
  A correction closes the current recorded interval and appends a replacement
  version atomically; historical payloads are never overwritten.
- source, actor, evidence, and lineage references: attribution remains explicit
  and authorization-filterable. Temporal order alone never creates causality.

The payload represents a namespace-scoped subject, predicate, and value or
object reference. Object and link APIs remain compatibility projections over
the currently recorded assertions valid at the request's effective domain
time. Existing clients keep current-state behavior. New historical reads must
require both `valid_at` and `recorded_at` (with an explicit `now` default only
when the caller omits the historical selector), return the selected temporal
coordinates, and use stable pagination bound to those coordinates.

An as-of row satisfies:

```text
recorded_from <= recorded_revision < recorded_to (or recorded_to is open)
and
known/unbounded validity bounds contain valid_at
```

Unknown bounds are reported as unknown in responses. Query helpers must not
silently treat unknown as infinite certainty. The first API should expose an
`unknown_bounds` policy and default to excluding indeterminate matches.

Conflicting assertions from distinct sources coexist. Non-overlap is enforced
only within one assertion identity's transaction-time versions. Domain-valid
overlap is allowed and returned as a conflict set until an explicit,
attributable reconciliation decision selects or suppresses candidates. Such a
decision is itself versioned; it does not rewrite source history.

Audit remains a separate append-only ledger. Each assertion mutation and its
audit entry commit atomically, but audit answers who performed a control-plane
operation, not what was true at a domain time. Lineage records explicit
derivation, revision, and source relationships. Neither audit sequence nor
timestamp order is promoted to causal lineage.

Historical authorization is evaluated using the requester's **current** tenant
and namespace access plus the selected assertion version's classification and
object ACL. The initial API will not recreate historical grants: losing access
removes access to history, while gaining access does not reveal versions whose
classification is outside the new grant. Existence, counts, conflicts, and
pagination must not leak filtered versions.

Retention and erasure operate on assertion versions and their payloads, not on
the current projection alone. Legal holds block collection. Erasure may replace
a payload with a verifiable tombstone while retaining the minimum temporal,
audit, and lineage envelope required by policy. Historical reads must report a
non-disclosing omission rather than reconstruct or imply erased content.

## Worked models

Assume an employment assertion `works_for(Ada, Northwind)`.

### Correction

At transaction revision `T1`, Sekai records validity
`[2025-01-01, unbounded)`. At
`T2`, evidence shows employment actually began on `2025-02-01`. Version 1's
recorded interval becomes `[T1,T2)` and version 2 is appended with validity
`[2025-02-01, unbounded)` and recorded interval `[T2,unbounded)`. A query with
`recorded_revision=T1` reproduces the earlier belief; revision `T2` returns the
correction. Audit records the correction operation but is not queried as truth.

### Late evidence

A source observed on `2025-03-10` that Ada worked for Northwind during
`[2024-11-01,2024-12-01)`, but Sekai admits it at `T3` in 2026. Its valid time
is the 2024 interval, `source_observed_at` is 2025-03-10, and `recorded_from` is
revision `T3`. Before `T3` the fact is absent from transaction-time as-of
results even
though its domain-valid interval is earlier.

### Conflict and reconciliation

Source S1 asserts `works_for(Ada, Northwind)` while S2 asserts
`works_for(Ada, Contoso)` for the same valid interval. Both remain visible and
attributed. A later reconciliation may prefer S2 for a bounded interval, but
does not close or modify S1 merely because its timestamp is older.

### Retention and erasure

When S1's payload passes its retention window, no legal hold exists, and policy
permits collection, the payload is removed and a tombstone remains. An as-of
query that would have selected S1 returns a retention omission without values
or hidden identifiers. S2 and the reconciliation history remain independently
queryable if their policies permit it.

## Persistence and migration

The first vertical implementation should introduce an assertion table rather
than adding four timestamps to every existing graph table. A normalized row
keeps object and link history under one semantic contract and avoids rewriting
the existing tables before compatibility projections are proven. At minimum,
indexes must support:

- current projection by namespace, subject, predicate, and open
  `recorded_to`;
- bitemporal as-of filtering by namespace and both intervals; and
- source/evidence and assertion-version lookup for provenance and correction.

SQLite requires application-managed interval checks in the same transaction
that closes and appends a version. Its partial index support is useful for the
current projection. PostgreSQL should use timestamp range columns and GiST
exclusion constraints where available, while preserving the same nullable-bound
and conflict semantics. This is a future interface implementation obligation,
not a claim of present PostgreSQL parity.

Migration is additive and staged:

1. create assertion storage and indexes on fresh and upgraded databases;
2. backfill one open-ended version for each existing object and link, using its
   current payload, allocating a migration commit revision, while marking
   domain validity unknown rather than inventing it;
3. dual-write graph mutations and compare current projections;
4. move reads to the projection only after parity checks; and
5. remove dual-write compatibility code in a separately reviewed migration.

Backfill is idempotent and resumable. Rollback before step 4 ignores the new
tables. Rollback after reads switch requires a backup or a reverse projection;
operators must not downgrade silently after temporal-only corrections exist.

## Prototype and cost evidence

`scripts/temporal_semantics_spike.sh` creates a bounded SQLite prototype with
the proposed columns and indexes. On an Apple arm64 development host with
SQLite 3.51.0, 100,000 current rows occupied 10,354,688 bytes and 100,000
assertion versions occupied 28,434,432 bytes (2.75x). In 1,000 cold-process
point lookups, current-state lookup took 3.84 s and the bitemporal predicate
took 3.50 s. Process startup dominates this deliberately simple measurement;
the useful evidence is that both plans used their intended indexes and that one
version had a material storage cost. Figures are directional, not release
guarantees.

The spike does not model correction fan-out. Storage grows with assertion
versions, so release work must benchmark representative version counts,
conflict density, retention churn, WAL growth, migration time, and stable
pagination. Run it with:

```bash
scripts/temporal_semantics_spike.sh 100000
```

## Alternatives considered

- **Valid-time fields plus audit.** Smallest schema change, but audit cannot
  reliably reconstruct database belief, corrections, or late admission and
  would be misused as temporal truth.
- **Mutable domain-schema timestamps plus generic helpers.** Lets each domain
  choose semantics, but makes cross-domain as-of queries, authorization,
  retention, and conflicts inconsistent.
- **Immutable event log with projections only.** Strong provenance, but every
  historical query depends on replay semantics and schema-version handling.
  Assertions preserve immutable versions while allowing bounded indexed reads.
- **Versioned assertions without valid time.** Reproduces prior database state
  but cannot answer when a fact held in the modeled domain.
- **Three or more first-class temporal axes.** Observation, decision, and event
  times can matter, but promoting each to query axes creates ambiguous APIs.
  Keep them as typed provenance until a measured use case justifies another
  temporal dimension.

## Consequences

The model answers current, as-of, correction, and late-arrival questions
without conflating audit or source timestamps. It increases row count, index
size, mutation complexity, migration cost, and authorization test surface.
Current APIs remain compatible through projections; historical APIs are
additive. Retention and erasure can make a historical view intentionally
incomplete, and responses must make that incompleteness explicit.

Implementation should be split into focused issues for storage/migration,
current projection and mutation coupling, historical query/API behavior, and
retention/authorization/operational hardening. Future projections and
simulation remain out of scope.

## Validation

Before acceptance, review the vocabulary and unknown-bound policy in the linked
Design Discussion. The implementation must prove fresh/reopen/upgrade behavior,
atomic correction and audit coupling, late arrival, conflicts, denied-history
non-disclosure, retention omissions, erasure tombstones, stable bitemporal
pagination, and unchanged current-state clients. SQLite benchmarks must include
write amplification and multi-version data. PostgreSQL work must demonstrate
equivalent interval and conflict behavior rather than schema resemblance.

References:

- [Clifford and Isakowitz, transaction-time and valid-time semantics](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=1289024)
- [PostgreSQL range types and exclusion constraints](https://www.postgresql.org/docs/18/rangetypes.html)
- [W3C PROV-O derivation and revision relationships](https://www.w3.org/TR/prov-o/)
