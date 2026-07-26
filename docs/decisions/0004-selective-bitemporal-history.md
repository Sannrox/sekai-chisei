# ADR 0004: Add selective bitemporal history to the current graph

- Status: accepted
- Date: 2026-07-22
- Owners: @Sannrox
- Source: [Issue #146](https://github.com/Sannrox/sekai-chisei/issues/146)
- Discussion: accepted via [PR #223](https://github.com/Sannrox/sekai-chisei/pull/223);
  storage implementation begins at Issue #225
- Supersedes: none
- Superseded by: none

## Context

Sekai needs to answer both “what was believed to be true at domain time V?” and
“what did the control plane know at transaction time T?” for governed facts.
Current objects and links expose mutable state plus creation/update timestamps.
Audit records explain mutations, but an audit event is not evidence that a
domain assertion was true. External evidence also has a source observation time
that can precede admission and arrive late.

The complete runtime is local-first and SQLite-backed. Database size, backup
cost, write amplification, migration time, and current-state latency therefore
matter as much as historical expressiveness. Most operational facts need only
their current state and audit trail. Making every graph property and link
bitemporal would charge every local deployment for history it may never query.

Where temporal history is enabled, the model must preserve corrections,
conflicting sources, unknown interval bounds, authorization, retention, legal
holds, erasure, and lineage. It must not imply parity with the partial
PostgreSQL interfaces. Future projections and simulation remain owned by issue
#148.

Temporal database literature distinguishes valid time (when a fact holds in
the modeled domain) from transaction time (when a version is present in the
database). PostgreSQL range documentation uses half-open application-time
ranges because adjacent ranges then meet without overlapping. W3C PROV treats
derivation and revision as explicit provenance relationships rather than
inferring them from timestamp order.

## Decision

Current `sekai_objects` and `sekai_links` remain the canonical, compact graph
and the default read path. Sekai will add **selective bitemporal history** that
an object type, property, or ontology relation must explicitly enable. There is
no implicit history for schemas that do not opt in, and audit is not replayed to
manufacture it later.

The temporal policy is versioned schema metadata. It names the covered
properties or relations, retention policy, classification behavior, and
whether conflicting source assertions are preserved. Enabling it affects only
new mutations unless an operator runs an explicit, bounded backfill. Disabling
it stops new history but follows retention and legal-hold policy for existing
versions; it never silently deletes them.

Each retained temporal assertion version has these independent dimensions:

- `valid_from` and `valid_to`: domain-validity bounds, each represented as
  `known(timestamp)`, `unbounded`, or `unknown`. Two known bounds form a
  half-open interval `[from, to)`. Unknown is never encoded as unbounded or
  “now”.
- `recorded_from` and `recorded_to`: a half-open interval over monotonic commit
  revisions assigned by Sekai and paired with system-recorded timestamps.
  Revisions select an exact database state and cannot be caller-supplied.
- `source_observed_at`: optional provenance describing when a source observed
  or produced evidence. It does not change valid or transaction time.
- stable assertion identity and monotonic version: a correction closes the
  current recorded interval and appends a replacement in the same transaction
  that updates current state. Historical payloads are never overwritten.
- source, actor, evidence, and lineage references: attribution remains explicit
  and authorization-filterable. Temporal order alone never creates causality.

The normal object and link APIs continue to read the current tables and incur
no temporal join. A mutation of temporal-enabled data updates current state,
appends its history version, and writes its audit entry atomically. New
historical reads require both a valid-time selector and a recorded revision,
return the selected coordinates, and use pagination bound to those coordinates.

An as-of row satisfies:

```text
recorded_from <= recorded_revision < recorded_to (or recorded_to is open)
and
known/unbounded validity bounds contain valid_at
```

Unknown bounds are reported as unknown. Query helpers must not silently treat
unknown as infinite certainty. The first API exposes an `unknown_bounds` policy
and defaults to excluding indeterminate matches.

Conflicting retained assertions from distinct sources coexist when the schema
policy enables conflict preservation. Non-overlap is enforced only within one
assertion identity's transaction-time versions. Domain-valid overlap is
returned as an attributed conflict set until an explicit reconciliation
decision selects or suppresses candidates. Reconciliation does not rewrite
source history.

Audit remains a separate append-only ledger. Audit answers who performed a
control-plane operation, not what was true at a domain time. Lineage records
explicit derivation, revision, and source relationships. Neither audit sequence
nor timestamp order is promoted to causal lineage.

Historical authorization uses the requester's current tenant and namespace
access plus the selected version's classification and object ACL. The initial
API does not recreate historical grants. Existence, counts, conflicts,
pagination, and timing must not leak filtered versions.

Retention and erasure operate on retained versions and payloads. Legal holds
block collection. Erasure may replace payload with a verifiable tombstone while
retaining the minimum temporal, audit, and lineage envelope required by policy.
Historical reads report a non-disclosing omission rather than reconstructing or
implying erased content.

## Worked models

Assume the `employment` relation opts into temporal history while an ephemeral
`active_session` relation does not.

### Correction

At revision `T1`, Sekai records `works_for(Ada, Northwind)` as valid from
2025-01-01. At `T2`, evidence shows employment began on 2025-02-01. The current
link is corrected, version 1 closes at `T2`, and version 2 is appended
atomically. A historical query at `T1` reproduces the earlier belief; `T2`
returns the correction. Audit records the operation but is not queried as
temporal truth.

### Non-temporal operational state

Changes to `active_session` update only the current link and normal audit
evidence. No as-of history is promised, no temporal indexes grow, and enabling
history later does not invent versions for past sessions.

### Late evidence and conflict

Evidence observed in 2025 but admitted at revision `T3` can carry a 2024 valid
interval. It is absent from transaction-time results before `T3`. If two
sources disagree for the same valid interval, both remain attributed when the
relation policy preserves conflicts; timestamp order does not choose a winner.

### Retention and erasure

When a retained payload passes its window, has no legal hold, and policy permits
collection, the payload is removed and a tombstone remains. An as-of query
reports a retention omission without values or hidden identifiers. Current
state remains independently governed and is not reconstructed from history.

## Persistence and migration

The first implementation adds a temporal policy registry and a normalized
history table beside the existing graph tables. It does not backfill or replace
all objects and links. Indexes are scoped to temporal rows and support:

- assertion identity and version lookup for correction;
- bitemporal as-of filtering by namespace, subject, predicate, and both
  intervals; and
- source/evidence lookup for provenance and reconciliation.

SQLite performs interval and policy checks in the transaction that updates
current state, closes the prior retained version, appends the replacement, and
writes audit. PostgreSQL should use timestamp ranges and GiST exclusion
constraints where available while preserving the same unknown-bound and
conflict semantics. This is a future implementation obligation, not a claim of
present parity.

Migration is additive:

1. create the policy registry, history table, and indexes on fresh and upgraded
   databases;
2. leave existing schemas non-temporal and existing current rows unchanged;
3. allow an operator to enable history prospectively per schema surface;
4. provide an explicit bounded backfill that creates one baseline version with
   unknown domain validity only when requested; and
5. permit rollback by disabling new history writes while retained rows remain
   governed until compatible software or an authorized export/collection path
   handles them.

Backfill is idempotent and resumable. A downgrade must fail explicitly when it
cannot preserve configured history obligations.

## Prototype and cost evidence

`scripts/temporal_semantics_spike.sh` creates a current-only database and a
selective database containing the same current rows plus history for a chosen
percentage. The initial universal-history experiment stored one assertion
version for every fact and used about 2.75 times the current-only file size.
That material local-storage cost is the reason universal history is rejected.

The revised default models 10 percent temporal coverage. Its output records the
current-only and selective file sizes, ratio, indexed current lookup, and
indexed historical lookup. On the same development host, 100,000 current rows
occupied 10,354,688 bytes; adding 10,000 temporal versions produced a
12,546,048-byte database, or 1.21 times the current-only size. Both lookup plans
used their intended indexes. Run it with:

```bash
scripts/temporal_semantics_spike.sh 100000 10
```

The spike is directional, not a release guarantee. It does not model correction
fan-out or compression. Release work must benchmark representative coverage,
version counts, conflict density, retention churn, WAL growth, migration time,
backup size, and stable pagination. Storage budgets and retention defaults must
be validated on constrained local deployments.

## Alternatives considered

- **Universal bitemporal assertions with current projections.** Provides one
  uniform historical model but makes all local deployments pay substantial
  storage, indexing, write, migration, and backup costs. Rejected as the
  default.
- **Valid-time fields plus audit.** Smaller, but audit cannot reliably
  reconstruct database belief, corrections, or late admission and would be
  misused as temporal truth.
- **Domain-specific timestamps without generic helpers.** Keeps storage local
  to each domain but makes as-of authorization, retention, and conflicts
  inconsistent.
- **Immutable event log with replayed projections.** Strong provenance, but
  historical reads depend on replay and schema-version semantics, and current
  state becomes unnecessarily indirect.
- **No temporal capability.** Lowest storage, but cannot satisfy governed
  correction, late-arrival, or dual-time questions where they are required.

## Consequences

Default graph storage and current reads stay compact. Temporal-enabled schema
surfaces gain correction, late-arrival, conflict, and as-of semantics at an
explicit storage and governance cost. Arbitrary history is unavailable for
surfaces that did not opt in before a change; that limitation must be visible in
schema discovery and historical query errors.

Implementation splits into policy/storage, atomic mutation history, historical
query/API behavior, and retention/operational hardening. Future projections and
simulation remain out of scope.

## Validation

The implementation must prove that non-temporal mutations create no history
rows and retain current performance. Temporal fixtures must cover prospective
enablement, explicit backfill, atomic correction and audit coupling, late
arrival, conflicts, denied-history non-disclosure, retention omissions, erasure
tombstones, and stable bitemporal pagination. SQLite gates must set storage,
write-amplification, backup, and migration budgets at multiple coverage and
version densities. PostgreSQL work must prove equivalent behavior rather than
schema resemblance.

References:

- [Clifford and Isakowitz, transaction-time and valid-time semantics](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=1289024)
- [PostgreSQL range types and exclusion constraints](https://www.postgresql.org/docs/18/rangetypes.html)
- [W3C PROV-O derivation and revision relationships](https://www.w3.org/TR/prov-o/)
