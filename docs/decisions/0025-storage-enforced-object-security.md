# ADR 0025: Enforce activated object security in storage queries

- Status: accepted
- Date: 2026-08-24
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/724
- Issue: https://github.com/Sannrox/sekai-chisei/issues/667
- Follow-up: https://github.com/Sannrox/sekai-chisei/issues/729
- Supersedes: ADR 0007 fail-open behavior, only after explicit namespace activation
- Superseded by: none

## Context

Namespace authorization, object ACLs, and classification markings narrow graph
access, but no complete object-instance policy currently participates in every
query operator. Filtering after retrieval can disclose counts, ordering, or
pagination positions. A global deny-default change would also break existing
namespaces without an explicit rollout decision.

## Decision

Use immutable, namespace- and kind-scoped
`sekai.object-security-policy/v1` revisions. An atomic namespace activation
selects exactly one valid revision for every currently instantiated object
kind. Before activation, existing ACL, team-namespace, and marking behavior is
unchanged. After activation, missing, invalid, unknown, or backend-unsupported
policy denies.

The v1 read vocabulary is an OR of rules whose predicates are ANDed. It permits
only explicit `allow_all`, trusted subject equal to an object property, a
required principal scope equal to a fixed value, and an object property equal
to a fixed value. SQLite and PostgreSQL compile these predicates into object
SQL before rows, totals, ordering, filters, limits, offsets, remaining object
consumers, or mutation snapshots are materialized. Existing layers continue to
narrow the result. Writes reuse that same read relation: create authorizes
proposed state, delete authorizes current state, and update authorizes both.

## Alternatives considered

Per-object grants create lifecycle and query fan-out. Application-layer
post-filtering leaves aggregate side channels. A global fail-closed switch
would change inactive namespaces without an auditable activation.

## Consequences

Policy administration is separate from generic object mutation and produces
bounded, value-free audit rows. Rollback activates a prior valid revision; it
does not restore implicit grants.

Direct reads, `ListObjects`, remaining object consumers, transactional write
reauthorization, and authority-bound list cursors now use the same storage
relation. Markings remain an additional narrowing layer. The v1 vocabulary is
unchanged; property-level, row, purpose, and classification policies remain
later stages.

## Validation

Pure domain tests cover canonicalization, stable digests, deny-unknown
parsing, and page-token binding. Shared backend conformance covers immutable
replay, activation completeness, supported predicates, non-disclosing direct
denial, list operators, write reauthorization, remaining consumers, bounded
audit reasons, and immediate policy replacement. SQLite runs in normal CI;
PostgreSQL follows the ignored isolated-database convention.
