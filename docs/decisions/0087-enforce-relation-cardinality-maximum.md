# ADR 0087: Enforce ontology relation maximum cardinality; keep the minimum advisory

- Status: accepted
- Date: 2026-09-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1098
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1089 (#1089)
- Supersedes: [ADR 0018](0018-ontology-relation-cardinality.md) for the maximum bound only
- Superseded by: none
- Related: [ADR 0080](0080-dual-community-runtime-storage.md)

## Context

ADR 0018 kept `min` and `max` advisory because the contract lacked a counted
identity, duplicate semantics, race-safe transactions, and a policy for
existing data. Evidence collected for #1089:

- **Link identity.** `sekai_links` rows are keyed by a generated `id`. There
  is no unique `(from_id, relation, to_id)`, so identical links can repeat.
  `(from_id, relation)` and `(to_id, relation)` are indexed on both
  backends, so counting a source's targets is an indexed read.
- **Write path.** Link admission enforces mapped domain and range only.
  Relation-definition validation rejects `max < min`.
- **Operator wording.** `docs/ontology.md` states that cardinality is
  advisory. `Cardinality` in `proto/sekai.proto` and the portable ontology
  crate carry the bounds with no enforcement claim. A declared `max: 1` still
  reads to an operator like an invariant the store does not hold.

Mature ontology platforms model link cardinality structurally. A to-one side
is an invariant of the storage shape: an object cannot hold two parents for
a to-one link. Many-to-many links carry no bound. Minimum or "required"
membership is a validation or lifecycle concern checked when an object is
completed. It is never checked per link write, because no single admission
can prove it.

## Decision

Enforce the maximum bound at link admission. Keep the minimum advisory. The
enforcement ships with [#1132](https://github.com/Sannrox/sekai-chisei/issues/1132).
Until that lands, ADR 0018's advisory contract governs both bounds.

- **Counted identity.** Count distinct target objects per
  `(from_id, relation)` among live links. A duplicate identical
  `(from, relation, to)` link does not count twice.
- **Race safety.** The count and the insert run in one write transaction on
  both backends. SQLite uses `BEGIN IMMEDIATE`. PostgreSQL takes a
  transaction-scoped advisory lock keyed on `(from_id, relation)`. Concurrent
  admissions of distinct targets admit at most `max`.
- **Existing state.** Nothing is rewritten, repaired, or deleted. A source
  already over the bound cannot gain another distinct target. A relation
  publication whose `max` is below existing graph state is refused, with the
  count of violating sources shown to the operator.
- **Disclosure.** A refusal carries one stable, bounded reason
  (`relation_cardinality_exceeded`) and no counts or identities of links the
  caller cannot see.
- **Parity.** SQLite and community PostgreSQL enforce the same semantics.
  There is no SQLite-only enforced flag.
- **Minimum.** `min` stays advisory metadata as ADR 0018 describes.

## Alternatives considered

- **Reaffirm advisory for both bounds (option 1).** Leaves `max: 1`
  declarations that the store does not hold. Operators already read them as
  invariants.
- **Enforce minimum and maximum (option 3).** A minimum cannot be proved by
  one link admission. It needs object-lifecycle validation and remediation
  of existing data, which belong to a separate decision if ever needed.
- **Add a unique `(from, relation, to)` identity.** Would change duplicate
  semantics for every relation and need a data migration. Counting distinct
  targets gives the bound without it.

## Consequences

Link admission becomes a potentially breaking boundary for relations that
declare `max`. Callers that relied on over-bound writes receive
`relation_cardinality_exceeded`. Existing over-bound data stays readable and
is reported, not repaired. Inverse-direction bounds are not counted.

## Validation

Implementation proof belongs to #1132: deterministic tests on both backends
for the bound, duplicates, concurrent admission, pre-existing over-bound
sources, and refused tightening publications, plus a PostgreSQL proof under
the isolated-database convention.
