# ADR 0032: Evaluate markings against a namespace-local classification lattice

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/757
- Issue: https://github.com/Sannrox/sekai-chisei/issues/679
- Supersedes: none
- Superseded by: none
- Related: [ADR 0007](0007-provisional-classification-markings.md)

## Context

ADR 0007 compares object `access_marking` values against a sealed principal
ceiling using the evidence ordinal `public < internal < confidential <
restricted`. That single chain cannot express incomparable compartments or
namespace-local tokens.

## Decision

Classifications are a namespace-local lattice, not a free string. Each
namespace may publish `sekai.classification-lattice/v1` naming tokens, parent
edges, and explicit incomparable pairs. Dominance is reachability: a read or
action is allowed only when every applicable marking is dominated by the
caller’s sealed ceiling.

Inheritance is object-centric. A child or derived hop takes the least upper
bound of its own marking and the markings of objects it may not hop through.
If that join does not exist, the markings are incomparable and the row is
denied. Hidden rows stay observationally identical to absent rows.

Unknown tokens, a stored lattice whose digest or namespace no longer matches,
or reuse of another namespace’s lattice fail closed. Unmarked data and
namespaces that never activate a lattice stay on today’s single-token ceiling.
The sealed `classification_ceiling` remains one global principal-profile token
and is interpreted in the object’s namespace lattice. Operators who need
isolated compartments must not reuse the same custom token name across
lattices.
Trusted service principals remain an explicit exception. SQLite is the
reference store. PostgreSQL get returns no lattice so the ordinal ceiling
stays in force; put is unavailable.

Credential admins publish and inspect the lattice through
`PutClassificationLattice` and `GetClassificationLattice`.

## Alternatives considered

A global shared lattice cannot name namespace-local compartments. Treating
tokens as free strings has no dominance rule. Inferring parentage from
naming conventions is not an explicit typed contract.

## Consequences

Operators who need compartments or extra tokens publish a lattice before
marking objects with those tokens. Existing unmarked deployments and
unactivated namespaces keep ADR 0007 behavior. Purpose-bound reads and
property-level grants remain separate contracts. Signed namespace snapshots
still carry only the evidence ordinal; custom lattice tokens are omitted on
export and fail closed on import until a later federation contract includes
the lattice.

## Validation

Pure tests cover dominance, incomparable join, unknown tokens, and the
unactivated ordinal fallback. SQLite persists lattices in normal CI.
PostgreSQL get remains empty so default-ceiling reads stay available.
