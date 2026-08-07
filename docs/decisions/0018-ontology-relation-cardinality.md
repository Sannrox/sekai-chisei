# ADR 0018: Keep ontology relation cardinality advisory in 1.x

- Status: accepted
- Date: 2026-08-07
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/542
- Supersedes: none
- Superseded by: none

## Context

`OntologyRelation.cardinality` is durable relation metadata with a minimum and
optional maximum bound. Relation-definition validation rejects malformed ranges,
while mapped domain and range constraints are enforced when links are admitted.
Cardinality is not currently enforced against graph state in either backend.

The link store does not define a unique `(from, relation, to)` identity, and
the current write paths do not establish whether cardinality counts rows,
distinct endpoint pairs, or some other qualified scope. Minimum bounds also
cannot be proved by one link admission. Enforcing either bound would therefore
require an explicit contract for duplicates, updates, definition publication,
concurrency, backend transactions, and existing data.

This decision resolves [Issue #542](https://github.com/Sannrox/sekai-chisei/issues/542),
building on [Issue #142](https://github.com/Sannrox/sekai-chisei/issues/142),
which established domain/range enforcement and left cardinality out of scope.

## Decision

Keep ontology relation cardinality advisory for the 1.x contract.

- Persist and expose `min` and `max` as relation metadata.
- Continue to reject malformed declarations, including `max < min`.
- Do not reject link creation, link updates, or relation-definition updates
  because an existing or resulting graph would violate cardinality.
- Do not assign implicit duplicate-counting, subject/target scope, or
  concurrency semantics to the bounds.
- Do not synthesize inverse links or facts, repair or delete existing links, or
  retroactively reject historical graph state.
- Keep mapped domain/range validation as the enforced ontology write boundary.

The authoritative guidance is [the ontology documentation](../ontology.md).
Any future cardinality enforcement must be proposed as a new bounded decision
with explicit SQLite/PostgreSQL parity and operator-authorized handling of
already persisted state.

## Alternatives considered

- **Enforce maximum cardinality only:** supplies a useful-looking constraint,
  but still requires a counted identity, duplicate semantics, and race-safe
  transactions that the current contract does not define.
- **Enforce minimum and maximum cardinality:** provides the strongest invariant,
  but minimum validation needs lifecycle or publication semantics and existing
  data would need an explicit preflight/remediation path.
- **Defer enforcement to semantic preflight:** preserves a permissive graph
  store, but still needs a separately specified counted scope and must not be
  presented as a write-time invariant.
- **Keep advisory metadata:** preserves deterministic provider-neutral writes,
  avoids silent graph mutation, and makes the missing semantics visible. This
  is the selected 1.x contract.

## Consequences

Current definitions and links require no migration, rewrite, repair, or delete.
Consumers must treat cardinality as descriptive metadata rather than a proof
that the graph conforms to the declared bounds. There is no cardinality
conflict error or enforcement receipt to depend on.

Future enforcement would be a new, potentially breaking boundary. Before it is
implemented, maintainers must decide the counted identity and scope, duplicate
and update behavior, minimum-bound lifecycle, relation-publication checks,
transaction/locking guarantees, backend conformance tests, stable bounded
errors and audit reasons, and an explicit remediation or migration authority
for existing state.

## Validation

- The source Issue records the alternatives, constraints, evidence required,
  and the accepted advisory outcome.
- `docs/ontology.md` and the `Cardinality` source documentation state the same
  1.x boundary.
- `sekai --db "$SEKAI_DB" --json validate` passes for the project ontology
  database; the portable ontology contains no cardinality-enforcement relation
  contract to rely on.
- A future enforcement proposal must add deterministic tests for both backends
  before changing this ADR's contract.
