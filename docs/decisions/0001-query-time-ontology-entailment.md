# ADR 0001: Evaluate bounded ontology entailment at query time

- Status: accepted
- Date: 2026-07-21
- Owners: @Sannrox
- Source: [Issue #143 research recommendation](https://github.com/Sannrox/sekai-chisei/issues/143#issuecomment-5037322028)
- Supersedes: none
- Superseded by: none

## Context

Sekai stores asserted graph facts and an ontology whose classes describe
inheritance, equivalence, and disjointness and whose relations can opt into
transitivity. Entailment-aware retrieval needs to derive useful results without
turning derived projections into authoritative facts, bypassing authorization,
or introducing an unbounded rule engine.

The first implementation must work with the complete SQLite runtime while the
implemented PostgreSQL interfaces remain partial. It must also preserve the
existing asserted-only behavior by default.

## Decision

Sekai will initially evaluate a fixed entailment profile at query time from an
immutable ontology snapshot. The profile contains:

- subclass and equivalence closure for ontology classes; and
- transitive closure only for relations explicitly marked `transitive`.

Evaluation is backward/query-time only. Derived facts are not persisted or
promoted into the asserted graph. A result derived by the profile must identify
its source fact IDs, ontology revision, ordered derivation steps, and whether
each step is asserted or derived.

Authorization filters source facts and intermediates before inference. Hidden
material must not affect returned results, counts, explanations, errors, or
truncation details. Evaluation must enforce independent limits for traversal
depth, source rows, derived rows, derivation steps, elapsed time, and memory,
and return explicit non-sensitive truncation metadata when a limit is reached.

Asserted-only remains the default. User-authored executable rules are outside
the profile. External RDF/OWL reasoners may be adapters only if they compile to
the same bounded internal semantics and preserve Sekai's authorization and
explanation contracts.

## Alternatives considered

- **Forward materialization.** It can accelerate repeated reads, but requires
  invalidation, stale-projection handling, transactional audit coupling,
  migration and rollback behavior, and backend parity before that benefit is
  justified.
- **Forward and backward reasoning together.** This creates two semantic and
  operational paths without evidence that both are necessary.
- **A constrained rule language.** Even a small language expands validation,
  execution, versioning, and governance beyond the fixed profile needed now.
- **An external reasoner as the core.** This weakens local-first operation and
  makes authorization and explanation behavior provider-dependent.

## Consequences

The asserted graph stays the sole durable source of truth, and ontology changes
cannot leave a persisted derived-fact store stale. Entailment-aware requests pay
bounded per-request compute and must carry an ontology snapshot/revision through
their explanations. Repeated workloads may eventually justify an
authorization-scoped cache, but cache entries are disposable projections and
must never become authoritative facts.

Issue [#144](https://github.com/Sannrox/sekai-chisei/issues/144) owns the first
vertical implementation. Research
[#658](../research/658-query-time-entailment-constructs.md) later kept this
profile and recorded the reopening test for any additional construct.
Research [#659](../research/659-derived-fact-admission.md) kept the same
no-persisted-derived-facts rule for governed functions and type revisions:
function pipelines and computed properties stay read-time overlays, and
Action object mutations remain asserted writes. A future
proposal for materialization or additional rule profiles requires new
measurements and a superseding decision.

## Validation

The research spike evaluated 10,000 query-time closures over synthetic ontology
DAGs of 100, 1,000, and 10,000 classes. On the development host, the 10,000-class
case took approximately 10–15 ms for all queries. Full materialization produced
about 203,000 closure pairs and took 10–15 ms both initially and after one
ontology mutation. These measurements are directional, not release performance
guarantees.

Issue #144 must add deterministic fixtures for subclass, equivalence, and
transitive derivations; denied intermediates; snapshot revisions; every bound;
and unchanged asserted-only behavior. Performance should be revisited when a
representative workload shows query-time evaluation is a bottleneck.
