# ADR 0174: The object log serves object-set reads, and the relational projection is removed after a fallback window

- Status: accepted
- Date: 2026-11-26
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2413 (#2413)
- Supersedes: [ADR 0091](0091-object-log-owns-evaluate-identity.md) decision 4
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0081](0081-evaluate-reads-mikura-library.md),
  [ADR 0088](0088-one-object-log-host-many-clerk-clients.md),
  [ADR 0112](0112-namespaced-object-log-identity.md)

## Context

ADR 0091 made the object log the owner of object identity and kept the
relational `object_type_index*` projection as the serving index for
`EvaluateObjectSet` (decision 4). #2290 makes the log a selectable engine
and leaves the default alone. Its findings name two gaps between the
engines:

- **Aggregate semantics.** The relational engine folds `f64` values over
  join paths, so a multi-hop count or sum counts a far object once per path
  that reaches it. The log counts distinct objects and sums exact integers.
- **Authorization.** The relational engine applies every per-object rule
  (grants, purpose policy, collaboration, markings) while it reads. The log
  restriction evaluates a narrower set of rules, and nothing proves that a
  page read from the log hides what the relational engine hides.

Comparable governed data platforms serve object-set reads from an object
index. They limit object, property and view security rules to the operators
that index can enforce, and they state whether each answer is exact instead
of forcing their engines to aggregate the same way.

## Decision

1. **Object semantics for every engine.** A hop yields a set of objects.
   Aggregates count and sum distinct objects, never join paths. The
   relational engine changes to match the log. Multi-hop counts and sums
   change for existing clients, so the pull request that changes them is
   breaking: a `!` subject, the `risk:breaking` label and a `### Breaking`
   note.
2. **The log answers only what it can authorize.** For an object kind the
   log serves, only per-object security rules the log restriction can
   evaluate are allowed. A kind with any other rule (a grant, a purpose
   policy, a collaboration, or a marking the restriction cannot carry)
   stays on the relational engine until the restriction can carry that
   rule. The evaluator checks this per request across the root kind and
   every hop kind. Without that check passing, it does not read from the
   log and falls back to the relational engine. After decision 4 removes
   the relational engine, the request fails closed.
3. **An explicit accuracy contract.** `EvaluateObjectSet` takes an accuracy
   mode: `approximate` allows an answer the engine cannot prove exact, and
   `accurate` requires an exact answer and fails with a typed error when
   the engine cannot give one. Every response states whether it is exact.
   Typed clients request `accurate`. An unset mode keeps the current
   behavior, which is `accurate`, so old clients get no approximate answers
   they did not ask for.
4. **Default, fallback window, removal.** When every gate below holds in a
   tagged release, the log becomes the default engine for object-set reads
   in the next minor release. The relational engine stays selectable through
   `SEKAI_OBJECT_INDEX_ENGINE` for two further minor releases and is removed
   in the third. After removal, a descriptor the log cannot answer fails
   closed with the refused shape named.

### Gates before the default changes

1. Every descriptor in the evaluate conformance suite returns the same page
   from every engine, under the object semantics of decision 1 (#2290).
2. The dual-read canary compares at least 1% of evaluates, incoming hops
   included (#2412), and reports no mismatch over a 14-day soak (#2291).
3. The seeded differential test passes its fixed seeds (#2293).
4. The object store passes its serving bar at 10^6 and 10^7 objects in a
   tagged release of the object store.
5. The object-path benchmark has rows for the log engine at the sizes it
   already measures and at 10^6 objects, and the log's p95 is at most twice
   the relational projection's p95 at each size.
6. Every descriptor shape the relational engine answers and the log refuses
   is listed in `docs/object-type-index.md`. For each one, either the public
   contract says it is refused, or a consumer fixture names the query so the
   object store can admit it under its own rule.
7. Where more than one object-log host runs, the client retries safely
   against a writer and a standby (#2292).

## Alternatives considered

- **Keep ADR 0091 decision 4.** Rejected: identity and serving stay split
  across two stores indefinitely, and every new object-set feature is built
  twice.
- **Make the log the default and keep the relational engine permanently.**
  Rejected: two engines with one contract must stay equal forever, which the
  differential test and canary would have to prove on every change.
- **Make the engines aggregate identically by copying the relational join
  path semantics into the log.** Rejected: counting a far object once per
  path is the surprising answer, and the log would have to carry join paths
  it does not store.

## Consequences

- During the fallback window two engines answer. After it, the log is the
  only engine and a descriptor it cannot answer fails closed.
- Kinds with rules the log restriction cannot evaluate stay on the
  relational engine during the window. Before removal they need a
  restriction that carries their rule, or they stop being served by
  `EvaluateObjectSet`. The gate 6 list names them.
- Search keeps its own index. This record does not move it.
- Rollback below the release that removes the relational engine rebuilds
  the projection from registered sources, receipts and the log with
  `ReindexObjectType`. ADR 0091 decision 2 already makes it rebuildable.
- A single-file install gains no new store. The log is already required at
  startup.
- #2290 (selectable log engine), #3510 (member pages) and #3511 (cost limits
  and freshness) build on this record.

## Validation

- The conformance suite, canary, differential test and benchmark rows above
  are the evidence for the default change.
- The pull request that switches the default links the gate evidence.
- The pull request that removes the relational engine states the release
  that made the log the default and the two releases that followed.
