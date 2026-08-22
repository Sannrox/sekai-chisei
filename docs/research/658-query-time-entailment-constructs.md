# Next query-time entailment constructs

[Issue #658](https://github.com/Sannrox/sekai-chisei/issues/658) asked which
additional constructs, if any, may join the bounded query-time entailment
profile without persisting derived facts or weakening authorization.

## Decision

Keep the current [ADR 0001](../decisions/0001-query-time-ontology-entailment.md)
profile. Do not add inverse expansion, query-time disjointness checks, or any
other derivation rule. Close #658 with no implementation follow-up.

Inverse and disjointness remain authoring, validation, and inspection metadata.
They are stored, write-validated, authorization-filtered on the ontology
snapshot, and shown in static inspection. They are not evaluation rules for
`RetrieveContext`, `ExpandRelations`, or `ExplainDerivation`.

PostgreSQL advertising the same current profile is a prerequisite for any later
growth. It is not itself a reason to pick a new construct now.

## Evidence

### Current profile coverage

`REASONING_PROFILE_VERSION` is `1`. Derivation `rule` values in
`proto/sekai.proto` are `root`, `graph_link`, `mapping`, `subclass`,
`equivalence`, and `transitive`.

| Construct | Durable metadata | Query-time evaluation |
| --- | --- | --- |
| Class subclass closure | `superclasses` | Yes, via `OntologyRegistry::kind_entailment_path` |
| Class equivalence closure | `equivalent_classes` | Yes, same path, including reverse-equivalence edges |
| Marked relation transitivity | `transitive` | Yes, only when every hop shares one marked relation |
| Class disjointness | `disjoint_classes` | No. Write-time contradiction checks only |
| Relation inverse | `inverse` | No. Pairing and endpoint reversal validated at write time |

Entailment-aware retrieval tests in `src/sekai/retrieval.rs` cover subclass
results without changing the asserted-only default, transitive explanations
with bounds, missing ontology references, and mixed-path rejection. Ontology
definition tests in `src/sekai/ontology.rs` cover disjoint-with-ancestor,
equivalent-and-disjoint contradictions, unknown inverses, and inverse endpoint
reversal. Inspection (`sekaictl ontology inspect`, ADR 0003) renders disjoint
and inverse fields and an entailment trace; it does not evaluate those fields.

Hidden class and relation names are stripped from the authorization-filtered
snapshot before inference, including `disjoint_classes` and `inverse`. Hidden
material therefore cannot affect results, counts, explanations, errors, or
truncation.

### PostgreSQL versus SQLite

Asserted graph retrieval is dual-backend. Query-time entailment is not.

- Capability advertisement sets `backend_sqlite_entailment=1` and
  `backend_postgres_entailment=0`.
- `RetrieveContext` and lookup-first expansion fail closed on PostgreSQL with
  `FAILED_PRECONDITION` rather than returning a partial ontology snapshot.
- Community PostgreSQL can persist ontology rows, including inverse and
  disjoint JSON, but it has no authorization-filtered entailment snapshot path.

Growing the SQLite-only profile would widen that advertised gap.

### What #143 and #144 left out

[#143](https://github.com/Sannrox/sekai-chisei/issues/143) selected query-time
subclass, equivalence, and marked transitivity. It rejected forward
materialization, a dual forward-and-backward path, a user-authored rule
language, and an external reasoner as the core.

[#144](https://github.com/Sannrox/sekai-chisei/issues/144) implemented that
profile as opt-in retrieval. Its non-goals were a textual query language,
probabilistic ranking, temporal queries, and arbitrary rules. Inverse and
disjointness were already stored as ontology fields and were not added as
derivation rules.

[#501](501-epistemic-rdf-owl-prov-o.md) records `owl:disjointWith` and
`owl:inverseOf` as `unsupported_owl_entailment` loss. [ADR 0018](../decisions/0018-ontology-relation-cardinality.md)
and [ontology.md](../ontology.md) already say inverse metadata must not
synthesize links or facts.

### Operator demand

No open Issue, Discussion, or checked-in operator fixture asks a question that
asserted-only retrieval plus the current profile cannot answer. VISION names
richer reasoning, temporal semantics, and simulation as long-term only. Near-
term and mid-term milestones do not. [#660](https://github.com/Sannrox/sekai-chisei/issues/660)
is a separate overlay question and remains blocked on this close; it must not
be answered by growing the entailment profile.

## Alternatives rejected

- **Add inverse as a query-time construct.** It would synthesize derived
  opposite-direction links, add a new `rule` value, and change expansion
  results without an unmet operator question. That contradicts the current
  non-synthesis rule and the OWL import loss record.
- **Add disjointness as a fail-closed query check.** Authoring already rejects
  equivalent-and-disjoint and ancestor-disjoint contradictions. A query-time
  instance check would be a new consistency product, not an expansion
  construct, and would need a disclosure rule for hidden disjoint classes.
- **Defer the decision until PostgreSQL parity.** Backend parity is required
  before any later growth. It does not identify a construct that should join
  the profile now, so it is a reopening gate rather than the recommendation.
- **Persist derived facts to unlock richer constructs.** That would replace
  ADR 0001. The issue says to close with no action if growth needs a persisted
  inference store. No candidate construct here requires one; the store is
  still rejected.

## Complexity and impact

A new derivation rule is not a documentation-only addition. It would change
the public reasoning profile version, explanation `rule` vocabulary, capability
advertisement, lookup-first fixtures, inspection traces, and the SQLite-only
entailment surface. Inverse expansion would also need a rule for a hidden
inverse relation so that filtered metadata cannot invent visible links.

Those costs are not supported by current evidence.

## Reopening criteria

Reopen only when all of the following are true:

1. At least one named operator or integrator question cannot be answered by
   asserted-only retrieval plus the current subclass, equivalence, and marked
   transitivity profile.
2. Community PostgreSQL advertises the same current profile as SQLite
   (`backend_postgres_entailment=1`) with an authorization-filtered snapshot
   and the same fail-closed bounds.
3. The proposed construct still evaluates backward at query time, persists no
   derived facts, and cannot let hidden ontology or graph material affect
   results, counts, explanations, errors, or truncation.

A reopened proposal must name exactly one construct, update
`REASONING_PROFILE_VERSION`, and supersede ADR 0001. It must not introduce a
persisted inference store to make the construct cheaper.

## Validation

The decision is supported by the existing deterministic suites and the
documents cited above:

```bash
cargo test --locked --lib sekai::retrieval
cargo test --locked --lib sekai::ontology
cargo test --locked --test epistemic_interop_conformance
```

This page records the research outcome. It does not change runtime behavior.
The maintained ontology guide and ADR 0001 remain the usage contract.
