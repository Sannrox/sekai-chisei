# ADR 0165: A measure is a definition member evaluated as ordinary object sets

- Status: proposed
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2299 (#2299)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md), [ADR 0086](0086-object-set-is-its-descriptor.md), [ADR 0134](0134-federated-aggregate-queries.md)

## Context

Aggregations are written ad hoc in each `EvaluateObjectSet` call. Two
consumers asking for the same business number can send two different
descriptors, and no review, lint or diff sees either. A drafted definition
(#2296) declares typed properties that are obvious measure inputs, but the
tree has no member kind that can hold a measure.

The research in
[`docs/research/2299-reviewed-measures.md`](../research/2299-reviewed-measures.md)
ran a draft and measured it against today's aggregation. A grouped count or
sum is already one descriptor. An ungrouped total is refused, because
`group_by` is required. A ratio such as an on-time share takes two
descriptors and a client-side division. Authorization, the revision fence and
both dual-read gates already cover every descriptor part a measure needs.

## Decision

1. **A new member kind, `measure`.** It is versioned, proposed, linted,
   diffed and exported with the rest of the tree, at `measure/<id>.json`.
2. **Bounded grammar, not a query language.** A measure names:
   - one `object_type` from the same revision;
   - a `numerator`: one aggregation (`count`, `sum`, `avg`, `min`, `max`)
     over one declared property (none for `count`), plus at most four
     property filters with the descriptor's operators;
   - an optional `denominator` of the same shape on the same object type;
   - an optional `group_by`, shared by both sides;
   - a `description` and a `unit`.

   There are no hops, no expressions, no property-to-property comparisons and
   no nesting. A condition that needs one is a property the source lands.
3. **Lint and diff.** Lint refuses a measure whose type, property, filter key
   or `group_by` is not declared, and a `sum` or `avg` over a non-numeric
   property. Removing or retyping a property a measure uses is a lint error on
   the measure. The diff classifies an added measure as compatible, and a
   changed or removed measure as breaking for its consumers, since the number
   changes meaning.
4. **The plane evaluates it, as the caller.** A governed evaluate call takes
   the namespace, the measure id and the definition digest it is pinned to. It
   compiles each side into an ordinary `sekai.object-set` descriptor and
   evaluates that through the existing authorized aggregate path. It returns
   one value per group key, with a ratio only where the denominator is
   nonzero. An ungranted property or hidden row affects a measure exactly as
   it affects the descriptors: the call fails closed or the rows are absent.
   It writes the same query receipt.
5. **No engine of its own.** Both sides use the same plan, the same revision
   fence, and the object-index and object-log dual-read gates. When the
   object log becomes a serving engine (#2290), measures follow without
   change.
6. **Ungrouped totals come first.** `group_by` becomes optional in object-set
   aggregation, as a descriptor change of its own, before the member kind
   ships.
7. **Not a federated measure.** ADR 0134's *measures* are properties a tenant
   allows others to aggregate. A definition measure is a named aggregation in
   one namespace, evaluated under the caller's rights. An allowance may
   reference a measure later, but only when a consumer asks for it.

## Alternatives considered

- **Measures in consumer bindings.** Rejected. That is today's state and the
  problem: one business number, many unreviewed requests.
- **Measures as governed functions.** Rejected. Functions are per-object
  read-time overlays behind a host and an evaluation gate. A measure is a
  declarative aggregate over a set with no code to run.
- **A general expression language.** Rejected. It turns a reviewed member into
  a query language, and every expression would need its own authorization
  and engine parity proof.
- **No measures.** Rejected. A drafted tree would have no place for the
  numbers people ask for most.

## Consequences

- Consumers and agents name a measure instead of rebuilding its descriptor,
  and a definition review sees every business number.
- The same measure can return different values to callers who see different
  rows. It is one definition, not one value for everyone. A shared value
  across differing rights stays the job of federated aggregates.
- New work: optional `group_by`, the member kind with lint and diff, the
  evaluate call with its receipt, and proposing measures from a draft. Each
  ships as its own Issue on acceptance.
- Package and branch readers that predate the kind refuse a revision that
  contains a measure, as they refuse any unknown kind. A namespace adopts
  measures only once every plane in a rolling deploy knows the kind.

## Validation

- A drafted tree with typed numeric and boolean properties carries reviewed
  measures through propose, lint, diff and export.
- A measure over an ungranted property fails closed for that caller, and a
  caller who sees fewer rows gets a value computed from only those rows.
- Under both dual-read gates, a ratio measure evaluates identically on the
  index plan and its comparison plan.
- Revisit if consumers need hops or derived conditions in measures often
  enough that landing the property is not practical.
