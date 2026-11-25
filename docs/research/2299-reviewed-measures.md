# Research: reviewed measures as definition members

Issue: [#2299](https://github.com/Sannrox/sekai-chisei/issues/2299)
Date: 2026-11-25
Status: **recommendation complete**; see [ADR 0165](../decisions/0165-a-measure-is-a-definition-member.md) (proposed)

## Decision question

Should a definition carry reviewed measures: a named, described aggregation
over an object set (for example "on-time share", a filtered count over a
count), so that every consumer and agent computes the same business number
the same way?

## Options

- **A. A measure is a definition member.** It is versioned, proposed, linted,
  diffed and exported with the tree, and the plane evaluates it.
- **B. Measures stay in consumer bindings.** Each client keeps its own saved
  descriptor, as [ADR 0086](../decisions/0086-object-set-is-its-descriptor.md)
  already allows.
- **C. A measure is a governed function.** It reuses the `function` member
  kind and its host.
- **D. No measures.** Aggregations stay ad hoc per `EvaluateObjectSet` call.

## Evidence

### A real draft has measures and nowhere to put them

The draft from #2296 (`sekaictl ontology draft`) was run on the
`fake.crm` discovery fixture with five columns added to `Order`:
`amount: decimal`, `status: string`, `promised_at` and `delivered_at:
timestamp`, and `is_late: boolean`. The drafted `object_type/Order.json`
declares all eight properties with their types. Three of them are obvious
measure inputs: a sum of `amount`, a count by `status`, and the share of
orders that were not late. The tree has no member kind that can hold any of
them. `KNOWN_MEMBER_KINDS` in `definition_branch.rs` lists `action_type`,
`agent`, `control`, `function`, `interface_type`, `link_type`,
`object_type`, `ontology_class`, `ontology_relation`, `policy` and
`transform`. A package or branch reader refuses any other kind.

### What evaluation already expresses

`sekai.object-set/v2` (`ObjectSetAggregation`) carries one function (`count`,
`sum`, `min`, `max`, `avg`, `distinct`), one property and one `group_by`, plus
the descriptor's at most four property filters (`eq`, `gt`, `gte`, `lt`,
`lte`). Measured against the draft:

| Measure | Today |
| --- | --- |
| Revenue by status: `sum(amount)` grouped by `status` | One descriptor. |
| Late orders by account: `count` where `is_late = true`, grouped by `account_id` | One descriptor. |
| Revenue in total | Not expressible. `prepare_aggregation` refuses an empty `group_by`. |
| On-time share: `count(is_late = false) / count` | Not expressible. Two descriptors and a client-side division, which is exactly how two consumers drift apart. |
| On time computed as `delivered_at <= promised_at` | Not expressible. Filters compare a property with a constant, never with another property. |

So a measure needs two things evaluation lacks: an ungrouped total and a ratio
of two aggregations over the same set. It does not need property-to-property
comparison. A source that wants an on-time measure lands the boolean, as
`is_late` here does. That keeps the grammar out of query-language territory.

### Authorization already covers the parts

The aggregate path in `object_set_query.rs` authorizes every part of a
descriptor before reading rows. Filter keys and `group_by` go through
`ensure_property_query_allowed`, and an ungranted one fails closed before any
row is matched. A `sum`, `min` or `max` over an ungranted property fails
closed on the leaf kind (`docs/object-type-index.md`). Hidden rows stay out of
members, groups and counts.

A measure that compiles to at most two ordinary descriptors, both evaluated
as the caller, therefore inherits this unchanged. It leaks no property a
caller cannot read, because the call fails rather than returning a number.
One consequence must be stated plainly: the same measure returns different
numbers to callers who can see different rows. "Computed the same way" means
the same definition, not the same value for everyone. A shared number for
callers with different rights is what federated aggregates
([ADR 0134](../decisions/0134-federated-aggregate-queries.md)) solve with
allowances and group suppression. It is out of scope here.

### The engines and the dual-read gate

Aggregates are served from the object type index (`sql_projection`).
`SEKAI_OBJECT_INDEX_DUAL_READ` and the object-log dual read already compare
aggregate evaluations and fail closed on a mismatch, and both require
`max_rows_scanned`. The object log is not yet a selectable serving engine for
`EvaluateObjectSet` (#2290, waiting on an object-log release). A measure that
evaluates as ordinary descriptors needs no engine work of its own. Each side
of a ratio goes through the same plan, the same dual read and the same
revision fence. When #2290 lands, measures follow it with no change.

### Why not the alternatives

- **B. Consumer bindings.** This is today's state, and the Issue's problem.
  Two consumers write two requests for one business number, and no review,
  lint or diff ever sees either one.
- **C. Functions.** Research
  [#659](659-derived-fact-admission.md) keeps governed functions as read-time
  overlays per object, behind an experimental host and an evaluation gate.
  A measure is an aggregate over a set, has no code to host and needs no
  model gate. Folding it into functions would put a declarative count behind
  the heaviest member kind there is.
- **D. No measures.** This leaves the drafted tree without a home for its
  most reviewable output, the numbers people actually ask for.

## Recommendation

Option A, kept small. A `measure` member names one object type and an
aggregation over it, with an optional denominator over the same type. The
plane evaluates it as at most two ordinary object-set evaluations as the
caller and returns one value per group. The member grammar, lint, diff
classes, export layout and the evaluate call are in
[ADR 0165](../decisions/0165-a-measure-is-a-definition-member.md).

The vocabulary needs care. A federated allowance already uses *measures* for
the properties a tenant lets others aggregate (ADR 0134). A definition
measure is a named aggregation, not a property. The ADR keeps the two apart
and lets a later allowance reference a measure only if a consumer asks.

## Follow-up work, once the ADR is accepted

1. Make `group_by` optional in `sekai.object-set` aggregation (an ungrouped
   total). This is a descriptor change on its own and is useful without
   measures.
2. The `measure` member kind: validation, lint, diff classes and export
   layout.
3. The governed evaluate call for a measure, with a receipt.
4. Proposing measures from a draft. This stays out until 1–3 ship, per the
   Issue's non-goals.
