# ADR 0166: Example questions bind against the definition tree, with no data

- Status: proposed
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2300 (#2300)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md), [ADR 0086](0086-object-set-is-its-descriptor.md), [ADR 0165](0165-a-measure-is-a-definition-member.md)

## Context

A definition drafted from a source discovery (#2296) exists only as files
until it is imported. Lint checks structure, and branch lint's data rules read
live objects, which a new source does not have. A reviewer has no way to show
that the draft can answer the questions it was drafted for.

The research in
[`docs/research/2300-draft-example-questions.md`](../research/2300-draft-example-questions.md)
bound eleven object-set descriptors against a drafted tree with
`ObjectSetDescriptor::prepare`, which reads only definitions. It refused the
right three and accepted five it should have refused, through two gaps: the
aggregation `property` and `group_by` are never bound to declared properties,
and the source types a draft writes in `property_types` are ignored, so every
drafted property binds as a string. Discovery samples are at most 8 rows per
kind, are never persisted, and need source credentials to read again.

## Decision

1. **A question file next to the tree.** `questions.json`, contract
   `sekai.ontology-questions/v1`:

   ```json
   {
     "contract_version": "sekai.ontology-questions/v1",
     "questions": [
       {"name": "late_orders_by_account",
        "ask": "Which accounts have late orders?",
        "object_set": {
          "kind": "Order",
          "property_filters": [{"key": "is_late", "op": "eq", "value": "true"}],
          "aggregation": {"function": "count", "group_by": "account_id"}}}
     ]
   }
   ```

   `object_set` holds the descriptor's `kind`, `property_filters`, `hops` and
   `aggregation`, with their `sekai.object-set/v2` meaning. Names are unique.
   There is no expected result. Questions are not definition members and never
   reach the plane. Import skips the file, and `draft --update` never writes
   it.
2. **Passing means binding.** A question passes when its descriptor binds
   against the tree's members:
   - everything `ObjectSetDescriptor::prepare` checks today;
   - the aggregation `property` is declared on the leaf kind and `group_by`
     on the root kind;
   - `sum` and `avg` take a numeric property.

   No objects, grants or samples are read. The rules only add refusals to
   `prepare`, so a question that passes also binds on the merged revision.
   Binding is not authorization: evaluate still fails closed on a property the
   caller may not query.
3. **Drafted types through one mapping.** For a list-form `properties`, the
   type of a property comes from `property_types` through a fixed mapping:
   `integer`, `int`, `bigint`, `smallint`, `decimal`, `numeric`, `number`,
   `float`, `double` and `real` are numeric; `boolean` and `bool` are boolean;
   `timestamp`, `timestamptz` and `datetime` are timestamps; `string`,
   `text`, `varchar`, `char` and `uuid` are strings. Any other source type
   binds by name only, and the check names it as unchecked. Measure lint
   (ADR 0165) uses the same mapping.
4. **No data check.** A bounded sample cannot confirm a count, a sum or an
   empty result, and reading one again needs source credentials and holds
   unmarked values outside the plane. Link soundness is already in the draft
   report's reference evidence. After the first ingest, a question is checked
   with data by evaluating it with `EvaluateObjectSet` on the published
   revision.
5. **Client-side.** `sekaictl ontology check --dir <tree>` binds every
   question with the `sekai-core` binder. It needs no plane, namespace or
   credentials.
6. **A failure blocks the tree's review, not the plane's merge.** The command
   prints one line per question and exits nonzero if any question does not
   bind. The tree's own review runs it. The plane's merge gate does not, since
   it never sees questions.

## Alternatives considered

- **Questions as a definition member kind.** Rejected. A question is review
  evidence, not meaning, and no consumer evaluates it. A number consumers
  share is a measure (ADR 0165).
- **Evaluate against the discovery sample.** Rejected. Eight rows per kind,
  sampled independently across kinds, cannot confirm results, and the check
  would need source credentials and unmarked values.
- **A branch RPC.** Rejected. It needs an import and an open proposal first,
  and the server adds nothing, because binding reads only definitions.
- **Expected results in the file.** Rejected for now. Without data there is
  nothing to compare them with, and a live value depends on who asks.
- **Make the plane's merge gate run the questions.** Rejected. Questions would
  have to be stored in the plane, which makes them members in all but name.

## Consequences

- A reviewer sees, before import, which questions the draft can answer and
  why the others fail, including ones that wait on a descriptor change (an
  ungrouped total waits on ADR 0165's optional `group_by`).
- The binder gains rules and a type mapping in `sekai-core`. The check calls
  them as a definition-only bind. Whether live evaluation also adopts them is
  a separate compatibility decision, because it would refuse descriptors the
  plane accepts today.
- An older `sekaictl` refuses to import a tree that holds `questions.json` (it
  is not a definition kind directory). That failure is visible and nothing is
  written. Remove the file or upgrade.
- New work, as one feature Issue on acceptance: the binder rules and mapping,
  the `check` command, import skipping the file, and docs.

## Validation

- The eleven questions from the research bind or are refused as its table
  says, as unit cases on the binder.
- `sekaictl ontology check` on the draft fixture with a `questions.json`
  exits 0 when every question binds, and nonzero with the question's name and
  reason when one does not.
- A question that passes the check binds when evaluated on the imported and
  merged revision.
- `sekaictl ontology import` of a tree with `questions.json` sends no
  question.
- Revisit if reviewers keep needing a data result before the first ingest.
