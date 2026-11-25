# Research: check a drafted definition against example questions

Issue: [#2300](https://github.com/Sannrox/sekai-chisei/issues/2300)
Date: 2026-11-25
Status: **recommendation complete**; see [ADR 0166](../decisions/0166-example-questions-bind-against-the-tree.md) (proposed)

## Decision question

A draft from #2296 (`sekaictl ontology draft`) describes a new source before
the plane holds any of its objects. Lint checks structure, and the data rules
of branch lint read live objects, which a first draft does not have. How can
the draft be tested against the questions people need answered before it is
merged?

## Evidence

### The binder already exists and needs no data

`ObjectSetDescriptor::prepare` in `crates/sekai-core/src/sekai/object_set.rs`
binds a descriptor to a list of definition members and a digest. It reads no
objects and no grants. It checks the root kind, each property filter (declared
name, operator, value against the declared type), the order, each hop (the
link exists and its `from`/`to` match the hop's direction) and the aggregation
function. `sekaictl` already depends on `sekai-core`, so a client can bind
against a tree on disk with the same code the plane runs.

### What it accepts that it should not, against a draft

A throwaway test bound eleven descriptors against a drafted `Order` with the
columns the #2299 note added (`amount: decimal`, `status: string`,
`is_late: boolean`) and its drafted link to `Account`:

| Question | `prepare` today | Right answer |
| --- | --- | --- |
| Revenue by status: `sum(amount)` by `status` | binds | binds |
| Late orders by account: `count` where `is_late = true`, by `account_id` | binds | binds |
| Accounts of late orders: one outgoing hop to `Account` | binds | binds |
| Hop walked the wrong way | refused | refused |
| Filter on undeclared `region` | refused | refused |
| Revenue in total (no `group_by`) | refused | refused, until ADR 0165 makes `group_by` optional |
| `sum(revenue)`, an undeclared property | **binds** | refused |
| `count` by `region`, an undeclared property | **binds** | refused |
| `sum(status)`, a string | **binds** | refused |
| `is_late = maybe` | **binds** | refused |
| `amount > lots` | **binds** | refused |

Two gaps explain all five wrong answers:

1. **Aggregation fields are not bound.** `prepare_aggregation` checks the
   function and that a property is present. It never checks that `property`
   is declared on the leaf kind or `group_by` on the root kind (the kinds the
   aggregate path in `object_set_query.rs` reads them from). The live call
   catches this later, through property grants on real rows. A draft has no
   rows.
2. **Drafted types are invisible.** A draft writes `properties` as a list and
   the source column types in a separate `property_types` map.
   `declared_property_type` reads a type only from the map form of
   `properties`. In the list form every property is a string, so a boolean or
   numeric filter value is never checked. The types in `property_types` are
   the source's own strings (`decimal`, `text`, ...), not the descriptor's
   type names, so reading them needs a fixed mapping. A type outside the
   mapping, such as `decimal` passed straight to `validate_property_value`,
   would be refused as unsupported.

ADR 0165 needs the same two things for measure lint ("a `sum` or `avg` over a
non-numeric property", every filter key and `group_by` declared). One binder
serves both.

### Where a draft lives

A draft is files. `draft` never writes to the plane, and `import` is the first
plane call. Review data already sits next to the tree: import skips
`draft-report.json` and `draft-decisions.json`, and `draft --update` never
overwrites a file it does not own. A question file fits that pattern. Questions
are not definition members: they say what a reviewer expects the tree to
answer, not what a type means, and no consumer evaluates them. A measure
(ADR 0165) is the member for a number consumers share.

### What a sample can and cannot say

`crates/sekai-source-sdk/src/discover.rs` caps a sample at
`MAX_DISCOVERY_SAMPLE_ROWS` (8) per record kind, compares values in memory, and
lets only counts leave. Samples are never part of the discovery document, so
they are not persisted. A data check would have to:

- read the source again, with the adapter's credentials, from the client that
  runs the check;
- hold values for columns the draft has not yet marked (a `possibly_sensitive`
  column only takes a marking in the draft) in a process the plane does not
  govern;
- answer from at most 8 rows per kind, joined across kinds sampled
  independently, so a hop can match nothing even when the link is sound.

Eight rows cannot confirm a count, a sum or an empty result. The one data fact
that matters for a draft is whether a link holds, and the draft report already
carries it as reference evidence (sampled, matched, null ratio). A data check
adds a credentialed source read and unmarked values for a result nobody can
trust.

After the first ingest, the questions can be evaluated live with
`EvaluateObjectSet` on the published revision, as the caller, with a receipt.
That is the data check worth having, and it needs no new surface.

### Where it can run

- **Client-side, against the tree.** Binding reads only definitions, which the
  tree holds. No plane, no credentials, no namespace. It runs in the
  repository CI that already reviews the tree.
- **A branch call.** The tree must be imported first, which opens a proposal.
  The call would be one more experimental RPC that sends the questions to a
  server that adds nothing to the result, since binding reads no data.

## Answers to the Issue

1. **Form.** One `questions.json` next to the tree, contract
   `sekai.ontology-questions/v1`, a list of named questions. Each has a `name`,
   an `ask` in words, and an `object_set`: the descriptor's `kind`,
   `property_filters`, `hops` and `aggregation`. Namespace, digest, limit and
   cost limit are left out; the check supplies them. There is no expected
   result: without data there is nothing to compare it with, and a live result
   depends on the caller's rights.
2. **Passing without data.** Every question binds: `prepare` as the plane runs
   it, plus the two missing rules (aggregation `property` declared on the leaf
   kind and `group_by` on the root kind; `sum` and `avg` over a numeric
   property), with drafted `property_types` read through a fixed mapping. This
   is enough for a first version. The check is never looser than the plane,
   so a question that passes binds on the merged revision. Binding is not
   authorization: a caller without a grant on a property still fails closed
   at evaluate.
3. **A data check.** Not worth it. The sample is 8 rows, never persisted, read
   with source credentials, and cannot confirm counts. Link soundness is
   already in the draft report. Evaluate the questions live after ingest.
4. **Where.** Client-side, in `sekaictl`, against the tree, using the
   `sekai-core` binder.
5. **Block or report.** The check exits nonzero when any question does not
   bind, and prints each one with its reason. That blocks the tree's own
   review wherever it runs, which is where the tree is merged. The plane's
   merge gate does not run it, because questions never reach the plane.
   Import does not run it either; it skips the file.

## Recommendation

Adopt the answers above as [ADR 0166](../decisions/0166-example-questions-bind-against-the-tree.md).
It records the file, the binding rules, the type mapping and the client-side
command.

## Follow-up feature, once the ADR is accepted

One feature Issue, not created by this research:

- **`sekaictl ontology check --dir <tree>`** reads `questions.json` and binds
  each question against the tree's members. Exit 0 when all bind, nonzero
  otherwise, one line per question.
- **Binder rules in `sekai-core`**: aggregation `property` and `group_by`
  declared, numeric `sum`/`avg`, and `property_types` read through one
  mapping. Expose them as a definition-only bind the check calls, so the
  plane's `prepare` keeps its current behavior until a separate change decides
  whether live evaluation adopts them.
- **Import skips `questions.json`**, like `draft-decisions.json`.
- **Docs**: the file and the command in `docs/ontology.md`, next to draft.
- **Tests**: the eleven questions above as unit cases on the binder, and one
  command test on the draft fixture.

Measure lint (ADR 0165) reuses the same binder rules and type mapping when it
ships. Once measures exist, a question may name a measure instead of an
`object_set`; that is a later, compatible addition to the file.
