# Type-bound derived-fact admission

[Issue #659](https://github.com/Sannrox/sekai-chisei/issues/659) asked how a
governed function may write derived objects onto a type revision without
becoming a transform catalog or a second object identity.

## Decision

Keep governed functions read-only. Derived views stay query-time only. Close
#659 with no persisted derived facts and no feature Issue.

Do not admit a derived-write path on Action instances or functions. Do not
mint a separate derived-fact kind or digest.

[ADR 0021](../decisions/0021-defer-second-object-sync-source.md) named no
second inbound source. That is the delivered dependency: there is no new
system of record to bind derived writes to. The two-day time box does not
open a write path.

## Evidence

### Functions resolve; they do not persist

`function::execute` and `execute_for_object_with_filter` walk a pipeline over
already-visible objects and return aggregates. They have no `create_object` or
`put_object` seam.

Schema computed properties call that path at read time
(`resolve_schema_computed_with_filter`). The resolver first removes stored
values for computed keys, then overlays the function result on the in-memory
object. `computed_property_resolves_from_function_without_persisting` asserts
`GetObject` and `ListObjects` see the overlay while `db.get_object` does not
contain the computed key. Namespace filters apply before the function walks
linked objects.

That is the ADR 0001 shape applied to functions: derived material is a
projection, not a durable fact.

### Action mutations are asserted writes, not derived admission

When a `GovernedActionType` binds `object_kind` and `object_mutation`,
admission plans exactly one `create` or `update` of that admitted kind. The
caller supplies `object_id` and properties. The plane validates the kind,
rejects reserved kinds, and writes through the ordinary object persistence
seam.

Receipt intent attributes then record `object_id`, `object_kind`, and
`object_mutation`. They do not record `origin_class`, `source_id`, or a
derived digest. Policy or budget deny persists a `denied` instance and does
not write the record.

Those writes are asserted graph facts under an already-admitted kind. Treating
them as derived-fact admission would relabel the existing mutation path as a
transform product. [ADR 0020](../decisions/0020-shared-type-revisions-and-object-sync.md)
rejects that catalog.

`external_mutate` remains permit-backed write-back to an existing object
identity. It does not mint derived objects.

### Sync identity cannot host derived writes

Inbound sync maps one GitHub Issue or PullRequest onto
`object_id = hash(type_digest, source_id)` with
`source_id = github:{owner}/{repo}#{number}`. Refresh, tombstone, and
type-revision conflict are defined for that identity. Lineage bind fails
closed without `type_digest`, `source_id`, and `object_id`.

A function result has no external source id. Applying sync conflict rules to
it would require inventing one. That is a second identity, not reuse of the
GitHub contract. [ADR 0021](../decisions/0021-defer-second-object-sync-source.md)
already forbids a second family and extra GitHub kinds under the current
format.

Derived material must not become the system of record for inbound sync. A
computed overlay that later synced as if it were GitHub truth would collide
with the live Issue/PR object or mint a parallel id on the same type
revision.

### Receipts already distinguish origins without a derived-fact row

| Origin | Where it lives | Durable row |
| --- | --- | --- |
| Asserted object | Graph object plus Action receipt `object_mutation` | Yes, one object id |
| Synced object | Sync decision + lineage `source → dataset → object` | Yes, same object id as `hash(type_digest, source_id)` |
| Derived entailment | Query-time explanation; `origin_class=derived` on the epistemic projection | No |
| Computed property | Read-time function overlay | No |
| Hypothesis | Vocabulary / test helper only ([#660](660-hypothetical-overlay.md)) | No |

[#502](502-epistemic-assertion-resource.md) already rejected a durable
`EpistemicAssertion` resource. A derived-fact object would recreate that
store under a type revision.

## Alternatives rejected

- **Option 2: persist derived objects of the same `type_digest` with
  lineage.** Action create/update already writes asserted objects of an
  admitted kind. Extending that path to function output would add a
  transform catalog: source objects in, derived objects out, on the same
  revision. Lineage today requires a source id; functions have none.
  Authorization-filtered compute would become a write that later reads and
  sync could treat as truth. That violates ADR 0001, ADR 0020, and the
  "must not become inbound-sync SoR" constraint.
- **Option 3: a separate derived-fact kind or digest.** A second digest is a
  second ontology. [#502](502-epistemic-assertion-resource.md) and
  [#660](660-hypothetical-overlay.md) already rejected parallel durable
  worlds. Nothing in the current mutation or sync paths needs a second
  identity to stay coherent.
- **Wait for a named second source.** #657 closed without naming one. The
  exit condition said to stay blocked only while that dependency was open.
  The dependency is delivered; the recommendation is still option 1.

## Complexity and impact

A derived-write path is not a documentation-only addition. It would need an
object identity rule that does not collide with GitHub sync, receipt fields
for origin, invalidation when source objects change, authorization on both
read and write, and a decision about whether sync refresh may overwrite the
derived row. Those costs are not supported by a live tenant workflow.

Existing Action mutations and permit-backed write-back stay as they are.
Functions and computed properties stay read-time overlays.

## Reopening criteria

Reopen only when all of the following are true:

1. A named tenant workflow cannot be answered by asserted Action mutations,
   GitHub Issue/PR sync, query-time ADR 0001 traces, and read-time computed
   properties.
2. The proposed write still uses one object identity per object, does not
   invent a source id that collides with `github:{owner}/{repo}#{number}`,
   and cannot become inbound-sync truth.
3. A superseding ADR replaces the no-persisted-derived-facts rule in
   [ADR 0001](../decisions/0001-query-time-ontology-entailment.md) and the
   no-transform rule in
   [ADR 0020](../decisions/0020-shared-type-revisions-and-object-sync.md).

Option 3 stays rejected unless that later design proves it is not a second
ontology. A reopened proposal must not treat function pipelines as a
connector or transform catalog.

## Validation

The decision is supported by the existing deterministic suites and the
documents cited above:

```bash
cargo test --locked --lib sekai::function
cargo test --locked --lib sekai::compute
cargo test --locked --lib sekai::action_object_mutation
cargo test --locked --lib sekai::object_sync
cargo test --locked --lib computed_property_resolves_from_function_without_persisting
```

This page records the research outcome. It does not change runtime behavior.
The maintained ontology guide, action-instance pages, and ADRs 0001, 0020,
and 0021 remain the usage contract.
