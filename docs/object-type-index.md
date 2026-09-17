# Object-type membership index

A registered dataset plus key mapping is the **source of members** for a type
revision. The index is a rebuildable **projection**. It is not object
authority: delete it and rematerialize from dataset rows and Action deltas.

See [ADR 0073](decisions/0073-source-and-action-objects.md), the published
[10⁷ envelope](research/876-object-index-envelope.md), and the
[hop-projection envelope](research/889-hop-projection-envelope.md).

## Operator path

Experimental RPCs (`SEKAI_EXPERIMENTAL_RPCS=1`):

1. `RegisterObjectTypeDatasource` — namespace, kind, type-revision digest,
   dataset id, key column, property mapping, optional hidden column.
2. `ReindexObjectType` — incremental by default; `full_rebuild` rematerializes
   from source then reapplies Action deltas.
3. `GetObjectTypeIndexStatus` — `stale`, `lag_ms`, `quarantine_reason`,
   visible `member_count`.
4. `PutObjectTypeIndexEdit` — Action delta that survives a full rebuild.

`EvaluateObjectSet` reads the index when a datasource is registered. Set
`required_freshness_ms` to fail closed when the index is stale or lagging.
Hidden rows never appear in members, counts, order, errors, or continuation
tokens. The SQL index remains the current evaluate backend.
`SEKAI_OBJECT_LOG_DUAL_READ=1` with `SEKAI_OBJECT_LOG` is a canary: it
compares hop/count/sum answers to a tagged in-process object-log library on
a sample of requests (`SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE`, default 32; `1`
for CI) and fails closed on mismatch, missing log, a missing
`max_rows_scanned`, or a descriptor that library cannot express (property
filters, `group_by` buckets, path multiplicity, or a non-i64 sum). Unsampled
requests keep the SQL answer and do not open the log. First soak
uses that library's allow-all property deny-list; clerk
grants stay compiled on the SQL path, so a grant-narrowed SQL answer fails
closed instead of being rewritten to match. This is not
`SEKAI_OBJECT_INDEX_DUAL_READ`. See
[ADR 0081](decisions/0081-evaluate-reads-mikura-library.md). It does not
retire these writes.

Schema drift (missing key or mapped column) quarantines the batch and leaves
the last consistent index readable with `stale=true`.

Governed transforms (`sekai.governed-transform/v1`) write datasets, not
type-revision object ids. Incremental runs process only new input rows.
A failing quality rule quarantines the batch and leaves the previous
output queryable.

`sekai.object-set/v2` can group count/sum/min/max/avg/distinct across bounded
index hops (`join_property`). Cost limits (`max_rows_scanned`, `max_depth`,
`max_time_ms`) fail closed with the limit named. `SEKAI_OBJECT_INDEX_ENGINE`
selects `hop-projection` (default) or `nested-loop`. Hop-projection is a
rebuildable join-key projection, not object authority. Evaluate walks those
join edges as the reachability plan and looks up children by the stored
raw join value, not a per-hop digest of every parent key. It fails closed
while that generation is unready. Evaluate reads one ready+generation+digest
fence for the root and hop kinds; a matching generation skips recounting
join and member rows. `nested-loop` is the original in-process
scan, kept as an explicit debug engine. Switching engines requires
`ReindexObjectType`. A definition-branch publish clears hop-projection
ready until `ReindexObjectType` restamps the datasource to the published
revision; evaluate fails closed while that generation is stale.
`RegisterObjectTypeDatasource` that changes dataset, key, mapping, hidden,
edits-only, or digest also clears ready for that kind, even when the catalog
digest is unchanged; identical re-register leaves the generation in place.
`SEKAI_OBJECT_INDEX_DUAL_READ=1` compares both
plans and fails closed on mismatch. Hidden rows stay out of members,
aggregates, and hop edges. Aggregate evaluates project only the group_by,
numeric, filter, and nested-loop join properties needed for the plan.
Indexed property filters (`eq`/`gt`/`gte`/`lt`/`lte`) are applied in SQL
against the stored member JSON so evaluate does not deserialize every
kind row before matching.
