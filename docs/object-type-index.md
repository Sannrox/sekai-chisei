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
   `ApplySourceBatch` registers this binding for each landed kind when the
   kind has no datasource, or expands an identity mapping on the binding
   dataset. An operator mapping on that dataset is left in place.
2. `ReindexObjectType` — incremental by default; `full_rebuild` rematerializes
   from source then reapplies Action deltas. Incremental apply that finds a
   stored dataset cursor and zero live source members treats that as an
   interrupted full rebuild and rematerializes from row 0. A full rebuild
   writes that cursor to 0 after deleting source members so a crash that
   already recreated some rows still resumes from the start. Incremental apply
   clears hop-projection ready before member upserts and keeps it false until
   the join rewrite commits, so evaluate cannot pair new member keys with old
   hop edges.
3. `GetObjectTypeIndexStatus` — `stale`, `lag_ms`, `quarantine_reason`,
   visible `member_count`.
4. `PutObjectTypeIndexEdit` — Action delta that survives a full rebuild.

Admitted object create/update still persists clerk objects and receipts
here. Combined and Sekai processes always open an object log (default
`<SEKAI_DATA_DIR>/objects.mikura`, or `SEKAI_OBJECT_LOG_HOST`). The same
admitted mutation is appended through tagged mikura ingest so the log owns
identity generations. A denied or unadmitted Action does not append. Action
apply does not write these SQL tables. See
[ADR 0091](decisions/0091-object-log-owns-evaluate-identity.md).

One process at a time may open a given `SEKAI_OBJECT_LOG` path: the
in-process log handle is a single writer, and a second process fails closed
on open. Several clerk processes share one object-log host
(`SEKAI_OBJECT_LOG_HOST`). See
[ADR 0088](decisions/0088-one-object-log-host-many-clerk-clients.md).

`EvaluateObjectSet` reads the index when a datasource is registered and the
descriptor has no one-hop traversal. One-hop still walks declared links
from authorized near objects. Clerk objects of that kind whose ids are not
index members stay in the indexed page so a first auto-registered binding
does not hide Action-written objects or objects from additional source
bindings. Set
`required_freshness_ms` to fail closed when the serving projection is stale
or lagging. Hidden rows never appear in members, counts, order, errors, or
continuation tokens. Existing `object_type_index*` tables are retained as a
rebuildable projection: `ReindexObjectType` rematerializes them; they are
not recovery material. Object-log identity is `(namespace, kind, key)`
([ADR 0112](decisions/0112-namespaced-object-log-identity.md)). A pre-namespace
`MIKURAV1` log fails closed on open until
`sekaictl admin store migrate-object-log --src <legacy> --dst <namespaced>`
assigns each `(kind, key)` its plane namespace from this projection and
from clerk objects.
The SQL index is the serving backend.
`SEKAI_OBJECT_LOG_DUAL_READ=1` with `SEKAI_OBJECT_LOG` is a canary: it
compares hop/count/sum/min/max/avg answers to a tagged
in-process object-log library on a sample of requests
(`SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE`, default 32; `1` for CI) and fails
closed on mismatch, missing log, or a missing `max_rows_scanned`. A
descriptor that library cannot compare without a silent rule mismatch
(property filters, `group_by`, multi-key sort, distinct, path
multiplicity, a non-i64 measure, or incoming hop direction) keeps the SQL
answer and skips the canary. After #980 every production multi-hop has
`group_by`, so those evaluates skip rather than turning the flag into a kill
switch. Whole-set min/max/avg without `group_by` compare when the reconstructed
i64 measures match the object-log; the SQL aggregation contract itself is
unchanged. Tagged `v0.1.0` is outbound-only;
incoming hops skip instead of comparing as outbound. Unsampled
requests keep the SQL answer and do not open the log. First soak
uses that library's allow-all property deny-list. Clerk
grants stay compiled on the SQL path; when a kind's property-grant
allow-list is non-empty the canary stays off instead of comparing
grant-narrowed SQL to allow-all. This is not
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
scan, kept as an explicit debug engine. It still honors the same
ready+generation+digest fence: a debug scan cannot read a revoked
membership generation. After hop-projection became the default,
operators must `ReindexObjectType` for hop kinds; pinning
`SEKAI_OBJECT_INDEX_ENGINE=nested-loop` only selects the debug scan
and does not restore evaluate while the generation is unready.
Switching engines requires
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
kind row before matching. Aggregate `sum`/`min`/`max` fail closed when
`aggregation.property` is not granted on the leaf hop kind.
