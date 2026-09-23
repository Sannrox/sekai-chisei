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
   from source then reapplies Action deltas. Incremental apply clears
   hop-projection ready before member upserts and keeps it false until the
   join rewrite commits, so evaluate cannot pair new member keys with old
   hop edges.
3. `GetObjectTypeIndexStatus` — `stale`, `lag_ms`, `quarantine_reason`,
   visible `member_count`.
4. `PutObjectTypeIndexEdit` — Action delta that survives a full rebuild.

Admitted object create/update still persists clerk objects and receipts
here. When `SEKAI_OBJECT_LOG` is set, the same admitted mutation is
appended through tagged mikura ingest so the log owns identity
generations. A denied or unadmitted Action does not append. SQL index
writes continue until the later retirement ADR.

One process at a time may set `SEKAI_OBJECT_LOG` to a given path: the
in-process log handle is a single writer. Several clerk processes, such as
replicas sharing PostgreSQL or separate Sekai and Chisei planes, share
object identity through the SQL index. The target is one object-log host
that every clerk process calls, and it waits on a mikura release with that
host. See [ADR 0088](decisions/0088-one-object-log-host-many-clerk-clients.md).

`EvaluateObjectSet` reads the index when a datasource is registered. Set
`required_freshness_ms` to fail closed when the index is stale or lagging.
Hidden rows never appear in members, counts, order, errors, or continuation
tokens. The SQL index remains the current evaluate backend.
`SEKAI_OBJECT_LOG_DUAL_READ=1` with `SEKAI_OBJECT_LOG` is a canary: it
compares hop/count/sum answers to a tagged in-process object-log library on
a sample of requests (`SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE`, default 32; `1`
for CI) and fails closed on mismatch, missing log, or a missing
`max_rows_scanned`. A descriptor that library cannot express (property
filters, `group_by` buckets, path multiplicity, a non-i64 sum, or incoming
hop direction) keeps the SQL answer and skips the canary. After #980
every production multi-hop has `group_by`, so those evaluates skip rather
than turning the flag into a kill switch. Tagged `v0.1.0` is outbound-only;
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
