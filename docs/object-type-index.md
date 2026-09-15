# Object-type membership index

A registered dataset plus key mapping is the **source of members** for a type
revision. The index is a rebuildable **projection**. It is not object
authority: delete it and rematerialize from dataset rows and Action deltas.

See [ADR 0073](decisions/0073-source-and-action-objects.md) and the published
[10⁷ envelope](research/876-object-index-envelope.md). Aggregations and
multi-hop (#878) and an alternate engine (#889) are out of scope.

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
tokens.

Schema drift (missing key or mapped column) quarantines the batch and leaves
the last consistent index readable with `stale=true`.

`sekai.object-set/v2` can group count/sum/min/max/avg/distinct across bounded
index hops (`join_property`). Cost limits (`max_rows_scanned`, `max_depth`,
`max_time_ms`) fail closed with the limit named. Two-hop at 10⁷ is still
outside the 500 ms envelope; do not treat a miss as a second object
authority.
