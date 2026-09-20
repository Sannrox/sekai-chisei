# Revision-bound ObjectSet evaluation

`sekai.object-set/v1` is a typed descriptor, not a query language.
`EvaluateObjectSet` evaluates that descriptor through the same authorized
`ListObjects` and one-hop traverse paths already used by generic reads.

The descriptor names a namespace, object kind, and the published definition
digest it is bound to. v1 may include at most four equality or comparison
property filters, one `order_by`, a documented limit, and optional one-hop
traversal over one declared `link_type` with a far-side kind filter.

`sekai.object-set/v2` is the multi-hop contract: extra hops, `aggregation`,
and cost limits (`max_rows_scanned`, `max_depth`, `max_time_ms`). Hop-projection
is the shipping default. See [object-type-index.md](object-type-index.md) for
engine selection, reindex, and aggregation.

## Non-authority

The descriptor, a returned page, a continuation token, and any client-cached
set grant no write, sync, or Action power. Subsequent reads recheck live
authorization. `EvaluateObjectSetResponse.authority` is always false.

## Revision fence

Evaluation requires the pinned `definition_digest` to match the current
published definition revision. A stale pin, expired cursor, changed
authorization snapshot, or changed descriptor is a typed non-success and
returns no partial page. Regenerating the same filters against a newer
revision is a new evaluation.

Hidden rows and ungranted properties cannot affect visible members, counts,
sort order, errors, or continuation tokens. Ungranted property predicates
fail closed before a page is returned.

## Backends

ObjectSet adds no store. SQLite and PostgreSQL share the existing graph
list and link surfaces. Isolated PostgreSQL proof is the same graph
conformance already required for those surfaces.

See [ADR 0066](decisions/0066-object-set-evaluate.md) and Discussion
[862](https://github.com/Sannrox/sekai-chisei/discussions/862).
