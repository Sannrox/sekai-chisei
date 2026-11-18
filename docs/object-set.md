# Revision-bound ObjectSet evaluation

`sekai.object-set/v1` is a typed descriptor, not a query language.
`EvaluateObjectSet` evaluates that descriptor through the same authorized
`ListObjects` and one-hop traverse paths already used by generic reads.

This RPC is `stable` on the wire and MCP-allowlisted. It is **not** part of
the advertised `sekaictl ontology` / typed SDK product loop. See
[integration-contract.md](integration-contract.md).

The descriptor names a namespace, object kind, and the published definition
digest it is bound to. v1 may include at most four equality or comparison
property filters, one `order_by`, a documented limit, and optional one-hop
traversal over one declared `link_type` with a far-side kind filter.

## Id filter

Every contract version accepts one more filter, `{ key: "id", op: "in",
value: <JSON array of ids> }`. It answers "which of these objects may this
caller read" in one call. The result is exactly the listed objects the caller
may read, through the same namespace, grant, and marking checks as any other
read. An id the caller may not read is absent, like an id that does not
exist, so a page or a count never reveals which absent ids exist.

- A list holds at most 1,000 ids. A longer list is refused with invalid
  argument and is never truncated. Capability discovery advertises the bound
  as `max_id_filter_values` on `sekai.objects.evaluate_set`.
- `in` applies only to `id`. On a property it is the unsupported-operator
  error. A server that predates the id filter returns the same error, so a
  client can tell whether the server supports it.
- The list counts as one of the four filters. Order and duplicates do not
  matter: the list is part of the query digest and the page cursor.
- On a kind with an object type index, the filter selects index members by
  object id, so the answer matches a plain evaluate of the same set.
  Aggregation and extra hops refuse it; one-hop traversal accepts it.

`sekai.object-set/v2` is the multi-hop contract: extra hops, `aggregation`,
and cost limits (`max_rows_scanned`, `max_depth`, `max_time_ms`). Hop-projection
is the shipping default. See [object-type-index.md](object-type-index.md) for
engine selection, reindex, and aggregation.

`sekai.object-set/v3` adds one optional spatial predicate to everything v2
admits: `property`, `operator` (`distance`, `contains`, or `intersects`),
`geometry_json` (a `sekai.geospatial-value/v1`), and `max_distance_m` for
`distance`. It matches like the [geospatial query](geospatial-queries.md)
with the same operator. The property must be declared on the kind and passes
the same property query and grant checks as a property filter, so an
ungranted property is refused before any row is matched. Rows are matched
after read authorization; denied rows are never matched or counted. The query
geometry holds at most 1,000 positions, and the predicate is part of the
query digest, the page cursor, and the query receipt. Matching runs in
process over visible rows, so each visible row scanned counts against
`max_rows_scanned` (default 10,000) and `max_time_ms`. v1 and v2 reject a
predicate with invalid argument. Traversal and aggregation do not evaluate
it, so combining them with a predicate fails closed, and object-set export
and object-set inputs refuse it.

## Evaluate-once

The server keeps no ObjectSet. Each `EvaluateObjectSet` call resolves
members from live authorized rows. There is no stored member list, page, or
set identity. The descriptor, including its pinned `definition_digest`, is
the durable form of a set: a client that wants to reuse a set stores the
descriptor and evaluates it again. After a definition publish the pin goes
stale; regenerate the descriptor against the new revision. See
[ADR 0086](decisions/0086-object-set-is-its-descriptor.md).

## Non-authority

The descriptor, a returned page, a continuation token, and any client-cached
set grant no write, sync, or Action power. Subsequent reads recheck live
authorization. `EvaluateObjectSetResponse.authority` is always false.
`EvaluateObjectSetResponse.source` names how this page was produced:
`sql_projection` (the `object_type_index*` serving index), `object_log`,
or `unknown` when this replica cannot say. The field is additive; clients
that do not know it ignore it. Do not open an object-log file to guess.

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

See [ADR 0066](decisions/0066-object-set-evaluate.md), Discussion
[862](https://github.com/Sannrox/sekai-chisei/discussions/862), and
[ADR 0086](decisions/0086-object-set-is-its-descriptor.md).
