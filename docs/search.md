# Permission-aware search

`Search` and `GetSearchIndexStatus` are experimental RPCs over the derived
search index ([ADR 0108](decisions/0108-permission-aware-search-index.md)).
The index is not authority. Every response carries `authority: false` and the
current namespace lag.

Capability discovery of `sekai.search.query` or `sekai.search.status` is not a
grant. Both RPCs stay classified `experimental`
([rpc-maturity.md](rpc-maturity.md)) and are rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is enabled.

## Search

`Search` takes text plus optional kind, source (`object`, `dataset`, or empty
for both), property equality filters, requested facets, and a page size.
`next_page_token` is opaque and bound to the request that produced it: the
namespace, text, kinds, source, filters, mode, weights, and page size. Send it
back with the same request to get the next page. A token from a different
request, or one that does not decode, fails with `INVALID_ARGUMENT`. Tokens
are not signed: an edited offset only moves within results the caller may
already read, because every hit is rechecked on the live authorized
projection.
Candidates are selected under the caller's compiled read policy. Each
candidate is rechecked on the live authorized projection. Highlights and
facet values come from that projection, never from indexed text.

Paging, the candidate cap, counts, and facets apply only after policy. Hidden
matches do not consume a page or turn an empty result into a lower-bound
count. When the cap is reached, `count_is_lower_bound` is true. Property
equality filters are applied on the live projection after a bounded
policy-scoped candidate scan; if that scan is full and a filter is present,
the count is a lower bound because the index has no candidate cursor.

An ungranted property filter or facet fails closed. Dataset metadata
(name and column names) is searchable at the discover level, the way
`ListDatasets` is. Object hits require read. Column classifications the
caller cannot cover are not matched or returned.

## Hybrid search

`mode: "hybrid"` adds vector candidates to the text candidates and fuses the
two lists under the one named profile `late_fusion.rrf/v1`: reciprocal rank
fusion with k = 60, each list weighted by `text_weight` and
`vector_weight` (both 0 means 1 each; a list weighted 0 adds nothing). Ties
break by source and id, so a fixed index returns a fixed order. The
response names the profile in `fusion_profile`. Hybrid search needs text.

Vector candidates come from the embedding index
([embedding-index.md](embedding-index.md)): every stored spec of the
requested kinds, or of all kinds when none are named. The query text is
embedded once per spec through its admitted route, so hybrid search runs in
combined mode only; elsewhere it fails with `FAILED_PRECONDITION`. A spec
whose kind's active policy withholds any of its source properties is not
searched.

The search is exact over the chunk table, on SQLite and PostgreSQL alike (#1682). Chunks whose marking the caller's
clearance denies are dropped before scoring, and objects rank by their best
chunk across all searched specs. Before a candidate counts toward the cap
it must pass the same per-object read policy as text candidates (ACL,
purpose, compiled object policy) and the live recheck. A vector hit is also
dropped when the live projection hides one of its source properties, or
when the object's kind or source text changed since it was embedded: a stale
vector may carry a value the caller can no longer read. Hidden objects
therefore never use up the cap, recall is 1.0 over what the caller may
read, and a filled cap marks the count as a lower bound. A vector hit that
does not match the text has no highlights. `vector_lag_ms` is the age of the
oldest object change the searched vectors have not consumed.

Agents reach hybrid search through the MCP tool `sekai.search.query`
([capability-catalog.md](capability-catalog.md#hybrid-search-tool)), which
returns object references, never vectors. Each hybrid hit carries its fused
`score`; text-mode hits carry 0.

Agents reach hybrid search through the MCP tool `sekai.search.query`
([capability-catalog.md](capability-catalog.md#hybrid-search-tool)), which
returns object references, never vectors. Each hybrid hit carries its fused
`score`; text-mode hits carry 0.

## Index catch-up

`Search` and `GetSearchIndexStatus` only read the index. The one write
they make is an empty checkpoint for an authorized namespace the index does
not follow yet, such as one whose only content is unbound datasets, so the
worker finds it. A scheduled worker on every Sekai plane keeps the index
current: every 10 seconds it visits up to 64 namespaces (those with object
history or an index checkpoint), continuing after the last one on the next
pass. Each visit consumes one page of the
object-change feed and re-reads the dataset catalog when its digest changed.
A namespace rebuilds when its index is not complete for the current
analyzer or the feed lost changes it had not consumed.

Several instances may run the worker at once. Every index write is fenced
on a revision in the namespace checkpoint: a writer whose revision moved
stops, and its namespace is retried on a later pass. A rebuild clears the
checkpoint's analyzer version until it completes and renews a five-minute
lease with every write. Other instances leave the namespace alone while
the lease holds and take the rebuild over once it lapses, so a rebuild that
died part-way is redone instead of reported current.

This index lives in its own `sekai_search_*_v2` tables. Planes from before
the scheduled worker keep reading and writing the unsuffixed
`sekai_search_*` tables, so during a rolling upgrade or after a rollback the
two versions never write each other's index; both follow the object-change
feed and the dataset catalog, which stay the source of truth. The upgrade
creates the new tables once and seeds them from the old ones, so search
starts warm; a namespace whose old index was stale or mid-rebuild is caught
up or rebuilt by the worker. The unsuffixed tables are retired and are
dropped in a later release.

## Status

`GetSearchIndexStatus` is a namespace read. It returns analyzer version,
lag, and index counts from durable state. The analyzer version is empty
before the first build and while a rebuild is in progress. Those counts are
not a grant and are not a filtered hit list.

See [ADR 0108](decisions/0108-permission-aware-search-index.md).
