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
([embedding-index.md](embedding-index.md)) of every requested kind that has
a stored spec. The query text is embedded through the spec's admitted
route, so hybrid search runs in combined mode only; elsewhere it fails with
`FAILED_PRECONDITION`. The search is exact over the chunk table: chunks
whose marking the caller's clearance denies are dropped before scoring,
objects are ranked by their best chunk, and the same per-object read policy
as text candidates (ACL, purpose, compiled object policy) applies before
the candidate cap, so recall is 1.0 over what the caller may read. A kind
whose active policy withholds any of the spec's source properties is not
searched, and a vector hit is dropped when the live projection hides one of
its source properties. Vector hits then pass the same live recheck as text
hits; one that does not match the text has no highlights.
`vector_lag_ms` is the age of the oldest object change the searched vectors
have not consumed.

## Status

`GetSearchIndexStatus` is a namespace read. It returns analyzer version,
lag, and index counts. Those counts are not a grant and are not a filtered
hit list.

See [ADR 0108](decisions/0108-permission-aware-search-index.md).
