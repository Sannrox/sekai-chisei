# Permission-aware search

`Search` and `GetSearchIndexStatus` are stable RPCs over the derived
search index ([ADR 0108](decisions/0108-permission-aware-search-index.md)).
The index is not authority. Every response carries `authority: false` and the
current namespace lag.

Capability discovery of `sekai.search.query` or `sekai.search.status` is not a
grant. Both RPCs are classified `stable` ([rpc-maturity.md](rpc-maturity.md),
#2243) and are served without `SEKAI_EXPERIMENTAL_RPCS`.

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
[Query bounds](#query-bounds) gives the numbers.

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
read among each spec's 10,000 nearest objects, and a filled cap marks the
count as a lower bound. A vector hit that does not match the text has no
highlights. `vector_lag_ms` is the age of the oldest object change the
searched vectors have not consumed.

Agents reach hybrid search through the MCP tool `sekai.search.query`
([capability-catalog.md](capability-catalog.md#hybrid-search-tool)), which
returns object references, never vectors. Each hybrid hit carries its fused
`score`; text-mode hits carry 0.

## Query bounds

One `Search` request keeps bounded memory and does bounded work after the
read policy, whatever the index holds (#2252). Every bound counts only
entries the store's read policy admits, so a cut never depends on entries
the caller cannot read. SQLite and PostgreSQL apply the same bounds in the
same order.

| Bound | Value | Applies to |
| --- | --- | --- |
| Text scan | 10,000 admitted documents | each source (`object`, `dataset`) |
| Vector ranking | 10,000 nearest admitted objects | each searched embedding spec |
| Candidate cap | 256 visible hits | text list and vector list, before paging |
| Page size | 100 hits (default 20) | each response |

- **Text.** Each source is scanned on its own, so one source reaching its
  bound never hides the other. A scan reads the matching index entries of
  the requested kinds in id order, a page at a time. An entry is one
  property, dataset name, or column whose text holds every query token; one
  holding only some of them is never read. PostgreSQL splits a long text
  into several indexed chunks and requires the tokens across the property's
  chunks, as SQLite does within its one row. As each document's entries
  arrive, the stored ACL, purpose, and marking filters and the grant and
  compiled-policy checks decide it; the scan stops once 10,000 documents
  were admitted and one more was found, so the entries it reads, and their
  policy checks, grow with the matching entries the caller may not read
  ahead of that point. A token longer than a
  PostgreSQL lexeme (2,047 bytes) is in no index: that query reads the
  stored text of every property of the requested kinds, or every dataset
  field, page by page and matches it in the server, so its read cost grows
  with the namespace's text. The live recheck then runs until 256 hits are
  visible.
- **Vectors.** A spec's chunks are read in pages, not loaded: memory holds
  one page and the 10,000 best-scoring admitted objects so far. Each object
  passes the per-object read policy once, before it may enter those 10,000.
  The live recheck then picks up to 256 of them, best first. Scoring still
  visits every chunk of the spec.
- **Truncation.** When a text scan stops at its bound, more visible hits
  may exist and `count_is_lower_bound` is true. A text scan that stops
  without yielding any hit the caller receives does not set it, whatever
  filters the request carries, so the count never reveals hidden matches;
  such a search reports an exact zero even if its filters dropped hits it
  could have read. A vector list sets it only when it fills 256 live,
  visible hits. A vector ranking that drops admitted objects past its
  10,000 does not set it, because that cut runs before the source-value
  checks; recall is then 1.0 only over the 10,000 nearest.

The maximum supported index size is 10^6 vectors per embedding spec, the
latency budget of [ADR 0117](decisions/0117-governed-embedding-index.md):
exact vector scoring over 10^6 vectors must finish within 2 s
(`exact_vector_latency_budget_at_one_million_vectors`, run in release). Text
search has no benchmarked size limit: the scan bound keeps the plane's
memory and post-policy work independent of index size, but each page asks
the database for the next matches in id order, which it finds by matching
and ordering every entry for the query, so text read cost grows with the
number of matching entries times the pages read. A larger index needs an approximate
nearest-neighbour index behind `SearchIndex::vector_candidates`, as ADR 0117
records.

## Embedding spec limits

`PutEmbeddingSpec` refuses a spec past these limits with `INVALID_ARGUMENT`,
and a new spec in a full namespace with `RESOURCE_EXHAUSTED` (#2244).
Catch-up checks the same spec limits and refuses, before any model call, an
object whose chunks would take its spec past the vector limit; the spec is
reported as failing until it is changed. A refusal makes no model call, and
growth waits until the deletes and shrinks in the same page of changes have
released their vectors. A spec stored before these limits that exceeds one
keeps its vectors but is refused on the next catch-up.

The limit counts stored vectors, which can include those of objects deleted
or shrunk in changes the catch-up has not reached yet. A spec that stays
refused although its objects now fit recovers when an operator deletes and
puts it again (`DeleteEmbeddingSpec`, then `PutEmbeddingSpec`): the next pass
rebuilds it from the current objects.

| Limit | Value |
| --- | --- |
| `dimension` | 4,096 |
| `chunk_chars` | 8,192 |
| `batch_size` | 256 texts per model call |
| Source properties | 32 per spec |
| Specs | 16 per namespace |
| Vectors | 1,000,000 per spec |

Exact vector scoring costs vectors times dimension; the 2 s latency budget in
[Query bounds](#query-bounds) was measured at 64 dimensions.

`ListEmbeddingSpecs` pages by spec id: `page_size` is at most 100 (0 means
100), and a non-empty `next_page_token` is sent back as `page_token` for the
next page. A client that sends neither receives up to 100 specs, more than a
namespace may hold.

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
