# ADR 0117: Embeddings are a derived index that inherits source governance

- Status: accepted
- Date: 2026-10-19
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1581
- Issue: #1581
- Supersedes: none
- Superseded by: none
- Related: [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0096](0096-sekai-runs-without-chisei.md),
  [ADR 0104](0104-namespace-object-change-generation.md),
  [ADR 0108](0108-permission-aware-search-index.md)

## Context

Semantic retrieval needs vectors computed from object properties. A vector is
derived from marked data and can leak it: it may be sent to an external model
to be computed, and it outlives the text it came from unless it follows edits.

## Decision

1. An embedding spec names one object kind in one namespace, its source
   properties in order, a character chunk size, the vector dimension and a
   batch size. The spec, the chunk rule (`embed.chars/v1`), the model and the
   model version hash to a spec digest stored with the checkpoint.
2. Vectors are a derived projection like the search index (ADR 0108): losing
   them loses no facts. Catch-up follows the object-change feed from a
   checkpoint and the namespace generation (ADR 0104). A feed gap or a new
   spec digest rebuilds the spec's vectors and records the rebuild with the
   old and new digest and the object count.
3. Chunks are content-addressed. Catch-up re-embeds only chunks whose digest
   changed and drops chunks past the new chunk count.
4. Every vector row carries the model, model version, source digest, the
   object's marking (joined per #1403) and the schema classification of each
   source property. An object edit that changes its marking retags all of the
   object's rows even when no chunk text changed. A schema classification
   change is not an object change; it reaches the rows on the object's next
   edit or the next rebuild.
5. The model route is admitted by the same model review state as other model
   calls; the caller supplies that admission. A route that sends text out of
   the deployment may only embed properties the egress policy lets leave
   (schema classification and the object's external-property list). Any
   other property fails the catch-up closed; it is never dropped silently.
6. Models sit behind the `Embedder` seam in `sekai-provider`. A failure leaves
   the checkpoint where it was, so the next catch-up retries.
7. Every write to a spec's index (vectors, deletes, resets, checkpoint) is a
   compare-and-bump of a per-spec revision in the same transaction. Two
   catch-ups for one spec cannot interleave: the stale one fails with a
   conflict and keeps nothing past that point.
8. A catch-up acknowledges namespace generations only as far as the
   mutations it consumed account for; a shortfall after the last page means
   the feed was purged and forces a rebuild. A page never ends inside a
   mutation, so no mutation is counted twice. A rebuild clears the stored
   spec digest when it resets the index and publishes the new digest only
   when it completes, so an interrupted rebuild is redone, never trusted.
   Mutations are identified like the search index does, by object and
   millisecond timestamp; two writes to one object in the same millisecond
   undercount, which can only trigger an unneeded rebuild. Rebuilds walk objects by id
   keyset, so deletions during the walk cannot skip a surviving object.
9. The catch-up needs the Chisei egress policy and the Sekai store, so it
   lives in `src/composition` (ADR 0096); the index types and storage stay
   in Sekai.

## Consequences

Both community backends store the same three tables (chunks, checkpoints,
rebuilds). The search API over vectors is a separate change.

Amended by #1609: specs are stored per namespace (`sekai_embedding_specs`)
and name a hosted catalog route as their model. Combined mode runs catch-up
on a schedule over every stored spec, admitting each route as hosted
execution does; the route is external unless its origin is loopback. See
[embedding-index.md](../embedding-index.md).

Amended by #1582: vector search is exact over the chunk table, filtered by
the compiled read policy before the candidate cap, so recall is 1.0. The
10^6-vector check is a latency budget; an ANN index is added behind
`SearchIndex::vector_candidates` only if measured latency fails it. Hybrid
`Search` fuses text and vector candidates under one named profile,
`late_fusion.rrf/v1` (reciprocal rank fusion, k = 60). An embedded HNSW index
was rejected for now (no measured need), and so were PostgreSQL-only vectors
(they leave SQLite without vector search). See
[search.md](../search.md#hybrid-search).
