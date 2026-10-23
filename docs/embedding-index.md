# Embedding index

The embedding index keeps vectors of object properties for a later vector
search API ([ADR 0117](decisions/0117-governed-embedding-index.md)). Vectors
are derived data: each carries the object's marking and the classification of
every source property, and catch-up follows the object-change feed.

## Stored specs

`PutEmbeddingSpec`, `ListEmbeddingSpecs` and `DeleteEmbeddingSpec` manage the
specs of a namespace. They are classified `experimental` and are rejected
unless `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled. The caller must be a credential admin with the namespace grant
(write for put and delete).

A spec names the object kind, the source properties, `chunk_chars`,
`dimension`, `batch_size`, and `model`: a hosted catalog route,
`hosted.<profile>/<upstream model>`. Deleting a spec removes its vectors and
rebuild history and resets its checkpoint. Put and delete both move the
spec's checkpoint revision on, never back, so a catch-up that listed the spec
before the change writes nothing.

## Catch-up

In combined mode every instance runs a catch-up pass over all stored specs
every 30 seconds. Each pass admits the spec's route as hosted execution
does: the routing profile must be registered in the namespace with an
allowlisted origin, the namespace policy must allow its runtime and list the
model in `allowed_models`, the namespace residency rules and the provider
privacy gate must permit the route for the namespace's data class, the model
must match the profile's model patterns, its credential reference must
resolve, and model review must admit it. The route is admitted again from
live state before every request; a changed origin, pinned weights digest,
model patterns or credential is refused, and the next pass builds a new client. Each object's whole source text passes the execution payload
leak check before any chunk of it is sent.
A refused or failing spec is logged and retried on the next pass; it does not
stop the others. Writes are fenced on the spec's revision, so instances never
interleave. A rebuild holds a five-minute lease that it renews before every model
call and with every object it writes, and a model call is cut off after
two and a half minutes; other instances leave it alone until the lease lapses, then take it
over.
Split planes do not run catch-up: it needs the Sekai change feed and the
Chisei route catalog in one process.

The route calls the OpenAI-compatible `POST <origin>/v1/embeddings`. It is
external unless its origin is loopback, and an external route refuses a spec
whose source properties are classified sensitive. Vectors are versioned by
the weights digest the profile pins, if any. A changed spec, model, or pinned
digest changes the spec digest, and the next pass replaces the vectors as a
recorded rebuild. `sekai_embedding_index_lag_ms` reports the age of the
oldest change a pass consumed.

## Query embedding

`embed_query` (#1681) embeds the text of a vector search query for the
stored spec of an object kind, through the same admitted route catch-up
uses (in combined mode, the hosted route admitted and readmitted as above).
It refuses when:

- the namespace has no stored spec for the kind, or more than one;
- the route's model and version do not give the spec digest the index was
  built with, so the query would be compared with unlike vectors;
- the route is external and a source property of the spec is classified
  restricted, as indexing refuses;
- the route's payload screen refuses the text.

Hybrid `Search` (#1582) calls it; see [search.md](search.md#hybrid-search).

