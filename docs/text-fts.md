# SQLite FTS text representation and HybridCandidate

Issue: [#360](https://github.com/Sannrox/sekai-chisei/issues/360).  
Research freeze: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md).

## Purpose

Provide a **rebuildable lexical text projection** on the SQLite complete
baseline and a durable **HybridCandidate** envelope so text scores can later
participate in hybrid plans without silent cross-kind comparison or identity
minting. Late fusion across adapters is a separate vertical (#361).

## Guarantees

- **Sources of truth stay writable only through existing APIs.** The FTS index
  is a projection rebuilt from evidence submission content and selected object
  property text.
- **Authz re-check on read.** Each hit is re-validated against live ACL,
  classification markings, evidence lifecycle, and content digests. Denied or
  deleted material is omitted (non-disclosure). Response `denied_count` never
  names hidden objects.
- **Similarity never mints identity.** `entity_ref` is set only when a source
  of truth already asserts the id (`object`, `evidence_submission`). Text
  scores do not create, merge, or equate durable ids.
- **Versioned score meaning.** Text hits use `score_kind = text.fts5_bm25/v1`.
  The numeric `score` is `-bm25(sekai_text_fts)` so higher is better. Scores
  must not be compared with `graph.context_affinity/v1` without a named fusion
  profile (#361).
- **SQLite complete.** This vertical does not require PostgreSQL. `SearchText`
  fails closed on non-SQLite community runtimes until a parity implementation
  exists.

## HybridCandidate fields

| Field | Meaning |
| --- | --- |
| `representation_id` | Stable adapter id (`text.fts5` for this vertical) |
| `source` / `source_version` | Projection origin and generation (`sqlite.text_fts5`, `gen:N#content_hash`) |
| `score` / `score_kind` | Rank value and versioned meaning (`text.fts5_bm25/v1`) |
| `entity_ref` | Optional SoT-asserted id only |
| `authz_context` | Namespace + principal class summary for audit (not a grant) |
| `truncated` / `denied` | Per-candidate flags; denied rows are normally omitted |

## gRPC

```text
SearchText
  query (required, sanitized FTS tokens)
  namespace (optional filter)
  source_kinds: all | evidence | object_props
  max_candidates (default 20, cap 100)
  max_time_ms (default 100, cap 1000)
  rebuild (optional operator rebuild-before-search)
```

Response: `HybridCandidate[]`, representation/source_version, truncation
reasons (`max_candidates`, `max_time_ms`), `denied_count`, `scanned`.

Optional catalog binding uses capability `sekai.text.search` with the same
receipt metadata contract as other semantic retrieval surfaces
(`x-sekai-capability`, `x-sekai-namespace`, `x-sekai-operation-id`).

## Storage and rebuild

Migration creates:

- `sekai_text_fts_meta` — generation, rebuild timestamp, corpus profile
  `evidence_content+object_props/v1`
- `sekai_text_fts_docs` — shadow rows keyed by `doc_id`
- `sekai_text_fts` — FTS5 external-content virtual table over `text_body`

Rebuild (`rebuild_text_fts` / `SearchText.rebuild=true`):

1. Clears the virtual table and docs.
2. Indexes string leaves of retained evidence `envelope.content` for lifecycle
   states that may still disclose content (`available`, `superseded`,
   `retracted`, `stale`).
3. Indexes non-empty object property values (keys not starting with `_`).
4. Advances `generation` to `gen:<n+1>`.

Operators should rebuild after bulk evidence or object imports. Query-time
authz re-check keeps stale ACL or deletes fail-closed even before the next
rebuild.

## Non-goals

- Late-fusion multi-adapter plan (#361).
- Embedding models, vectors, or ANN indexes.
- Replacing `RetrieveContext`, evidence get/list, `QueryRows`, or Kioku APIs.
- Automatic adapter selection.

## Capability catalog

`DiscoverCapabilities` advertises `sekai.text.search` with:

- scopes `namespace:read`, `object:read`;
- decision points `namespace_access`, `object_acl`, `classification`,
  `evidence_content_acl`;
- limits including `max_candidates`, `max_query_chars`, and
  `mints_identity_from_similarity=0`;
- evidence requirements for the HybridCandidate envelope, BM25 score kind,
  per-hit authz re-check, and SoT-only entity refs.

## Related

- Research recommendation: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md)
- Graph representation: `RetrieveContext` / `src/sekai/retrieval.rs`
- Follow-up: [#361](https://github.com/Sannrox/sekai-chisei/issues/361) late fusion
