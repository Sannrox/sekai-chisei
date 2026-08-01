# SQLite FTS text representation and HybridCandidate

Issue: [#360](https://github.com/Sannrox/sekai-chisei/issues/360).  
Research freeze: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md).

## Purpose

Provide a durable **HybridCandidate** envelope backed by an authorization-built
per-request lexical corpus. The existing rebuildable global FTS projection is
kept as an internal optimization, but public SearchText never ranks against it.
Late fusion across adapters is a separate vertical (#361).

## Guarantees

- **Authorization precedes ranking.** SearchText enumerates source-of-truth
  object properties and readable evidence for the caller, then builds a private
  in-memory FTS5 table from those rows only. Hidden, stale, retracted, or
  unprojected material never enters the candidate set, rank calculation, or
  truncation accounting. Public denial counts remain zero and `scanned` counts
  only returned authorized hits.
- **Both source kinds make progress.** When `source_kinds=all`, the bounded
  authorized corpus gives object properties and evidence an even document and
  byte share so a large authorized object corpus cannot starve evidence rows.
- **The global projection is internal.** `sekai_text_fts` and its rebuild
  generation are retained for internal maintenance and migration compatibility;
  `text.fts5` is not a public representation id and is rejected by HybridRetrieve.
- **Stable non-disclosure behavior.** The adapter uses the fixed source version
  `authorized-text/v1`; deadline exhaustion is reported only as the generic
  `max_time_ms` truncation reason and never includes hidden identifiers or
  denial counts. The enclosing hybrid plan owns the shared budget.
- **Similarity never mints identity.** `entity_ref` is set only when a source
  of truth already asserts the id (`object`, `evidence_submission`). Text
  scores do not create, merge, or equate durable ids.
- **Versioned score meaning.** Text hits use `score_kind =
  text.authorized_bm25/v1`. The numeric `score` is `-bm25(authorized_text_fts)`
  so higher is better. Scores
  must not be compared with `graph.context_affinity/v1` without a named fusion
  profile (#361).
- **SQLite complete.** This vertical does not require PostgreSQL. `SearchText`
  fails closed on non-SQLite community runtimes until a parity implementation
  exists.

## HybridCandidate fields

| Field | Meaning |
| --- | --- |
| `representation_id` | Stable public adapter id (`text.authorized`) |
| `source` / `source_version` | Authorization-built origin and fixed version (`sqlite.authorized_text`, `authorized-text/v1`) |
| `score` / `score_kind` | Rank value and versioned meaning (`text.authorized_bm25/v1`) |
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
  max_time_ms (shared-plan deadline bound)
  rebuild (legacy compatibility flag; ignored by public SearchText)
```

Response: `HybridCandidate[]`, representation/source_version, truncation
reasons (`max_candidates`, `authorized_corpus`, or `max_time_ms`),
`denied_count`, `scanned`.

Optional catalog binding uses capability `sekai.text.search` with the same
receipt metadata contract as other semantic retrieval surfaces
(`x-sekai-capability`, `x-sekai-namespace`, `x-sekai-operation-id`).

## Storage and rebuild

Migration creates:

- `sekai_text_fts_meta` — generation, rebuild timestamp, corpus profile
  `evidence_content+object_props/v1`
- `sekai_text_fts_docs` — shadow rows keyed by `doc_id`
- `sekai_text_fts` — FTS5 external-content virtual table over `text_body`

Internal rebuild (`rebuild_text_fts`, outside the public SearchText request):

1. Clears the virtual table and docs.
2. Indexes string leaves of retained evidence `envelope.content` for lifecycle
   states that may still disclose content (`available`, `superseded`,
   `retracted`, `stale`).
3. Indexes non-empty object property values (keys not starting with `_`).
4. Advances `generation` to `gen:<n+1>`.

Operators may rebuild after bulk evidence or object imports for internal
consumers. Public SearchText does not depend on rebuild freshness for ranking
and never performs the global rebuild synchronously. It reads the authorized
source rows directly on every request; the legacy `rebuild` flag is retained
only for wire compatibility.

## Non-goals

- Late-fusion multi-adapter plan (see [hybrid-retrieval.md](hybrid-retrieval.md) / #361).
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
- evidence requirements for the HybridCandidate envelope, authorization-built
  BM25 score kind, pre-ranking authorization, and SoT-only entity refs.

## Related

- Research recommendation: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md)
- Graph representation: `RetrieveContext` / `src/sekai/retrieval.rs`
- Follow-up: [#361](https://github.com/Sannrox/sekai-chisei/issues/361) late fusion
