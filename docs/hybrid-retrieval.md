# Late-fusion hybrid retrieval (graph + FTS)

Issue: [#361](https://github.com/Sannrox/sekai-chisei/issues/361).  
Research freeze: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md).  
Depends on: [text-fts.md](text-fts.md) / [#360](https://github.com/Sannrox/sekai-chisei/issues/360).

## Purpose

Provide one governed plan that combines **graph context retrieval** with
**lexical FTS** without inventing opaque “automatic best” ranking. Callers name
representations and a versioned fusion profile; scores keep their
representation-specific `score_kind`.

## Guarantees

- **Explicit selection.** `representations` must be non-empty. Empty selection
  is rejected; pure graph callers keep `RetrieveContext` unchanged.
- **Fusion profile required for multi-adapter plans.** Supported v1 profiles:
  - `late_fusion.rrf/v1` — reciprocal rank fusion (k=60) over adapter ranks
  - `late_fusion.graph_priority/v1` — all graph candidates first, then others
  - `late_fusion.identity/v1` — adapter selection order (default when a single
    representation is selected and `fusion_profile` is empty)
- **No silent cross-kind score comparison.** Each candidate retains
  `representation_id`, `score`, and `score_kind`
  (`graph.context_affinity/v1` or `text.authorized_bm25/v1`).
- **Partial failure is first-class.** Per-adapter status is
  `ok | truncated | denied_empty | error`. Healthy adapters still contribute
  candidates when another side fails.
- **Authz re-check.** Graph and text adapters re-use live ACL / marking /
  evidence checks. Hidden material is omitted; fusion order, public counts, and
  error messages must not expose denied sources. Denial accounting stays
  internal to the adapter.
- **Similarity never mints identity.** `entity_ref` is set only when a source
  of truth already asserts the id.
- **SQLite complete baseline.** No external vector service is required.

## gRPC

```text
HybridRetrieve
  representations[]          # required, non-empty
                             # graph.retrieve_context | text.authorized
  graph: HybridGraphParams   # RetrieveContext-compatible bounds
  text:  HybridTextParams    # query + source_kinds; legacy rebuild is ignored
  fusion_profile             # required when len(representations) > 1
  max_candidates             # default 40, cap 200
  max_per_representation     # default 20, cap 100
  max_time_ms                # shared budget; default 100, cap 1000
```

Response:

- `candidates[]` — fused `HybridCandidate` envelope
- `adapter_results[]` — per representation status, truncation reasons,
  candidate/denied counts, non-sensitive error code/message
- `fusion_profile` — profile actually applied
- `truncated` / `truncation_reasons` — overall caps (`max_candidates`,
  `max_time_ms`, and adapter-level reasons)

## Adapters

| Representation | Adapter | Score kind |
| --- | --- | --- |
| `graph.retrieve_context` | Wraps existing `RetrieveContext` semantics (#144) | `graph.context_affinity/v1` |
| `text.authorized` | Wraps the authorization-built SearchText corpus (#497) | `text.authorized_bm25/v1` |

## Capability catalog

`DiscoverCapabilities` advertises `sekai.hybrid.retrieve` with:

- scopes `namespace:read`, `object:read`;
- decision points including namespace, object ACL, classification, ontology,
  and evidence content ACL;
- limits for `max_candidates`, `max_per_representation`,
  `requires_explicit_representations=1`, and
  `mints_identity_from_similarity=0`;
- evidence requirements for the HybridCandidate envelope, per-adapter status,
  versioned fusion profile, and partial-failure metadata.

Optional catalog binding uses the same receipt metadata contract as other
semantic retrieval surfaces (`x-sekai-capability`, `x-sekai-namespace`,
`x-sekai-operation-id`).

## Non-goals

- Maintaining the internal global FTS projection (done in #360).
- Multi-hop pattern IR (delivered as [#375](https://github.com/Sannrox/sekai-chisei/issues/375);
  see [pattern-plan.md](pattern-plan.md) / research [#145](research/145-semantic-pattern-query.md)).
- Automatic NL adapter selection or embedding training.
- Identity reconciliation from similarity scores.
- Replacing catalog composition (#151) or lookup-first model substitution.

## Related

- Research: [152-hybrid-retrieval.md](research/152-hybrid-retrieval.md)
- Text: [text-fts.md](text-fts.md)
- Graph: `RetrieveContext` / `src/sekai/retrieval.rs`
- Fusion: `src/sekai/hybrid.rs`
