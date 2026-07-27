# Research: governed hybrid retrieval contract

Issue: [#152](https://github.com/Sannrox/sekai-chisei/issues/152)
Related: [#141](https://github.com/Sannrox/sekai-chisei/issues/141) (closed),
[#144](https://github.com/Sannrox/sekai-chisei/issues/144) (closed),
[#145](https://github.com/Sannrox/sekai-chisei/issues/145) (closed; see
[145-semantic-pattern-query.md](145-semantic-pattern-query.md)),
[#151](https://github.com/Sannrox/sekai-chisei/issues/151) (catalog projection;
coordinate, do not block), [#175](https://github.com/Sannrox/sekai-chisei/issues/175)
(closed; S1 via #281), [#281](https://github.com/Sannrox/sekai-chisei/issues/281)
(S1 shipped; lookup-first), [#360](https://github.com/Sannrox/sekai-chisei/issues/360)
(shipped FTS), [#361](https://github.com/Sannrox/sekai-chisei/issues/361)
(shipped hybrid plan)
Date: 2026-07-27
Status: **recommendation complete — Phase A/B shipped (#360 / #361)**
Operator guides: [text-fts.md](../text-fts.md),
[hybrid-retrieval.md](../hybrid-retrieval.md)

## Decision question

Should Sekai expose one retrieval plan across graph/ontology, retained
documents/evidence, datasets/virtual tables, and a future lexical/vector
index—and how should provenance, authorization, ranking, and failure semantics
remain representation-independent?

## Product posture

- Existing **graph**, **datasets**, **evidence**, **Kioku**, and **lineage**
  remain sources of truth. Hybrid retrieval is a **read plan over adapters**,
  not a second durable store of identities or facts.
- **Similarity never reconciles identities.** A high text score may *suggest*
  an object or evidence id already present in the plane; it must not mint,
  merge, or equate durable object identities.
- Every candidate identifies **representation**, **source/version**, **score
  meaning**, and **authorization context**.
- **Partial failure and truncation are explicit.** No “automatic best” that
  hides which adapters ran, failed, or were capped.
- **SQLite is the complete baseline.** Any index or fusion path must work on
  the community SQLite runtime before optional PostgreSQL acceleration.
- **Event-stream ingestion** and **embedding-model development** are out of
  scope for this contract and its first verticals.

## Evidence collected

### Current-contract inventory

| Surface | Location | Representation | Ranking / score | Authz / failure |
| --- | --- | --- | --- | --- |
| `Traverse` / `GraphQuery` | `src/sekai/query.rs`, `Traverse` RPC | Asserted graph BFS | None (set result) | Kind/property filters; no hybrid partial-failure envelope |
| `RetrieveContext` (#144) | `src/sekai/retrieval.rs`, `RetrieveContext` RPC | Asserted graph + opt-in entailment | Deterministic `context_affinity_score` (depth + multi-root corroboration) | Roots unresolved/denied; depth/objects/links/source/derived/time/explanation truncation reasons; ontology revision on explanations |
| Ontology class/relation CRUD + inspect | `proto/sekai.proto`, ontology modules, ADR 0001/0003 | Vocabulary metadata | N/A (definition, not retrieval rank) | Authenticated; ACL-filtered discovery |
| Datasets / `QueryRows` / virtual tables | `src/sekai/dataset.rs`, `QueryRows` | Tabular rows with equality-style filters | None | Dataset-scoped; not free-text |
| Evidence submissions | `src/db/evidence.rs`, Get/List/content RPCs | External envelopes + projected objects | Lifecycle list filters, not ranked search | Content disclosure fail-closed when non-disclosable |
| Kioku memories | `src/chisei/kioku.rs`, `ListKiokuCandidates` / retrieve path | Operational memory + evidence refs | Rank from affinity hits, confidence_bps, freshness | Namespace/actor/classification ceiling; evidence resolvability |
| Lineage | `src/sekai/lineage.rs`, `GetLineage` | Provenance link walk | Truncation by depth | Relation-kind filter on lineage edges |
| Capability catalog (#106/#107) | `DiscoverCapabilities`, `docs/capability-catalog.md` | Discovery metadata over existing RPCs | N/A | Visibility ≠ grant; invoke rechecks authz |
| Pattern / multi-hop IR (#145) | Research only | Future structured join plan | N/A | Separate from score fusion |
| Full-text (FTS) text representation | **Shipped (#360)** — `SearchText`, `src/sekai/text_fts.rs`, [text-fts.md](../text-fts.md) | `text.fts5` / `HybridCandidate` | `text.fts5_bm25/v1` (higher is better as `-bm25`) | Authz re-check; SQLite complete; no embedding store |
| Hybrid late-fusion plan | **Shipped (#361)** — `HybridRetrieve`, `src/sekai/hybrid.rs`, [hybrid-retrieval.md](../hybrid-retrieval.md) | Explicit multi-adapter plan | Named fusion profiles only (`late_fusion.rrf/v1`, `graph_priority/v1`, `identity/v1`) | Partial-failure metadata; pure graph stays on `RetrieveContext` |
| Vector / embedding index | **Absent** | — | — | No embedding store; out of scope for first verticals |

### What already matches a hybrid candidate shape

`ContextCandidate` already carries:

- durable object payload;
- structural path metadata (`depth`, `via_relation`);
- a **named score** (`affinity` with documented meaning in
  `context_affinity_score`);
- explanation with source fact ids, ontology revision, asserted/derived steps;
- response-level truncation and denial counters.

That is the **graph representation** of the target envelope. Gaps for hybrid
work are cross-representation identity of *score meaning*, explicit
**representation id**, and a plan that can return **mixed** candidates without
pretending one ranking is universal.

### What is deliberately not present

- No event-stream ingestion plane (out of scope).
- No embedding model training, fine-tune, or provider-embedding product
  (out of scope for development; future adapter may call an **already
  available** embedding API only under a separate issue).
- No monorepo “automatic best retrieval” that selects adapters without the
  caller naming them.
- No similarity-driven object merge or external-id inventing.

### Coordination (not hard blocks)

| Work | Relationship |
| --- | --- |
| #144 (closed) | Graph adapter = existing `RetrieveContext` (+ asserted default). |
| #145 (closed) | Multi-hop **pattern IR** is structured join, not late fusion. Implement as its own vertical; hybrid may *call* graph after pattern expand later. |
| #151 (open) | Catalog should **project** hybrid/resolve/expand/retrieve capabilities; hybrid API must not wait on #151, and #151 must not depend on a speculative mega-RPC. |
| #175 / #281 | Lookup-first answers may later bind fixed capability contracts to hybrid or graph-only plans; research #175 already defers until catalog substrate is ready. |

### SQLite cost sketch (directional)

| Approach | Storage | Query | Fit |
| --- | --- | --- | --- |
| Graph-only (status quo) | Asserted objects/links only | Bounded BFS / entailment limits already enforced | Baseline |
| **FTS5 external content** over authorized text projections | Index rows keyed by `(source_kind, source_id, version)` + content hash | BM25/`rank` with post-filter ACL | Complete on SQLite; rebuildable from sources of truth |
| Dense vectors in SQLite blob + brute force | Large; model version couples index | Linear scan unless external ANN | Defer; model development out of scope |
| Dense vectors + external ANN | Breaks single-file baseline unless optional | Fast | Optional later; never required for contract validity |

**Finding:** the first non-graph representation that preserves local-first
completeness is **lexical FTS**, not vectors.

## Options evaluated

| # | Option | Verdict |
| --- | --- | --- |
| 1 | **Federated typed adapters** with explicit caller selection of representations | **Core architecture** |
| 2 | **Deterministic late fusion** of graph + **one** text representation | **v1 product plan** (graph + FTS) |
| 3 | Separate surfaces only; compose solely via #151 | Insufficient alone—callers still need a shared candidate/failure envelope; #151 is the *agent* projection, not the core IR |
| 4 | Full-text first, defer any unified plan | Acceptable phase-0, but loses a versioned fusion contract and invites ad-hoc client ranking |
| 5 | Single opaque “smart retrieval” RPC with automatic adapter choice | **Reject** — violates explicit selection and “no automatic best” |
| 6 | Early fusion / joint embedding of graph+text | **Reject for now** — couples training/index to core; similarity identity risk higher |

## Recommendation

Adopt **federated typed adapters** as the durable hybrid contract, and ship
**deterministic late fusion of graph + one lexical text representation** as the
first hybrid plan. Do **not** introduce a black-box automatic selector. Do
**not** make #151 or #145 block the index vertical; coordinate wire shapes so
catalog capabilities and future pattern IR can invoke the same adapters.

### Contract principles

1. **Adapter boundary.** Each representation implements an internal (and
   eventually public-plan) adapter:

   - `representation_id` (stable string, e.g. `graph.retrieve_context`,
     `text.fts5`, `dataset.rows`, `evidence.submission`, `kioku.memory`);
   - `source` + `source_version` (table/index generation, ontology revision,
     package version, content hash as appropriate);
   - `score` + `score_kind` (e.g. `graph.context_affinity/v1`,
     `text.fts5_bm25/v1`—**never** compare raw floats across kinds without a
     fusion profile);
   - optional `entity_ref` (object id, link id, evidence id) that is only set
     when the **source of truth already asserts** that identifier;
   - `authz_context` summary (namespace, principal class, classification
     ceiling applied)—enough for audit, not a grant token;
   - per-candidate truncation / denial flags where applicable.

2. **Sources of truth stay writable only through existing APIs.** Indexes are
   **rebuildable projections**. Deleting or denying source material must make
   candidates disappear on next recheck even if the index is briefly stale
   (fail closed on disclosure: re-check ACL before return).

3. **Similarity never assigns identity.** Fusion may *order* candidates and may
   *group* candidates that already share an `entity_ref`. It must not create
   equivalence between distinct durable ids based on score.

4. **Caller selects representations and fusion profile.** Empty selection is
   invalid or defaults only to **graph asserted** (document either way in the
   vertical; recommend **require explicit list** for hybrid RPC, keep
   `RetrieveContext` for pure graph).

5. **Partial failure is first-class.** Response includes per-adapter status:
   `ok | truncated | denied_empty | error_code` without leaking hidden names.
   Overall success can still return candidates from healthy adapters.

6. **Ranking is versioned and testable.** A fusion profile id (e.g.
   `late_fusion.rrf/v1` or `late_fusion.graph_priority/v1`) defines how
   heterogeneous scores become an order. Fixtures pin profile → order. Profiles
   are additive; renaming requires a new version.

7. **SQLite complete.** FTS5 (or equivalent) and fusion must run without
   PostgreSQL. PG may later provide parallel implementations, not different
   semantics.

### v1 shape (logical)

```text
HybridRetrieveRequest
  representations[]   # explicit, non-empty for hybrid path
  graph: RetrieveContext-compatible bounds (optional block)
  text:  query string + source kinds (evidence | object_props | …)
  fusion_profile      # required when len(representations) > 1
  limits: max_candidates, max_per_representation, max_time_ms

HybridRetrieveResponse
  candidates[]        # HybridCandidate envelope
  adapter_results[]   # per representation status + truncation reasons
  fusion_profile
  truncated
```

Wire placement: prefer **one additive gRPC** on Sekai (or a versioned plan
message reusable by #151) rather than overloading `RetrieveContext` with
unrelated text fields. Pure graph callers keep `RetrieveContext` unchanged.

### Phase plan

| Phase | Deliverable | Issue shape |
| --- | --- | --- |
| **A** | Shared `HybridCandidate` (+ score_kind registry) and **SQLite FTS** text representation over a **narrow** authorized corpus (start with evidence content and/or selected object property text already visible to the principal). Rebuild/index maintenance from sources of truth. ACL re-check on read. | Feature: index + candidate contract |
| **B** | Late-fusion executor: graph adapter (wrap `RetrieveContext`) + FTS adapter; explicit representation selection; versioned fusion profile; partial-failure metadata; deterministic tests. | Feature: hybrid plan |
| **C** (later, separate issues) | Dataset row adapter; Kioku adapter; optional vector adapter using **pre-existing** external embeddings; catalog projection via #151; multi-hop pattern IR from #145 feeding graph roots into the same plan. | Do not open here |

### Explicit non-actions

- Do not build event ingestion or embedding training in core for this work.
- Do not treat FTS or vector hits as ontology entailment or as ACL grants.
- Do not block #151 on hybrid; do not block hybrid on #151.
- Do not replace `RetrieveContext`, `QueryRows`, Kioku, or evidence APIs.
- Do not promise cross-representation score comparability outside a named
  fusion profile.
- Do not auto-select “best” adapters from free-form NL in core (agent NL
  planning stays outside or on a governed model call per #151/#175).

## Follow-up issues

Opened two focused verticals (implementation; not research):

1. [#360](https://github.com/Sannrox/sekai-chisei/issues/360) — **shipped** —
   **feat(sekai): SQLite FTS text representation and HybridCandidate contract**
   Candidate envelope + FTS5 projection + authz re-check + rebuild story.
   Operator guide: [../text-fts.md](../text-fts.md).
2. [#361](https://github.com/Sannrox/sekai-chisei/issues/361) — **shipped** —
   **feat(sekai): late-fusion hybrid retrieval plan (graph + FTS)**
   Explicit multi-representation plan, fusion profile v1, partial failure.
   Operator guide: [../hybrid-retrieval.md](../hybrid-retrieval.md).

## Impact on related work

- **#151:** project named capabilities (`retrieve_context`, later
  `hybrid_retrieve`) with limits and fusion_profile in metadata; invocation
  still rechecks authz.
- **#145:** pattern IR remains the multi-hop *structure* path; hybrid late
  fusion remains the multi-*representation* path.
- **#281 / #175:** hybrid improves lookup substrate but does not by itself
  authorize model-call substitution.

## Conclusion

**Recommend federated typed adapters with deterministic late fusion of graph
plus one lexical (FTS) text representation.** Keep existing surfaces as sources
of truth; make scores, versions, authz, and partial failures explicit; reject
automatic best and similarity-based identity. Close research #152 with this
recommendation and the two follow-up feature issues above.
