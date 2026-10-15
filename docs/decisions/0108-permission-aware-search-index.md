# ADR 0108: Search is a derived index, selected and decided under the read policy

- Status: accepted
- Date: 2026-10-15
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1534
- Issue: #1534 (for #1406)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0025](0025-storage-enforced-object-security.md),
  [ADR 0030](0030-row-scoped-query-access.md),
  [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0076](0076-compiling-policy-entry.md),
  [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0090](0090-object-change-action-bindings.md),
  [ADR 0104](0104-namespace-object-change-generation.md)

## Context

#1406 asks for full-text and filtered search across object types, object
properties, and dataset metadata, with facets. A search index is a second
copy of data. If it answers hits, counts, facets, or highlights on its own,
it can reveal objects, rows, or properties that a read would hide.

The plane already has one read decision point
([ADR 0076](0076-compiling-policy-entry.md)): namespace access, the marking
lattice, row rules ([ADR 0030](0030-row-scoped-query-access.md)), purpose,
and property projection. Indexed object-set evaluation already reads a
rebuildable projection and rechecks each member against the live object
before counting it ([ADR 0066](0066-object-set-evaluate.md)). The earlier
full-text surface was retired for 1.0 and is design history only
(`docs/research/152-hybrid-retrieval.md`).

## Decision

1. **Derived, never authority.** The search index is a rebuildable
   projection of the object store and the dataset catalog. Responses carry
   `authority: false`. The index lives in the plane's existing store for
   each community backend, so it is not a third control-plane store
   ([ADR 0080](0080-dual-community-runtime-storage.md)).
2. **Candidates are selected under the caller's compiled policy.** The
   caller's ADR 0076 policy is compiled once per query and applied inside the
   candidate query itself, the way storage-enforced list reads apply it
   (ADR 0025, [ADR 0030](0030-row-scoped-query-access.md)): namespace and
   kind, ACL, row rules, marking classification against the caller's
   clearance, and purpose. The index stores the object attributes those
   rules read. This reuses the compiled policy; it is not a second policy
   language. An index backend that cannot apply the compiled filter cannot
   serve policy-scoped queries.
3. **Hidden properties neither match nor highlight.** The index stores text
   per object property, and the candidate query matches only properties the
   caller may see (`visible_property_names`). A match that exists only in a
   hidden property is never a candidate. A property filter or facet on an
   ungranted property fails closed, as on other query paths (ADR 0027,
   ADR 0038).
4. **Every hit is rechecked live; limits come after policy.** Each candidate
   is decided through the ADR 0076 decision point against the live object,
   and its match is then recomputed on the caller's live authorized
   projection (`project`, including value instances,
   [ADR 0049](0049-value-instance-access.md)). A candidate whose object is
   no longer readable, or whose match no longer holds on its visible live
   cells, is dropped. Highlights and facet values come from that live
   projection, never from indexed text. Paging, the plane-set
   candidate cap, counts, and facets apply only after policy selection, so
   data the caller cannot read never consumes a limit or changes a count.
   When the cap is reached, the count is reported as a lower bound. The only
   residual effect of hidden data is bounded by index lag: an object or cell
   hidden since it was indexed can be decided and dropped until the index
   catches up.
5. **Datasets: metadata only in the first cut.** Dataset name, column names,
   and the bound object are indexed; row contents are not. Dataset hits are
   authorized by the dataset access check, and a column whose classification
   the caller's clearance does not cover is not matched or returned. Dataset
   metadata search is allowed at the discover level, like `ListDatasets`;
   object search requires read.
6. **Incremental with a durable checkpoint.** The object side consumes the
   committed object-change feed per namespace from a stored cursor, like
   Action bindings ([ADR 0090](0090-object-change-action-bindings.md)). If
   the namespace object generation
   ([ADR 0104](0104-namespace-object-change-generation.md)) advanced past
   what the feed delivered, as after change-row retention, the namespace is
   rebuilt. There is no global dataset-version feed, so the dataset side
   re-reads a namespace's dataset catalog when its catalog digest changes.
7. **Rebuild is deterministic.** A namespace rebuild reads only the
   authoritative stores and produces the same index contents for the same
   inputs under the same analyzer version (`search.text/v1`).
8. **Lag is visible.** The plane exports the maximum index lag as a gauge on
   `/metrics` and returns per-namespace lag in the search status response,
   like `ObjectTypeIndexStatus.lag_ms`.
9. **A trait with an embedded default per backend.** `SearchIndex` covers
   indexing, deletion, candidate queries, namespace rebuild, and status. It
   is a trait, not an engine enum, because an external or vector backend is
   expected. The embedded default is SQLite FTS5 on the SQLite backend and
   PostgreSQL full-text search on the PostgreSQL backend. Ranking may differ
   between backends; the hits for the same query and policy may not.
10. **Experimental surface.** Search ships as experimental RPCs
    ([ADR 0071](0071-rpc-maturity.md)). Capability discovery is not a grant
    (ADR 0019).
11. **Vector search later.** Candidate queries take a query mode; only text
    exists now. A vector mode waits for vector property types in the object
    store library and plugs in behind the same trait and the same per-hit
    decision.

## Alternatives considered

- Reinstate the retired text search surface. Rejected because a new surface
  can start from this policy contract instead of retrofitting one.
- Filter in the index with per-principal or per-policy access tokens.
  Rejected because markings, row rules, and purpose are not static tokens;
  encoding them would be a second policy language, which ADR 0076 rules out,
  and every policy change would need a reindex.
- Select candidates by text only and filter afterwards. Rejected because a
  cap or page applied before policy lets hidden matches crowd out visible
  hits and change counts.
- Exact counts by deciding every policy-selected candidate. Rejected because
  the cost is unbounded; a capped lower bound over policy-selected data does
  not depend on hidden data.
- An external search service as the default. Rejected because the community
  runtime must work on its own stores; an external backend can be added
  behind the trait.
- Index dataset row contents now. Rejected for the first cut because row
  rules and column markings would have to be decided per row and column at
  query time; metadata search covers discovery.

## Consequences

- The index carries the policy-relevant object attributes and must be
  updated when they change; index lag bounds how long a stale attribute can
  matter, and the live recheck keeps it from exposing anything.
- Search latency includes one policy decision per decided candidate; the
  candidate cap bounds it.
- Both community backends gain derived search tables, a per-namespace
  checkpoint, and rebuild support. Losing or dropping them loses no facts.
- Ranking parity across backends is not a contract; hit membership is.
- #1406 is delivered in slices: the index and its feed, PostgreSQL parity,
  and the search RPC.

## Validation

- A caller without a marking, property grant, row access, or namespace
  access gets no hit, count, facet value, or highlight from that data.
- Many hidden matches do not displace a visible hit or turn an empty result
  into a lower-bound count.
- A cell indexed while visible that has since become hidden, on an object
  that stays readable, no longer produces a hit, count, or highlight.
- A match only in a hidden property is not a hit for that caller.
- An object edit appears in results once the checkpoint passes it; a forced
  generation gap triggers a rebuild.
- A namespace rebuild yields identical results to incremental indexing.
- Both backends return the same hits for the same query and policy.
