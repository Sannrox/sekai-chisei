# Research: two-hop hop-projection envelope for #889

Issue: [#889](https://github.com/Sannrox/sekai-chisei/issues/889)
Predecessor: [#876](876-object-index-envelope.md), [#877](https://github.com/Sannrox/sekai-chisei/issues/877),
[#878](https://github.com/Sannrox/sekai-chisei/issues/878)
Date: 2026-09-15
Status: **envelope published**
Hardware: Apple M2 Pro, 32 GiB, Darwin 25.5.0 arm64 (same profile as #876)

This note re-measures two-hop on the #877 product membership projection and
compares throwaway query plans on the #876 fixture. It is not a shipped
indexer and does not pick a vendor engine.

## Product projection (#877 / #878)

`EvaluateObjectSet` multi-hop nested-loops visible membership rows in process
(`src/grpc/object_set_query.rs`). At `EnvelopeScale::from_objects(100_000)`
through `SekaiDb` datasets + `apply_object_type_index`:

| Plan | p95 | Count | vs 500 ms |
| --- | ---: | ---: | --- |
| Distinct-customer nested-loop (#876 metric) | 963 ms | 990 | **miss** |
| Product all-paths nested-loop (every matching shipment) | 64_902 ms | 88_110 | **miss** |
| In-process hash-join (distinct customers) | 18 ms | 990 | hold |

Index load 61 ms. Hidden rows (1/100) stay out of counts. The product
evaluator clones every matching path before aggregating; that work already
misses at 10⁵. 10⁷ nested-loop is not runnable
(O(|customers|·|orders|) then O(|paths|·|shipments|)).

Harness: `cargo run --release --example object_type_index_hop_envelope -- --objects 100000`.

## #876 fixture at 10⁷ (throwaway membership tables)

`cargo run --release --example object_index_envelope -- --objects 10000000 --plan compare`

| Plan | p95 two-hop | Count | vs 500 ms |
| --- | ---: | ---: | --- |
| On-the-fly SQL join (published #876 plan) | 2_545 ms | 99_000 | **miss** |
| In-process hash-join | 4_408 ms | 99_000 | **miss** |
| Rebuildable hop projection **query** | 0 ms | 99_000 | **hold** |
| Hop projection **build** (index time) | 2_167 ms | — | not a query SLA |

Counts match across plans. Hidden customers stay out of the 99_000.

### 10⁸ follow-up (same profile, same compare plan)

| Plan | p95 two-hop | Count | vs 500 ms |
| --- | ---: | ---: | --- |
| On-the-fly SQL join | 37_207 ms | 990_000 | **miss** |
| In-process hash-join | 65_023 ms | 990_000 | **miss** |
| Hop projection **query** | 0 ms | 990_000 | **hold** |
| Hop projection **build** | 36_934 ms | — | not a query SLA |

The hop projection is `idx_two_hop(id)` filled with `GROUP BY` customer ids
that have a visible Customer → Order → Shipment path. Query is
`SELECT COUNT(*) FROM idx_two_hop`. Build pays the join once at materialize
time, the same rebuildable-projection rule as #877 membership.

## Meaning

On-the-fly joins miss 500 ms at 10⁷, matching #876. The product nested-loop
misses earlier. A **rebuildable two-hop reachability projection** holds the
query SLA on this fixture without naming an external search or columnar
engine. Incremental membership (#877) is unchanged; hop output is another
projection, not object authority.

## Consequences

- **#889** ships `SEKAI_OBJECT_INDEX_ENGINE=hop-projection` as this in-process
  join-key projection, with nested-loop remaining the default. Do not adopt a
  vendor engine from this note.
- On-the-fly SQL and hash-join remain measurement baselines, not product
  query plans.
- 10⁸ hop-projection **query** holds; 10⁸ on-the-fly joins still miss.

## Alternatives rejected here

- Ship nested-loop hops as the 10⁷ plan. Rejected: miss at 10⁵.
- Pick an external full-text or columnar engine because SQL join missed.
  Rejected: a plane-owned hop projection holds the query SLA first.
- Treat `idx_two_hop` as object authority. Rejected: ADR 0073, rebuildable
  projection only.
