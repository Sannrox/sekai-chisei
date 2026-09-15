# Research: object-index envelope at 10⁷

Issue: [#876](https://github.com/Sannrox/sekai-chisei/issues/876)
Follow-up: [#877](https://github.com/Sannrox/sekai-chisei/issues/877),
[#878](https://github.com/Sannrox/sekai-chisei/issues/878),
[#889](https://github.com/Sannrox/sekai-chisei/issues/889)
Date: 2026-09-15
Status: **envelope published**
Decision: [ADR 0073](../decisions/0073-source-and-action-objects.md)

This note records the throwaway measurement #876 required. It is not an
indexer, not a storage-engine pick, and not object authority. Source tables
stand in for registered datasources and Action deltas. Index tables are a
rebuildable projection.

## Hardware profile

| Field | Value |
| --- | --- |
| CPU | Apple M2 Pro |
| RAM | 32 GiB |
| Logical CPUs | 10 |
| OS | Darwin 25.5.0 arm64 |
| Engine under test | bundled SQLite via `rusqlite` 0.40, WAL, `synchronous=OFF` |
| Durability | measurement-only; not a production durability claim |

## Fixture

`EnvelopeScale::from_objects(10_000_000)`:

| Kind | Rows | Hidden (1/100) |
| --- | ---: | ---: |
| customer | 100_000 | 1_000 |
| order | 1_000_000 | 10_000 |
| shipment | 8_900_000 | 89_000 |
| **total** | **10_000_000** | 100_000 |

Two-hop shape: Customer → Order → Shipment. Hidden rows stay in source and
projection and must not affect visible counts or sums.

Harness: `cargo run --release --example object_index_envelope -- --objects 10000000`.
Invariants at small scale: `sekai::object_index_envelope` unit tests.

## Targets from #876

| Metric | Target | Measured | Result |
| --- | --- | ---: | --- |
| Objects | 10⁷ | 10_000_000 | hold |
| Initial materialize | (record) | 4_942 ms | hold |
| 1_000-key incremental | ≤ 60 s | 1 ms | hold |
| p95 filter | part of ≤ 300 ms with aggregate | 3 ms | hold |
| p95 aggregate | part of ≤ 300 ms with filter | 32 ms | hold |
| p95 two-hop | ≤ 500 ms | 2_140 ms | **miss** |
| Rebuild after deleting the projection | restore visible membership | 4_925 ms, `source_matches_projection=true` | hold |

Captured run: 2026-09-15T, same machine as the profile above.

### 10⁸ follow-up (same profile, same harness)

| Metric | 10⁷ | 10⁸ |
| --- | ---: | ---: |
| Initial materialize | 4_942 ms | 92_401 ms |
| 1_000-key incremental | 1 ms | 2 ms |
| p95 filter | 3 ms | 33 ms |
| p95 aggregate | 32 ms | 357 ms |
| p95 two-hop | 2_140 ms | 35_356 ms |
| Rebuild | 4_925 ms | 216_205 ms |

Membership incremental still holds. Two-hop and aggregate miss the 10⁷
envelope at 10⁸ on the on-the-fly SQL plan. The hop-projection candidate
is recorded in [889-hop-projection-envelope.md](889-hop-projection-envelope.md).

## Meaning of the miss

Filter + aggregate at 10⁷ is inside 300 ms. Incremental membership update is
inside 60 s. Deleting the projection and rematerializing from source restores
visible counts and sums; hidden shipments (89_000) stay out of the visible
aggregate (8_811_000).

Two-hop grouped traversal on this star schema missed 500 ms (2.14 s p95). That
is a **query-plan** miss, not a membership-index miss. It is the kill signal
#876 named for pulling [#889](https://github.com/Sannrox/sekai-chisei/issues/889)
forward *if* a later product index still misses two-hop. It is not a license
to pick an external engine in this note.

## Consequences for open Issues

- **#877** (datasource-backed incremental membership index) is unblocked as a
  **projection**: register a dataset, materialize members, re-index changed
  keys, fail closed on hidden rows, rebuild from source and Action deltas.
  Two-hop SLA is a non-goal of that Issue.
- **#878** landed without claiming the 500 ms two-hop SLA.
- **#889** is unblocked by the hop-projection envelope in
  [889-hop-projection-envelope.md](889-hop-projection-envelope.md). Product
  nested-loop misses at 10⁵; a rebuildable hop-projection query holds at 10⁷.
- **#870** is unblocked by the embedded-PostgreSQL envelope in
  [870-embedded-postgres-envelope.md](870-embedded-postgres-envelope.md). This
  SQLite fixture is still not the runtime storage decision.

## Alternatives rejected here

- Treat this SQLite star schema as the product indexer. Rejected: ADR 0073
  forbids picking an indexer in the meaning rule.
- Implement #877 against graph rows “for now.” Rejected: that freezes the
  wrong store into descriptors and security tests.
- Pick an external index engine because two-hop missed. Rejected: membership
  and incremental held; two-hop is #878/#889 after #877 exists.
