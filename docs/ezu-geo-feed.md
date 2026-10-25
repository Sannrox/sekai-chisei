# Fenced Ezu geo feed

Issue: [#1797](https://github.com/Sannrox/sekai-chisei/issues/1797).
Decision: [ADR 0132](decisions/0132-ezu-geo-feed.md).

`sekai.ezu-geo-feed/v1` projects committed object geo changes into Ezu.
`PutEzuGeoFeed` and `RunEzuGeoFeed` are experimental; enable
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` build feature.

A feed is namespace-scoped and names the object kind, geo property, Ezu
collection, optional filter fields, and the `run_as` service principal whose
Ezu token authenticates writes. One Chisei tenant and namespace maps to one
Ezu namespace through that scoped token. The plane never names an Ezu
namespace, and a run never writes across namespaces.

A run reads the committed object-change stream after a durable cursor, upserts
or expires one Ezu entity per object, and only then moves the cursor while it
holds the run lease. `write_fence` plus the object's last mutation seq in
the page is `ts_ms`; Ezu ignores a stale write, including a delayed write
from a replaced feed. A failed run raises the fence before release so a
delayed HTTP write cannot overwrite the retry. A second instance cannot
take a held lease or advance the cursor. Missing geo, a gone object, or a marking `run_as` cannot
read expires the entity at that seq. Rejected geometry is counted and skipped;
the cursor still advances. A transport error fails the run without moving it.
A run rechecks that `run_as` still has namespace write.

Marked properties (`access_marking`, `_`-prefixed, schema
`internal`/`sensitive`) are never copied as filter fields.

`SEKAI_EZU_URL` is the Ezu HTTP address. Community `EZU_TOKEN` is the bearer;
enterprise resolves provider `ezu` per `run_as` tenant. Lag, errors, and
rejected geometries are `sekai_ezu_geo_feed_lag_ms`,
`sekai_ezu_geo_feed_errors`, and `sekai_ezu_geo_feed_rejected_geometries`.

Backfill is a later slice. Device position ingest and geo queries inside
Chisei are out of scope.
