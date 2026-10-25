# ADR 0132: Fenced incremental feed of object geo changes into Ezu

- Status: accepted
- Date: 2026-10-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1797 (#1797)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0121](0121-fence-event-bindings.md), #1798

## Context

Objects carry geo properties. Nothing pushed committed changes into Ezu.
Fence bindings (#1564, ADR 0121) read Ezu events into governed Actions. This
decision is the inverse write: object geometry into Ezu, under the same
tenant token and run-lease rules.

## Decision

- **Feed.** `sekai.ezu-geo-feed/v1` is namespace-scoped and names the object
  kind, geo property, Ezu collection, optional filter fields, and a `run_as`
  service principal. `PutEzuGeoFeed` is a namespace-administration act and
  requires `run_as` namespace write. A reinstall bumps the revision, keeps
  the cursor, and raises `write_fence` above the namespace change watermark
  so a delayed write from the old revision cannot overwrite the replacement.
  A lapsed-lease takeover raises the same fence so the previous holder's
  in-flight write is stale.
- **Ezu.** A run writes `POST /v1/entities` at `SEKAI_EZU_URL`, with the bearer
  resolved as provider `ezu` for `run_as`'s registered tenant (an enterprise
  resolver's credential, else the process `EZU_TOKEN`), never the caller's.
  The token decides the Ezu namespace; the plane never names one. One Chisei
  tenant and namespace map to one Ezu namespace.
- **Run.** `RunEzuGeoFeed`, triggered by namespace admins or `run_as`, rechecks
  that `run_as` still has namespace write, then takes the feed's run lease
  (one minute). A second run is refused `ABORTED`;
  a crashed run's lease lapses and the next run takes over; a failed run
  raises `write_fence` before releasing so a delayed HTTP write cannot
  overwrite the retry; a reinstall clears the lease. Then it:
  1. reads at most the feed's per-run cap of committed object changes after
     its cursor, keeping a trailing split write whole;
  2. upserts or expires one Ezu entity per object of the bound kind, using
     `write_fence` plus the object's last committed mutation seq in the page
     as `ts_ms` so Ezu ignores a stale write. Missing geo, a kind change, a
     gone object, or an object `run_as` can no longer read expires the
     entity (`ttl_ms = 1`) at that seq so a delayed remove cannot wipe a
     newer live write.
  3. copies selected small properties as filter fields and never copies a
     marked property (`access_marking`, `_`-prefixed, schema
     `internal`/`sensitive`);
  4. moves the cursor to the page's read-through seq in one write, forward
     only and only while it holds the lease of the revision that read.
- **Failure.** A transport error or Ezu refusal (quota, rate, conversion)
  fails the run before the cursor moves, raises `write_fence` by one, then
  releases the lease so a retry can start at once and a delayed apply is
  stale. A locally rejected geometry is
  counted and skipped; the cursor still advances. Missing geo expires the
  Ezu entity at the mutation seq. A write freeze or lost namespace write on
  `run_as` stops the run. Ezu has no durable tombstone; equal-seq retries
  follow Ezu's newer-or-equal-wins rule.
- **Back-pressure.** The per-run cap bounds each run (default 100, at most
  1000), and `more` tells the scheduler to run again. Lag is the age of the
  oldest change a run read, as `sekai_ezu_geo_feed_lag_ms`. Errors and
  rejected geometries are `sekai_ezu_geo_feed_errors` and
  `sekai_ezu_geo_feed_rejected_geometries`.
- **Storage and wire.** SQLite and PostgreSQL (`0117_ezu_geo_feeds`) keep
  the feed, its cursor, and the run lease. The run reads
  `list_committed_object_mutations_after`, the same committed object-change
  stream subscriptions use. Both RPCs are `experimental`.

## Alternatives considered

- Write from the live object table without the change stream: a cursor
  cannot fence two instances, and deletes have no row to project.
- Name an Ezu namespace on the request: a body could write tenant B.
- Advance the cursor before the Ezu writes: a crash would skip objects.

## Consequences

Geo in Ezu is an explicit, opt-in install. Backfill is a later slice
(#1798). Device position ingest and geo queries inside Chisei stay out.

## Validation

Create, move, and delete appear as upserts and expires. Replay of an older
revision is stale. A second instance cannot take a held lease or advance
the cursor. A marked property is never a filter field. The upsert body
never names a namespace. A revoked `run_as` cannot run.
