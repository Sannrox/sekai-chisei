# ADR 0133: GeoArrow backfill for the Ezu geo feed

- Status: accepted
- Date: 2026-10-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1798 (#1798)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0132](0132-ezu-geo-feed.md), #1565

## Context

The incremental feed (ADR 0132) only follows the committed object-change
stream. A new or rebuilt Ezu namespace needs the objects that already exist.
Ezu accepts bulk upserts as GeoArrow over Arrow Flight.

## Decision

- **RPC.** `BackfillEzuGeoFeed` is experimental, namespace-scoped, and uses
  the same install, `run_as` token, run lease, and write fence as
  `RunEzuGeoFeed`. A second instance cannot take a held lease. A reinstall
  clears an in-flight backfill page.
- **Watermark.** The first page of a rebuild captures the namespace change
  watermark and keeps it. Later pages of that rebuild do not recapture it.
  PostgreSQL takes `SHARE ROW EXCLUSIVE` on `sekai_object_changes` before
  `MAX(audit_seq)` so in-flight identity values commit first and the
  captured value is a committed prefix; SQLite takes an immediate write
  lock on the same file. Each backfill write uses `write_fence` plus that
  watermark as `ts_ms`, so a delayed Flight put is stale against an
  incremental mutation after the watermark.
- **Page.** A run lists live objects of the bound kind after the last id it
  put, at most the feed's backfill cap (default 1000, or the named
  `max_changes_per_run`). It copies the same filter fields as the
  incremental path and never copies a marked property. Missing geo is
  skipped. Rejected geometry is counted and skipped. A Flight refusal or
  transport error fails the run without advancing the page or the cursor,
  then raises `write_fence`.
- **Handoff.** A short last page sets the incremental cursor to the captured
  watermark, forward only, and clears the backfill page. Changes after that
  watermark are not in the snapshot; `RunEzuGeoFeed` applies them. The
  snapshot is live objects with geo; pre-watermark removals are not expired.
  A new or rebuilt Ezu has none. The backfill can be re-run after Ezu
  snapshot loss to put live objects again.
- **Ezu.** Writes go to Arrow Flight `DoPut` at `SEKAI_EZU_URL` with the
  `run_as` bearer. The batch schema is Ezu's GeoArrow WKB schema (spec 0.2,
  CRS `OGC:CRS84`). The plane never names an Ezu namespace.

## Alternatives considered

- Replay the change stream from seq 0: a delete has no live row to skip, but
  a million-object namespace would walk every historical mutation.
- Capture the watermark after the last page: an object created after its
  listing slot and before that capture is in neither the snapshot nor the
  incremental window.

## Consequences

A scheduler can call `BackfillEzuGeoFeed` until `more` is false, then
`RunEzuGeoFeed`. Device position ingest and geo queries inside Chisei stay
out.

## Validation

A backfill of live objects followed by edits, then incremental, matches a
clean rebuild of the same live set. A change after watermark capture and
before complete is visible to incremental. A held incremental lease refuses
backfill.
