# ADR 0147: Spatial engine integration runs outside the plane

- Status: accepted
- Date: 2026-11-08
- Owners: @Sannrox
- Discussion: none
- Supersedes: [ADR 0121](0121-fence-event-bindings.md),
  [ADR 0132](0132-ezu-geo-feed.md),
  [ADR 0133](0133-ezu-geo-feed-backfill.md)
- Superseded by: none
- Related: [ADR 0090](0090-object-change-action-bindings.md),
  [ADR 0095](0095-feedback-evidence-finding-package.md)

## Context

ADRs 0121, 0132 and 0133 put Ezu fence bindings, the geo feed and its
GeoArrow backfill inside Sekai: five experimental RPCs, three tables, an
Ezu URL and bearer in plane configuration, and Arrow Flight in the plane
build. No deployment runs them. The plane already has the generic paths an
adapter needs: object-change subscriptions (snapshot, then stream, with
exact replay), leases, and idempotent `SubmitActionInstance`.

## Decision

Sekai carries no code, configuration or state for one spatial engine.
`PutFenceBinding`, `RunFenceBinding`, `PutEzuGeoFeed`, `RunEzuGeoFeed` and
`BackfillEzuGeoFeed` are removed. `SEKAI_EZU_URL` and `EZU_TOKEN` are
ignored. PostgreSQL migration `0145_drop_ezu_state` and SQLite open drop
`sekai_fence_bindings`, `sekai_fence_binding_receipts` and
`sekai_ezu_geo_feeds`.

When a deployment first needs Ezu, an adapter outside the plane does the
work over the generic RPCs:

- the geo feed reads an object-change subscription and writes to Ezu,
  keeping its own cursor;
- fence events become `SubmitActionInstance` calls keyed by the Ezu event
  id, so a retry never submits twice.

[ezu-adapter.md](../ezu-adapter.md) describes both loops.

## Alternatives considered

- Keep the in-plane code until an adapter exists. It keeps paying build,
  review and migration cost for a feature nobody runs.
- Move the code to `adapters/` now. It would be written against no real
  deployment; build it when one exists.

## Consequences

- The plane build loses Arrow Flight and its dependency tree.
- Clients that called the five RPCs get `Unimplemented`. They were
  experimental with no known consumer.
- Stored bindings and feeds are dropped, not migrated. An adapter rebuilds
  its state from a fresh subscription snapshot.
- During a rolling deploy an old replica's Ezu RPCs fail once the tables
  are gone; no other surface changes.

## Validation

`rg -i 'ezu|fence_binding|geo_feed'` outside ADR history, CHANGELOG and the
migration ledger finds nothing. Fresh and upgraded databases open with the
tables absent.
