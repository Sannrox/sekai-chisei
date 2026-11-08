# Binding Ezu from outside the plane

Sekai has no Ezu code (ADR 0147). An Ezu adapter is an ordinary client of
the plane: it calls generic RPCs as a service principal and holds the Ezu URL
and bearer itself. Build it under `adapters/` when a deployment first needs
it ([#2182](https://github.com/Sannrox/sekai-chisei/issues/2182)).

There are two directions. Each is one loop.

## Geo feed: objects to Ezu

Object geometry flows out to Ezu.

1. Hold `AcquireLease(namespace, "ezu-geo-feed/<feed>", owner, ttl_ms)`.
   Renew it while running. After a crash, another instance calls
   `TakeoverExpiredLease`. One runner reads the subscription at a time.
2. Call `ReadObjectChangeSubscription` for the namespace and object kind,
   with an empty `snapshot_revision`. The outcome is `resnapshot_required`.
3. Snapshot: page through `ListObjects` and upsert each object's geometry to
   Ezu. Large snapshots use Ezu's bulk ingest. This replaces the old
   backfill.
4. Stream: read again with the pinned revision. Events name the object, not
   its values. For a create or update, `GetObject` and upsert its geometry.
   For a delete, expire the entity. Use the event `offset` as Ezu's
   timestamp, so a replayed or stale write loses.
5. Acknowledge the page by passing its `page_digest` as `last_page_digest`
   on the next read. The plane owns the cursor. A crash before the
   acknowledgement replays the same page, and the Ezu writes are idempotent.
6. `resnapshot_required` at any time (retention gap, authorization change)
   means: go back to step 3.

An `invalidate` event means the principal can no longer see the object.
Expire the entity.

## Fence events: Ezu to Actions

Geofence events flow in and become governed Actions.

1. Hold a lease as above, on `ezu-fence/<binding>`.
2. Read Ezu events after the adapter's cursor `(lsn, index)`.
3. For each bound event, call `SubmitActionInstance` with the pinned type
   and version, parameters mapped from the event, and
   `idempotency_key = "ezu:<lsn>:<index>"`. Admission, approval, markings
   and budget apply as for any submit. `require_approval` parks.
4. After the page, store the cursor in a Sekai object owned by the
   adapter's principal. A crash before that write replays the page. The
   idempotency key turns each replayed submit into the original instance.

The cursor lives in the plane, so any instance can take over. Nothing in the
adapter's local disk is authoritative.

## Configuration

### Plane, once per namespace

A namespace administrator sets up:

1. **Service principal.** `PutServicePrincipal` with `namespaces` set to
   the namespace and, for fence events, `action_types` set to the bound
   Action type. `IssueServicePrincipalToken` gives the adapter its bearer.
   The principal reads objects as it is allowed to. A geometry property
   above its classification ceiling is never sent to Ezu.
2. **Action type** (fence events only).
   `sekaictl admin governance action type put --file <type.json>`
   defines the type the events submit, with a closed parameter schema. Pin
   its version in the adapter configuration.
3. **Leases.** `AcquireLease` and `TakeoverExpiredLease` are experimental.
   The plane runs with `SEKAI_EXPERIMENTAL_RPCS=1`. Subscriptions, object
   reads and Action submits are stable.

No Ezu setting goes into the plane.

### Adapter

| Variable | Meaning |
| --- | --- |
| `SEKAI_TARGET` | Plane address |
| `SEKAI_CREDENTIAL` | The service principal token |
| `EZU_URL` | Ezu HTTP address. Bulk ingest uses the same address |
| `EZU_TOKEN` | Ezu bearer. It decides the Ezu namespace |
| `EZU_ADAPTER_CONFIG` | Path to the feed and binding document |

The document replaces the old `sekai.ezu-geo-feed/v1` and
`sekai.fence-binding/v1` bodies:

- **Feed:** namespace, object kind, geometry property, Ezu collection,
  optional filter fields.
- **Binding:** namespace, fences, event kinds, Ezu collection and object
  kind, Action type and version, and the mapping from event fields to
  parameters.

Changing the document needs no plane change. A changed feed scope starts a
new subscription, and therefore a new snapshot.

## Tests

The tests run against an in-memory runtime and a fake Ezu:

- crash mid-page, then rerun: no duplicate submits or stale writes;
- lease expiry, then takeover by a second instance;
- `resnapshot_required`: the adapter converges to the requeried scope.
