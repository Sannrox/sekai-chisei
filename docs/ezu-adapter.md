# Binding Ezu from outside the plane

Sekai has no Ezu code (ADR 0147). The Ezu adapter is an ordinary client of
the plane: it calls generic RPCs as a service principal and holds the Ezu
address and bearer itself. It lives in `adapters/ezu.rs`
([#2182](https://github.com/Sannrox/sekai-chisei/issues/2182)).

The module talks to Ezu through the `Ezu` trait. The wire client that
implements it belongs to the deployment that runs the adapter; the tests use
an in-memory fake.

There are two loops and one read path. Each loop holds a lease and keeps its
cursor in a plane object, so any instance can take over. Nothing on the
adapter's local disk is authoritative.

## Geo feed: objects to Ezu

`GeoFeedRunner` sends object geometry to Ezu. Each `step` does one unit of
work and returns `Worked` or `Idle`.

1. Hold `ezu-geo-feed/<collection>` with `AcquireLease`, and refresh it
   every step. After a crash, another instance calls `TakeoverExpiredLease`
   once the lease has expired. A runner whose lease was taken over stops
   with `LeaseLost`.
2. Snapshot. A subscription keeps the revision it was first read at, so each
   snapshot revokes the previous subscription and reads a new one
   (`ezu-geo-feed.<collection>.<random>`) with an empty
   `snapshot_revision`. The new subscription id is stored in the cursor
   first, so a crash mid-snapshot leaves nothing the next runner cannot
   revoke. The adapter then pages through `ListObjects`, upserts each
   object's geometry, and expires every Ezu entity the listing did not
   return.
3. Stream. Read the subscription at the pinned revision. Events name the
   object, not its values. For a create or update, `GetObject` and upsert
   its geometry. For a delete or `invalidate`, or an object the adapter can
   no longer read, expire the entity.
4. Ezu orders writes by plane time: the step's lease refresh time, or the
   event's `committed_at_ms` when that is later. Each write carries the
   state the plane holds after that time. A write from a runner that lost
   its lease is older than the new holder's writes and loses in Ezu, and an
   object whose visibility comes back unchanged replaces its tombstone at
   the next observation. On a tie the later write wins. Object `updated`
   times are set by writers and the event `offset` restarts on a
   resnapshot, so neither is used.
5. `resnapshot_required` or `disconnected` means: go back to step 2.

### Cursor and recovery

The plane commits a subscription page when it delivers it. Before applying
a page, the runner stores the page's events and `page_digest` in its cursor
object, written under the lease's fencing token. It then applies the events
and clears them.

An instance that loads the cursor, after a start or a takeover, reads once
with the stored `page_digest`. The answer `replayed` proves that no later
page was delivered, and the runner applies any stored events and continues.
Any other answer means a page may have been delivered and lost, and the
runner takes a new snapshot. The cursor also records the feed settings it
was written for; a runner started with other settings takes a new snapshot,
so unchanged objects are rewritten with the new geometry and fields. A runner that has read no page since its
snapshot also takes a new snapshot on restart.

An idle read writes nothing to the plane.

## Fence events: Ezu to Actions

`FenceRunner` turns Ezu geofence events into governed Actions.

1. Hold `ezu-fence/<binding_id>` as above.
2. Read Ezu events after the cursor `(after_lsn, after_index)`.
3. For each event, `GetObject` the fence as the adapter. The event submits
   only when the fence is a plane object of the binding's namespace and
   fence kind whose `action_type` property names the bound Action type.
   Fences that Ezu holds for anything else are skipped.
4. Call `SubmitActionInstance` with the pinned type and version, parameters
   mapped from the event, and `idempotency_key = "ezu:<lsn>:<index>"`.
   Admission, approval, markings and budget apply as for any submit.
5. After the page, store the cursor under the lease's fencing token. A crash
   before that write replays the page, and the idempotency key turns each
   replayed submit into the original instance.

A fence is itself an object on a geo feed, so deleting the fence object
expires it in Ezu.

## Reads

`nearby`, `positions` and `tracks` answer for a reader with the reader's own
credential. Ezu answers which objects match; the plane decides which of them
the reader may see.

- `nearby` asks Ezu first and keeps at most 200 candidates.
- `positions` and `tracks` take at most 200 ids, and refuse more.
- The ids are filtered with `EvaluateObjectSet` and an `id in [...]` filter,
  called as the reader. Namespace, grant and marking checks apply as for
  any object read. Only ids the plane returns are answered from Ezu.
- Any plane error fails the read. Nothing is returned unfiltered.

`CheckAccess` is not the read filter. Positions streamed straight into Ezu
write nothing to the plane; a later position for the same entity wins in
Ezu by its timestamp.

## Configuration

### Plane, once per namespace

A namespace administrator sets up:

1. **Service principal.** `PutServicePrincipal` with `namespaces` set to
   the namespace and, for fence events, `action_types` set to the bound
   Action type. `IssueServicePrincipalToken` gives the adapter its bearer.
   The adapter needs Write on the namespace for its cursor objects. It
   reads objects as it is allowed to: what it cannot read is never sent to
   Ezu.
2. **Action type** (fence events only).
   `sekaictl admin governance action type put --file <type.json>`
   defines the type the events submit, with a closed parameter schema. Pin
   its version in the binding.
3. **Fence objects** carry an `action_type` property naming the type.
4. **Readers** need read access to the namespace's published definition
   revision, which `EvaluateObjectSet` checks against.

The cursor kind `ezu_adapter_state` must stay undeclared in the published
definition. A kind with a published type accepts writes only through Action
submits or source sync.

The lease, subscription, object, object-set and Action RPCs the adapter
calls are stable. `PutServicePrincipal` and `IssueServicePrincipalToken`
are still experimental and need `SEKAI_EXPERIMENTAL_RPCS=1` on the plane.

No Ezu setting goes into the plane.

### Adapter

`AdapterConfig` is a JSON document with `feeds` and `bindings`. Unknown
fields are refused.

- **Feed:** `namespace`, `kind`, `geometry_property`, Ezu `collection`, and
  optional `filter_fields` copied onto the entity.
- **Binding:** `binding_id`, `namespace`, `fence_kind`, Action `type_id`
  and `version`, and `parameters`, which maps each parameter to an event
  field (`fence`, `entity`, `collection`, `kind`, `ts_ms`).

Changing the document needs no plane change. Changed feed settings start a
new snapshot.

## Tests

`tests/ezu_adapter.rs` runs the adapter against an in-memory plane served
over gRPC and a fake Ezu:

- a crash mid-page and a takeover converge, and the runner that lost its
  lease writes nothing;
- a lost subscription answer leads to a new snapshot;
- a new snapshot restores an entity behind a newer visibility tombstone;
- changed feed settings rewrite unchanged objects;
- fence events submit once, only for bound plane fences, across a refused
  cursor write and a takeover;
- deleting a fence object removes the fence in Ezu;
- reads return only objects the reader may read, by grant and by marking,
  and an unknown reader gets nothing;
- a direct position stream writes nothing to the plane.
