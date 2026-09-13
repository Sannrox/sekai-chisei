# Object-change subscriptions

`ReadObjectChangeSubscription` delivers committed create, update, and delete
facts for a namespace and kind. It reuses `sekai.event-subscription/v1`
identity, cursor, retention, and revocation. The producer is the control
plane. A caller-supplied page is not object authority.

## Snapshot, then stream

Call once with an empty `snapshot_revision`. The response outcome is
`resnapshot_required` and includes the revision to pin. Take an authorized
`ListObjects` snapshot, then read again with that revision. Later insert,
update, and delete pages must converge to a requery of the same scope.

A retention gap, expired cursor, authorization-pin change, or stale
revision returns `resnapshot_required`. The server does not invent catch-up
events. Exact replay of the last admitted `page_digest` returns `replayed`
and does not move the cursor.

## Non-authority

`ReadObjectChangeSubscriptionResponse.authority` is always false. Events
name object identity, op, and changed field. They do not carry source
credentials or newly hidden values. Visibility loss emits `invalidate`
without field names. Revoke with `revoke=true` to end delivery.

## Backpressure

A page is bounded. A consumer that falls more than the documented backlog
behind committed mutations is disconnected with `disconnect_reason =
slow_consumer`.

## Backends

SQLite and PostgreSQL read the same `sekai_object_changes` log and the same
subscription store. Isolated PostgreSQL proof uses
`SEKAI_TEST_POSTGRES_URL`.

See [ADR 0068](decisions/0068-object-change-subscriptions.md) and
Discussion [864](https://github.com/Sannrox/sekai-chisei/discussions/864).
