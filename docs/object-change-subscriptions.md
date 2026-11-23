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
without field names. A `create` is delivered only for an object the caller can
read. Property filters pass the same restricted-property and property-grant
query checks as a listing filter.

A page names only objects the caller can read, or deleted objects whose history
the caller may read under the `ListObjectChanges` rule: in a namespace with
object security activated, and for tenant callers, deleted history fails
closed; otherwise the object ACL decides. A change to any other object returns
`resnapshot_required` and names no object. Take a new snapshot at the returned
revision and read again with the same subscription id. The restart says only
that something in scope changed. Revoke with `revoke=true` to end delivery.

## Backpressure

A page is bounded. A consumer that falls more than the documented backlog
behind committed mutations is disconnected with `disconnect_reason =
slow_consumer`.

## Action bindings

A namespace administrator can bind a subscription scope to one governed
Action type with `PutActionBinding` (experimental, gated by
`SEKAI_EXPERIMENTAL_RPCS=1`). `RunActionBinding` reads
the binding's own subscription as its `run_as` service principal and submits
one Action per bound event, checked through normal admission. Properties are
read as that principal sees them, so hidden fields never become parameters.
A rerun admits nothing new, and `require_approval` parks. See
[ADR 0090](decisions/0090-object-change-action-bindings.md).

A binding can fire on a fixed interval instead (#3033): it carries
`"schedule": {"every_ms": N}` with N from 60000 (one minute) to 604800000
(seven days), names no `kind`, `ops` or `property_filters`, and maps every
parameter from a constant. The plane's schedule tick submits it, never
`RunActionBinding`, which refuses it with `FAILED_PRECONDITION`. Each binding's
buckets are phased by its namespace and id. Every tick submits the current
bucket as `run_as` through normal admission, with an idempotency key from the
namespace, binding id, revision, and bucket start. That key is the only fence: planes
ticking the same bucket, and a tick rerun after a crash, replay one instance,
and nothing is recorded after the submit. Buckets missed while no plane ran
collapse into the current one. A refusal (grants, write freeze, policy) is
logged and retried on the next tick, so it never fails the other bindings; a
reinstall bumps the revision, so it can submit once more in the current
bucket. Planes from before #3033 never tick a binding, and their
`RunActionBinding` fails on a scheduled one (its empty `kind` is invalid)
without submitting.

A binding can fire on dataset commits instead (#3034): it carries
`"dataset_commit": {"dataset_id": "<id>"}`, or `{}` for every dataset bound to
an object in the binding's namespace. It names no `kind`, `ops` or
`property_filters`, and maps each parameter from a constant,
`{"source": "dataset_id"}` or `{"source": "version_id"}`; `schedule` and
`dataset_commit` exclude each other. Every new dataset version fires it: an
append, a rollback, or a branch merge. Branch working copies write no
version and do not fire; purged versions are skipped. `RunActionBinding`
drives it. The first run records each scoped dataset's latest version and
submits nothing (no backfill); a dataset created later starts from its first
version. Each later run submits one Action per new version, in commit order
and up to `limit`, as `run_as` through normal admission, with an idempotency
key from the namespace, binding id, revision, dataset id and version id. The
submission reports `op` `dataset_commit`, the binding object as `object_id`,
and the `dataset_id` and `version_id`. A dataset's cursor
(`sekai_action_binding_dataset_cursors`) moves only after its versions were
admitted, so a rerun after a crash in between replays the same instances. A
dataset `run_as` cannot read (object ACL, marking, or a source-owned dataset)
is never submitted or named, and its cursor moves past what it hid. A
reinstall bumps the revision and re-pins. Planes from before #3034 refuse a
dataset-commit binding (its empty `kind` is invalid) without submitting.

## Backends

SQLite and PostgreSQL read the same `sekai_object_changes` log and the same
subscription store. Isolated PostgreSQL proof uses
`SEKAI_TEST_POSTGRES_URL`.

See [ADR 0068](decisions/0068-object-change-subscriptions.md) and
Discussion [864](https://github.com/Sannrox/sekai-chisei/discussions/864).
