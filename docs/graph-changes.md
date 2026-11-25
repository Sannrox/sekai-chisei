# Applying graph changes

`SekaiService.ApplyGraphChanges` (experimental, #3062) writes a set of graph
changes all or none. Sekai does not decide which records change: a client
computes them and calls this RPC. The plane serves it only with
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature.

## Changes

A request names one `namespace` and up to 256 changes, applied in order:

| Change | Effect | Authorized as |
| --- | --- | --- |
| `create_object` | Creates the object. An empty namespace means the request's. | `CreateObject` |
| `patch_object` | Sets `set_properties` and removes `remove_properties`. Other properties stay. | `UpdateObject` |
| `create_link` | Creates the link. An existing link id fails the call. | `CreateLink` |
| `delete_link_id` | Deletes the link. A missing link fails the call. | `DeleteLink` |

Every object a change creates, patches or links must be in the request
namespace. An object appears in at most one create or patch, and a link in
at most one change. A link may join objects that an earlier change in the
same call creates. Namespace objects and principal profiles change only
through their own RPCs.

## Revisions

`GetObject` returns `Object.revision`, a digest of the object as returned to
that caller. A patch carries the revision the caller read as
`expected_revision`. If the object changed since that read, the call fails
with `FAILED_PRECONDITION` and a message starting `graph_change_conflict:`,
and nothing is written. The same refusal covers any concurrent write to an
object or link endpoint the call touches, and a change to the namespace's
object security policy. Of two calls patching from one read, exactly one
succeeds.

Response objects are read back through `GetObject`, so they carry new
revisions and show only what the caller may read.

## Replay

`request_id` is required. A repeat from the same caller with the same body
writes nothing and returns `replayed: true` with the objects as they are
now; objects the caller can no longer read are left out. The same id with a
different body fails with `ALREADY_EXISTS`
(`graph_change_request_conflict:`).

## Action instances

When `action_instance_id` is set, the call applies only if that instance is
`admitted`, belongs to the request namespace, and was submitted by the
caller. It applies once: the record of the call is written in the same
transaction, and a later call bound to the instance fails with
`FAILED_PRECONDITION` (`action_instance_not_applicable:`). The change audit
names the instance and its operation as the writer. A missing instance, an
instance in another namespace, and one someone else submitted give the same
refusal.

## Storage

Both backends store one row per applied call in
`sekai_graph_change_requests`, written with the changes. PostgreSQL creates
it in migration 0180; SQLite creates it on first use.
