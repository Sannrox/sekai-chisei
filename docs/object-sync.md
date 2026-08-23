# Inbound object sync

Inbound object sync admits bounded source batches and advances a plane-owned
checkpoint only when every object, audit, lineage, result, and checkpoint write
commits. The first and only source profile is GitHub Issue/PullRequest under
`source_control.object_sync`. See
[ADR 0022](decisions/0022-source-batch-transactions.md) and
[ADR 0021](decisions/0021-defer-second-object-sync-source.md).

## Adapter workflow

An out-of-process adapter follows this loop:

1. Call `GetSourceSyncState` for `namespace`, GitHub `owner/repository`, and the
   exact type-revision digest.
2. Normalize at most 500 Issue/PullRequest records and build
   `sekai.source-batch/v1`.
3. Persist that exact batch to the local source-adapter outbox before sending.
4. Call `ApplySourceBatch` as one authenticated principal with namespace write
   authority.
5. Remove the outbox entry only when the response commits the same idempotency
   key, batch digest, and proposed cursor.

The offline helper and reference normalizer live under
[`adapters/`](../adapters/README.md). They contain no source credentials and
perform no GitHub network requests.

## Batch contract

A batch binds one namespace, authenticated producer, source instance, adapter
version, and type revision. `current_cursor` must be empty for the first batch
and must exactly equal the last committed cursor thereafter. The adapter may
propose `proposed_next_cursor`; only the control plane persists it.

Version 1 admits exactly one code-owned type revision:

- contract: `sekai.source-type-revision/v1`;
- family: `source_control.object_sync`;
- source: `github`;
- ordered record types: `Issue`, `PullRequest`;
- digest:
  `sha256:97a329c80d00af0525c6076aef9f8162471eee9c108cefae42f68a8309fb708a`.

The digest is SHA-256 of
`sekai.source-type-revision/v1\nsource_control.object_sync\ngithub\nIssue\nPullRequest\n`.
Any other digest fails as `unbound_type_revision` before source binding or
mutation. A configurable or additional revision requires a separate design
decision and authoritative registration lifecycle; v1 does not infer a
revision from caller input.

The canonical batch digest includes all replay-relevant input, including the
idempotency key and both cursors. It excludes `collected_at_ms`, so an exact
retry after restart remains the same batch. The server rejects:

- unknown contract or adapter versions;
- mixed sources, repositories, or unsupported record kinds;
- reused idempotency keys with different canonical input;
- stale or foreign cursors;
- source, producer, type-revision, type-kind, or object-id conflicts;
- reuse of one immutable source version with different payload content;
- unbounded identifiers, records, properties, cursors, or secret-like text.

Diagnostics identify the bounded error class without echoing offending
property values, cursors, credentials, or database details.

## Transaction lifecycle and recovery

The control plane first persists `OPEN`. It then applies all records in one
backend transaction and closes the batch as `COMMITTED` or `ABORTED`.

- `COMMITTED` means all graph objects, object-change audit rows, source
  identities, lineage projections, per-record results, and the checkpoint
  committed together.
- `ABORTED` means a post-open conflict was proven. No object or checkpoint
  mutation from that batch committed.
- A storage failure may leave matching durable `OPEN` evidence. Retrying the
  exact batch resumes it; a different batch cannot overtake it.
- Exact committed replay returns the stored result and does not mutate again.
- Ambiguous transport progress stays pending in the adapter outbox. Neither the
  adapter nor server manufactures `success`, `partial`, or `unknown`.
- The outbox permits only one unresolved batch for a
  namespace/source-instance/type-revision binding. Exact re-enqueue is
  idempotent; a distinct later batch waits until the prior batch resolves.

There is no operator endpoint that force-commits, edits, or discards an open
transaction. Recovery is exact replay or database repair from authoritative
evidence.

## Identity and deletion

- Source identity is `github:{owner}/{repo}#{number}`. The server requires a
  lowercase canonical two-part GitHub repository and a positive canonical
  decimal number; adapter-side validation is not trusted.
- Object id is derived from `type_digest` plus source identity.
- Issue and PullRequest share GitHub's repository number space. A pull request
  and its issue number are one identity, and a batch cannot submit both.
- A later observation may refresh properties and source version but cannot
  change type kind, type revision, source binding, or object id.
- Reusing the same immutable source version with a different payload digest,
  display name, or projected properties fails as `source_revision_conflict`;
  the object and checkpoint remain unchanged. The same version and projected
  content may be retried or refreshed, while a different source version may
  advance normally.
- Generic object update and delete paths reject source-owned projections.
  Refresh and tombstone changes must arrive through `ApplySourceBatch`.
- Delete observations tombstone the same object; they do not mint a new id.
- Additional GitHub kinds remain rejected. Check runs stay evidence
  observations.

Dataset lineage records source → dataset → object. Permit-backed write-back may
extend it through action → external mutate without inventing another object
identity. See [ADR 0020](decisions/0020-shared-type-revisions-and-object-sync.md).

## Authorization and trust boundary

`ApplySourceBatch` requires exactly one authenticated principal. The request's
producer identity must match that principal, and the principal must have write
authority for the canonical namespace. `GetSourceSyncState` requires read
authority. Enterprise tenant context, when present, must agree with the
namespace.

Adapters retain source credentials and transport behavior outside the control
plane. Evidence admission cannot mutate an object-sync identity. Outbound
source mutation remains a governed Action with a permit-backed
`external_mutate` effect.

## Persistence, retention, and rollback

SQLite and reusable PostgreSQL implement the same binding, replay, lifecycle,
identity, tombstone, and checkpoint contract. Normal CI runs SQLite
conformance. PostgreSQL conformance and concurrency tests require an isolated
TLS database through `SEKAI_TEST_POSTGRES_URL` and are ignored otherwise.
A partial unique graph index on `(namespace, external_id)` for `github:*`
identities prevents concurrent ordinary object writes from colliding with sync
projections. Existing duplicate GitHub identities must be repaired before the
object-sync migration can apply.

Object-sync migrations are additive and have no automatic down migration.
Backups must include graph, audit, source binding, transaction, identity,
result, and checkpoint tables from one database snapshot. Rolling back the
binary does not roll back a committed checkpoint. Restore the complete atomic
backup instead of deleting or editing individual sync rows.

Retain committed batch/result and identity/lineage evidence while the projected
object or downstream decisions remain retained. The current retention runner
does not independently purge object-sync tables.

## Non-goals

Webhook, snapshot, and change-feed collection remain separate transports into
this contract. This foundation adds no pipeline, transform language, plugin
runtime, connector marketplace, credential store, unrestricted write-back, or
second source.

Governed functions and computed properties do not write derived objects onto a
type revision and must not invent a sync source id. See
[derived-fact admission](research/659-derived-fact-admission.md).
