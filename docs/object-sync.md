# Inbound object sync

Inbound object sync admits bounded source batches and advances
control-plane-owned generation, offset, and cursor state only when every
object, audit, lineage, result, and checkpoint write commits. The first and
only source profile is GitHub Issue/PullRequest under
`source_control.object_sync`. See
[ADR 0022](decisions/0022-source-batch-transactions.md) and
[ADR 0021](decisions/0021-defer-second-object-sync-source.md). The ordered-feed
design rationale is in
[ADR 0023](decisions/0023-generation-fenced-source-change-feeds.md).

## Adapter workflow

An out-of-process adapter follows this loop:

1. Call `GetSourceSyncState` for `namespace`, GitHub `owner/repository`, and the
   exact type-revision digest.
2. Normalize at most 500 Issue/PullRequest records and build
   `sekai.source-batch/v1`.
3. Persist that exact batch to the local source-adapter outbox before sending.
4. Call `ApplySourceBatch` as one authenticated principal with namespace write
   authority, or admit a signed webhook delivery that the plane maps onto the
   same batch contract.
5. Remove the outbox entry only when the response commits the same idempotency
   key, batch digest, and proposed cursor.

The offline helper and reference normalizer live under
[`adapters/`](../adapters/README.md). They contain no source credentials and
perform no GitHub network requests.

Signed push deliveries use the same identity. Pin a verifying key, then admit
the bundle. The authenticated producer must match the envelope:

```text
sekaictl admin sync pin-webhook-key \
  --namespace ops --source-instance owner/repo --key-id k1 --public-key-hex <hex>
sekaictl admin sync admit-webhook --bundle ./delivery.json --actor connector/ops
```

## Version 1 checkpointed snapshots

The reference snapshot runner pages a bounded source snapshot through the same
batch contract. It does not add a snapshot RPC or persistence schema, and the
control plane never decodes snapshot cursors:

1. Flush an exact pending outbox page before collecting anything new.
2. Stop as `pending` when delivery is unavailable or ambiguous. A later
   invocation must replay that exact persisted page.
3. Call `GetSourceSyncState` and pass only its committed opaque cursor to the
   page source. Local page counters are not resume authority.
4. Refuse new collection when the plane reports an `OPEN` transaction but the
   outbox has no exact page to replay; this is `recovery_required`.
5. Normalize a non-empty page, persist it, and apply it. Only an exact committed
   response followed by state whose checkpoint cursor and committed batch digest
   match that page permits the next page. A historical exact replay is not
   current checkpoint advancement.
6. Return `in_progress` at the configured page bound. Return `complete` only
   after the final non-empty page commits, or when a restarted source confirms
   that an already committed final cursor has no later page.

One invocation processes at most 32 pages by default, and every page remains
subject to the 500-record batch maximum. The page source may lower either
bound. A next cursor must be non-empty, different from the current cursor, and
pass the existing cursor bounds and secret-like-text checks. Invalid pages fail
before outbox publication. A cursor copied from another binding is still
foreign or stale under the plane's exact binding-local checkpoint comparison.
When one outbox contains multiple bindings, the runner flushes only the exact
pending entry for its configured binding.

The final page commits a non-empty opaque cursor just like every other page;
there is no empty completion batch. An empty source has no durable completion
representation in version 1. Snapshot completion does not imply
tombstone-by-absence: deletions must remain explicit `deleted: true` records.
Across pages, a later revision of the same source identity refreshes the same
derived object id.

## Version 2 ordered synchronization

`sekai.source-batch/v2` adds a replay-relevant `delivery` window and an optional
`source_sequence` on each record. It retains the v1 source binding, identity,
cursor, authorization, outbox, and atomic-commit rules.

A v2 adapter must use one of two delivery modes:

- `snapshot` establishes a control-plane-owned `sync_generation`. Snapshot
  records have no `source_sequence`. The terminal page sets
  `snapshot_complete`, supplies the stable `source_feed_epoch`, and carries the
  source's consistency-barrier offset. The cursor on that terminal page is
  committed with the barrier; adapter-local page state is not handoff
  authority.
- `change_feed` remains in the same generation and epoch. Its range is
  `(offset_start, offset_end]`: `offset_start` must equal the last committed
  offset, `offset_end` is inclusive, and every record has a strictly increasing
  `source_sequence` that covers every offset in the range exactly once.

Read `GetSourceSyncState` before collection and after every exact commit. Build
the next batch only from the returned cursor, generation, epoch, and committed
offset. Persist the complete normalized batch, including delivery metadata and
source sequences, before calling `ApplySourceBatch`. Do not derive progress from
timestamps, pagination positions, process-local counters, or the order in which
records happened to arrive.

The control plane owns generation transitions. Generation 1 begins with a
snapshot. After the generation enters `RECOVERY_REQUIRED`, only a snapshot for
exactly the next generation may reset ordered progress, and its
`current_cursor` must reference
the last committed cursor. The reset preserves the existing source binding,
type revision, object identity, and lineage. Batches from an older generation
cannot advance the replacement generation.

### Ordered-feed failure and recovery

- Exact replay of a committed batch returns the stored result without another
  mutation or checkpoint advance.
- A duplicate, reordered, or noncontiguous sequence inside a declared batch is
  contract-invalid and is rejected before enqueue or durable transaction
  creation. It cannot mutate generation state.
- An overlapping non-replay range durably aborts without changing graph state,
  generation progress, or the checkpoint.
- A stateful missing range, where `offset_start` is ahead of the plane-owned
  committed offset, durably aborts and marks the current generation
  `RECOVERY_REQUIRED`. Do not skip the range or synthesize a replacement
  offset.
- Ambiguous transport progress stays in the outbox. Replay the exact persisted
  batch before collecting another range.
- Once a generation is `RECOVERY_REQUIRED`, only the next-generation snapshot
  flow above can resume collection. Database repair must use authoritative
  evidence and a complete consistent backup.

A source is eligible for `change_feed` only when it provides a stable feed
epoch, a contiguous monotonic sequence, and an authoritative snapshot/feed
handoff offset. If any guarantee is absent, report the source capability as
unsupported. GitHub's public Events API is not a supported gapless feed and
must not be mapped to v2 offsets. A deployment-specific source transport may
use v2 only when it independently provides all three guarantees.

Snapshot completion still does not imply tombstone-by-absence. Every deletion
must arrive as an explicit `deleted: true` source record.

## Batch contract

A batch binds one namespace, authenticated producer, source instance, adapter
version, and type revision. `current_cursor` must be empty for the first batch
and must exactly equal the last committed cursor thereafter. The adapter may
propose `proposed_next_cursor`; only the control plane persists it.

The current object-sync profile admits exactly one code-owned type revision:

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
idempotency key and both cursors. For v2 it also includes the complete delivery
window and every source sequence. It excludes `collected_at_ms`, so an exact
retry after restart remains the same batch. The v1 canonical form is unchanged,
so previously committed v1 batches remain exactly replayable. Once a binding
has started v2 ordered synchronization, a new v1 batch cannot advance it. The
server rejects:

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
- `ABORTED` means a post-open ordered-feed conflict was proven. No object or
  checkpoint mutation from that batch committed. Exact replay of an abort
  cannot become success.
- `QUARANTINED` means the batch was schema-incompatible with the admitted
  type identity or immutable source revision. Record results, reason codes,
  and the denial outcome are stored. No object or checkpoint mutation from
  that batch committed. Exact replay returns the stored quarantine.
- A storage failure may leave matching durable `OPEN` evidence. Retrying the
  exact batch resumes it; a different batch cannot overtake it.
- Exact committed replay returns the stored result and does not mutate again.
- For v2, generation state and the committed offset advance in this same
  transaction; no audit row is treated as a substitute for offset continuity.
- Ambiguous transport progress stays pending in the adapter outbox. Neither the
  adapter nor server manufactures `success`, `partial`, or `unknown`.
- The outbox permits only one unresolved batch for a
  namespace/source-instance/type-revision binding. Exact re-enqueue is
  idempotent; a distinct later batch waits until the prior batch resolves.

There is no operator endpoint that force-commits, edits, discards, or skips an
open transaction or ordered range. Recovery is exact replay, an authorized
next-generation snapshot after `recovery_required`, or database repair from
authoritative evidence.

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
  display name, or projected properties, or changing the bound type identity,
  is quarantined as a retained denial. The object and checkpoint remain
  unchanged. Exact replay of that batch returns the stored quarantine result
  and cannot become success. Additive optional properties on a new source
  version still commit. Malformed reserved properties and invalid checkpoints
  fail closed before mutation. The same version and projected content may be
  retried; a different source version may advance normally.
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
plane. Delivery metadata is progress evidence, not authority; every state read,
batch apply, and recovery snapshot rechecks the authenticated principal and
namespace access. Evidence admission cannot mutate an object-sync identity.
Outbound source mutation remains a governed Action with a permit-backed
`external_mutate` effect.

Diagnostics use bounded reason codes and do not echo source payloads, feed
epochs, cursors, credentials, authorization metadata, database details, or
outbox contents.

## Persistence, retention, and rollback

SQLite and reusable PostgreSQL implement the same binding, replay, generation,
contiguous-range, recovery, identity, tombstone, and checkpoint contract.
Normal CI remains offline and runs both the advertised-adapter lifecycle suite
and SQLite backend conformance:

```sh
cargo test --test object_sync_adapters
cargo test --test object_sync_backend_conformance
```

The versioned lifecycle fixture covers initial projection, refresh, explicit
tombstone, reversal/reactivation, immutable-revision conflict detection, stable
source/object/type identity, canonical normalized payload digests, snapshot
source-sequence absence, and source → dataset → object lineage. The conflict
reuses the current reversal revision with divergent content so stateful backends
must fail closed against their latest source version. The fixture runs against
the one catalog-advertised GitHub Issue/PullRequest normalizer and an independent
test-only canary implementation of the same fixed profile. The canary is not
catalog-advertised and does not add a source, profile, connector, or adapter
family. Catalog coverage must exactly match the advertised profile set, and
deliberately divergent fixtures must be rejected.

The shared backend exercise verifies reactivation after tombstone with the same
object id, stable projected identity and persisted lineage binding, fail-closed
current-revision and type conflicts, and unchanged checkpoints after denial.
SQLite and the ignored PostgreSQL test invoke that same exercise. PostgreSQL
conformance and concurrency tests require an isolated TLS database through
`SEKAI_TEST_POSTGRES_URL` and are ignored otherwise:

```sh
SEKAI_TEST_POSTGRES_URL=... \
  cargo test --test object_sync_backend_conformance -- --ignored
```

A partial unique graph index on `(namespace, external_id)` for `github:*`
identities prevents concurrent ordinary object writes from colliding with sync
projections. Existing duplicate GitHub identities must be repaired before the
object-sync migration can apply.

Object-sync migrations are additive and one-way. Existing v1 transactions and
checkpoints remain readable, but a binary that cannot read v2 generation state
cannot safely continue an upgraded binding. There is no automatic down
migration.
Backups must include graph, audit, source binding, transaction, identity,
result, generation, and checkpoint tables from one database snapshot. Rolling
back the binary does not roll back a committed generation, offset, or
checkpoint. Restore the complete atomic backup from before the v2 transition
instead of deleting or editing individual sync rows.

Retain committed batch/result, generation/offset, and identity/lineage evidence
while the projected object or downstream decisions remain retained. Batch and
record-result history is the ordered-feed continuity evidence; object-change
audit may have a different retention window and is not a replacement for it.
The current retention runner does not independently purge object-sync tables.
Snapshot pages have no separate retention or rollback unit. Restore the graph,
source-sync tables, generation state, and final checkpoint from the same
database snapshot, then let the adapter resume from that restored
control-plane-owned cursor and offset.

## Non-goals

Signed webhook deliveries (`sekai.source-webhook-delivery/v1`) are a collection
transport into this contract; see
[ADR 0035](decisions/0035-source-webhook-transport.md). Pin a verifying key,
then admit the signed bundle. The plane maps it onto one source batch whose
idempotency key is the delivery id. Snapshots and ordered feeds remain the
other collection transports. Ordered synchronization adds no pipeline, transform
language, plugin runtime, connector marketplace, credential store,
tombstone-by-absence, unrestricted write-back, or second source.

Governed functions and computed properties do not write derived objects onto a
type revision and must not invent a sync source id. See
[derived-fact admission](research/659-derived-fact-admission.md).
