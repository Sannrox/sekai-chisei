# ADR 0100: Bound a PostgreSQL-first relational source family

- Status: accepted
- Date: 2026-10-11
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1410
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1410 (#1410)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0021](0021-defer-second-object-sync-source.md),
  [ADR 0022](0022-source-batch-transactions.md),
  [ADR 0023](0023-generation-fenced-source-change-feeds.md),
  [ADR 0046](0046-bounded-source-health.md),
  [ADR 0060](0060-additive-source-type-descriptors.md),
  [ADR 0061](0061-quarantine-repair-preview.md)

## Context

[ADR 0021](0021-defer-second-object-sync-source.md) forbids a later object-sync
source until a bounded decision names one system of record, an identity that
cannot collide with GitHub Issue/PullRequest numbers, and refresh/tombstone
rules. [ADR 0060](0060-additive-source-type-descriptors.md) already supplies
the admission mechanism: one live registered descriptor per record kind, with
identity `{source}:{instance}#{record_kind}/{immutable_key}`. Catalog family
stays `source_control.object_sync`.

The next live system of record is a relational database. Snapshot pages can
reuse the warehouse table ingest shape, but that profile is checkpointed
snapshots only and cannot prove ordered change capture.
[Issue #1410](https://github.com/Sannrox/sekai-chisei/issues/1410) asks for the
family rules before any connector is built. This decision does not open the
control-plane PostgreSQL dest as a source, compile a connector into Chisei, or
replace GitHub as the code-owned catalog profile.

## Decision

Admit a PostgreSQL-first relational object-sync profile as registered
descriptors. Do not add a second adapter family.

### Catalog and source token

- Family remains `source_control.object_sync`. GitHub Issue/PullRequest stays
  the only code-owned catalog profile. Extra GitHub kinds stay rejected under
  `github:{owner}/{repo}#{number}`.
- The first registered source token is `postgres.table`. It names an external
  PostgreSQL system of record. It is not `SEKAI_DB_BACKEND` and not the Sekai
  or Chisei dest. The plane never opens the source database and never stores
  its credentials.
- A later engine may reuse these family rules only with its own source token
  and a proof it can meet the same key, epoch, sequence, and barrier
  guarantees. That proof is a new bounded decision.
- One descriptor admits exactly one record kind and one schema revision.
  One table is one record kind. Do not infer `record_kind` from the table
  name, a display label, or an unregistered `type_name`.

### Identity

Identity is the ADR 0060 grammar:

`postgres.table:{system}/{database}/{schema}/{table}#{record_kind}/{immutable_key}`

- `instance` is `{system}/{database}/{schema}/{table}`. `/` is the only
  hierarchy separator, which registered `source_instance` tokens already
  allow. Each of the four components uses the same canonical encoding as
  primary-key components, including encoding `/`, `#`, `:`, and `~`, so
  schema `a/b` plus table `c` cannot collide with schema `a` plus table
  `b/c`, and quoted catalog names remain registered tokens.
- `system` is an operator-registered stable identifier for one external
  PostgreSQL system of record in the namespace. It is not a hostname,
  connection string, user, or secret. Distinct systems in the namespace
  cannot share it. Tables, schemas, and databases on that system share it.
  Database name alone is not distinguishing.
- `database`, `schema`, and `table` are the relation's catalog names as the
  source stores them (case-preserving). The connector must not fold case on
  its own.
- `record_kind` is the registered object kind for that table. It is not the
  table name unless an operator registers that token.
- Object id remains `type_digest` plus that source identity. Refresh and
  tombstone keep the same object id. Rebinding the same source id across
  schema revisions is `type_identity_conflict`.

Canonical encoding for instance and key components:

1. Percent-encode each component: UTF-8 bytes that are not
   `A-Z a-z 0-9 - . _` become uppercase `%HH`. Empty or NULL components fail
   closed.
2. `instance` joins the four encoded components with `/`.
3. A single-column primary key is that one encoded component.
4. A composite primary key joins encoded components with `~` in the
   registered primary-key column order.

The resulting `instance` and `immutable_key` are registered tokens: they
contain no `#`, `:`, or control characters, and `immutable_key` contains no
`/`, so they cannot collide with GitHub's number space or split the ADR 0060
grammar. Encoding `~` inside a component keeps `a~b` (one column) distinct
from `a` plus `b` (two columns).

Tables without a primary key cannot mint object identity. Heap location,
row hashes, unique-but-not-primary indexes, and timestamps are not keys.
The first profile requires the relation primary key on snapshot rows and on
change-feed update/delete events. A source that cannot present those key
columns fails before batch construction.

Changing the primary-key column set is a new schema revision: new digest,
new object-id space.

### Snapshot and change-feed handoff

The plane owns generation, integer offset, and the opaque checkpoint
([ADR 0022](0022-source-batch-transactions.md),
[ADR 0023](0023-generation-fenced-source-change-feeds.md)). This family does
not add a delivery mode or recovery RPC.

Ordered capture uses `sekai.source-batch/v2`:

- A snapshot opens generation 1. Snapshot records have no `source_sequence`.
  The terminal committed page sets `snapshot_complete`, the source-provided
  `source_feed_epoch`, and the consistency-barrier offset from which
  change-feed delivery may resume.
- Change-feed records in that generation carry strictly increasing contiguous
  sequences. The first sequence is the committed offset plus one. The source
  log position is adapter-private resume state inside the proposed opaque
  cursor. It is not the plane-owned offset. Timestamps, pagination, polling
  by update time, and locally invented counters are not sequences.
- The control plane advances generation, offset, and checkpoint only in the
  same transaction as objects, audit, identities, lineage, and record
  results. Exact committed replay is idempotent. Overlap aborts without
  checkpoint movement. A gap marks the generation `RECOVERY_REQUIRED`.
- Only a snapshot for the next generation, referencing the last committed
  cursor, may reset ordered progress, and only after `RECOVERY_REQUIRED`.
  Old-generation batches cannot advance the new generation.
- Resume of the **same** `source_feed_epoch` from the last barrier continues
  the active generation. A **replaced** epoch (new stream identity the
  connector cannot prove contiguous with the last barrier) is
  `feed_epoch_conflict` on the current v2 machine: no mutation, no
  `RECOVERY_REQUIRED`, and no next-generation snapshot. The connector must
  fail closed rather than invent a missing range. This ADR does not fold
  epoch mismatch into recovery; a later Issue may. Until then, restore the
  prior epoch or wait for that contract change.
- Snapshot completion does not tombstone by absence. Deletes arrive as
  explicit `deleted: true` records.

A relation that cannot provide a stable epoch, contiguous sequence, and
snapshot/feed barrier stays on `sekai.source-batch/v1` checkpointed
snapshots. It must not advertise `change_feed` and must not start v2.
Periodic snapshot refresh is v1. Once a binding starts v2, a v1 batch
cannot advance it.

`source_version` is unique per change of that source identity and is never
reused with a different payload. Change-feed versions may use the assigned
sequence. Snapshot versions must not be a hash of the payload alone, or
undeclared drift cannot be distinguished from an identical refresh.

### Schema drift and quarantine

Declared drift is a new registered schema revision (ADR 0060). Until that
revision is live, its batches fail as `unbound_type_revision` without
disclosure. Additive optional properties on a **new source version** of an
already admitted revision still commit. Primary-key change, mapped-column
type change, and dropping a mapped column require a new revision.

Undeclared drift (the same immutable source version with a different
payload, display name, or projected properties) is a retained
`source_revision_conflict` quarantine. Objects and the checkpoint stay.
Exact replay returns the stored quarantine.

Inspect, preview, and re-admit stay
[source quarantine](../source-quarantine.md) /
[ADR 0061](0061-quarantine-repair-preview.md). Preview is not a permit.
Re-admission is existing `ApplySourceBatch` with a new idempotency key.
Hidden and unknown sources share one unavailable result. Inspection never
returns cursors, payloads, or secret-like text.

Restricted columns never leave the connector.

### Source health

Health remains the `sekai.source-health/v1` projection of authorized
`GetSourceSyncState` ([ADR 0046](0046-bounded-source-health.md)). Identity is
`(namespace, source_instance, type_digest)`. This family adds no health
table, no live probe of the source database, and no new class.

`RECOVERY_REQUIRED` and a retained quarantine project as `blocked`. Stale
checkpoint age projects as `delayed`. Hidden and unknown sources stay
`unavailable`. Audit records class, namespace, failure class, and outcome,
not cursors or credentials.

### Connector boundary

Connectors run out of process over the existing batch contract and
`sekai-source-sdk`. This ADR implements no connector, publication, slot, or
in-process driver. Discovery drafts ([#1408](https://github.com/Sannrox/sekai-chisei/issues/1408))
stay reviewable; they do not auto-admit a descriptor.

## Alternatives considered

- **Reuse the warehouse table ingest profile.** Rejected: that profile
  checkpoints snapshots and has no generation-fenced change feed.
- **Add a second catalog family.** Rejected by ADR 0060; family stays
  `source_control.object_sync`.
- **Compile a connector into Chisei.** Rejected by ADR 0022; credentials and
  source failures would enter the trusted process.
- **Treat source log position as the plane-owned offset.** Rejected by
  ADR 0023: log positions are not a contiguous integer sequence, so a gap
  would be indistinguishable from successful progress.
- **Hash rows or use heap location as identity when no primary key exists.**
  Rejected: those values move, collide, or encode payload into identity.
- **Infer `record_kind` from the table name.** Rejected by ADR 0060.
- **One descriptor for a whole database or publication.** Rejected: one
  descriptor admits one record kind. Extra tables stay unadmitted.

## Consequences

- Connector authors have a closed identity, handoff, drift, quarantine, and
  health contract before writing a PostgreSQL adapter.
- GitHub identity, warehouse table ingest, and registered-descriptor
  persistence are unchanged. Registered apply remains SQLite until a later
  parity Issue; this ADR does not add that parity.
- A follow-up Issue owns the out-of-process connector and the conformance
  kit cases listed below. This slice ships no runtime behavior.

## Validation

This ADR is listed in [the decisions index](README.md). Usage points from
[inbound object sync](../object-sync.md). The cases below are implementation
acceptance obligations for the family; merging this record does not run them.

### Identity

- `postgres.table` cannot be registered as `github`, and its identities do
  not match `github:{owner}/{repo}#{number}`.
- Two `system` tokens with the same database, schema, table, and key keep
  distinct source ids, object ids, and checkpoints.
- Encoded catalog names that contain `/`, `#`, or `:` remain unambiguous
  registered tokens.
- Two tables keep distinct source ids and object ids, including when the
  encoded key is the same decimal.
- `record_kind` is not inferred from a table name.
- Single-column and composite primary keys round-trip through the canonical
  encoding; component order is significant; encoded `~` does not collide
  with the join delimiter.
- A table without a primary key, a NULL key component, or a change-feed
  update/delete that omits the primary key fails before outbox publication.
- Primary-key column-set change is a new schema revision and a new object-id
  space.

### Handoff and checkpoints

- A v2 snapshot opens generation 1. The terminal page commits epoch and
  barrier with the checkpoint; adapter-local page state is not handoff
  authority.
- The first change-feed sequence is the committed offset plus one and covers
  the declared range exactly once.
- Exact committed replay returns the stored result without mutation or
  checkpoint advance.
- Overlap aborts without graph or checkpoint movement. A gap marks
  `RECOVERY_REQUIRED` without skipping or synthesizing an offset. Only that
  next-generation snapshot, referencing the last committed cursor, resumes.
  Source, type-revision, object, and lineage identity survive recovery.
- Resume of the same epoch from the last barrier continues the active
  generation. A replaced epoch is `feed_epoch_conflict` and does not open
  recovery.
- Log position, timestamp, and polling are rejected as sequences.
- A source that cannot provide epoch, sequence, and barrier uses v1
  snapshots only and never advertises `change_feed`.
- Once a binding starts v2, a v1 batch cannot advance it.
- Deletes are explicit `deleted: true` records. Snapshot completion does
  not tombstone by absence.

### Drift, quarantine, and health

- An unregistered schema revision is `unbound_type_revision` without
  disclosure. Rebinding a source id across revisions is
  `type_identity_conflict`.
- Same source version with a different payload is quarantined; objects and
  checkpoint stay; exact replay remains that quarantine.
- Inspect omits cursors, payloads, and secret-like text. Preview is not a
  permit; a stale correction cannot apply. Re-admission uses a new
  idempotency key through `ApplySourceBatch`.
- Health classes `healthy`, `delayed`, `blocked`, and `unavailable` derive
  only from authorized sync state. `RECOVERY_REQUIRED` and retained
  quarantine are `blocked`. Hidden and unknown sources are `unavailable`.
  Replay of the same durable state and observation time is identical. No
  probe, credential, or health table is consulted.

### Connector boundary

- The plane does not open the source database. Batches carry no credentials.
- Restricted columns never appear in properties, digests, display names, or
  definitions.
- A publication that lists extra tables does not admit those tables without
  a live descriptor per record kind.
