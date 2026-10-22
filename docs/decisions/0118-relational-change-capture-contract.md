# ADR 0118: One change-capture contract for relational sources beyond PostgreSQL

- Status: accepted
- Date: 2026-10-21
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1578
- Issue: #1578
- Supersedes: none
- Superseded by: none
- Related: [ADR 0022](0022-source-batch-transactions.md),
  [ADR 0023](0023-generation-fenced-source-change-feeds.md),
  [ADR 0046](0046-bounded-source-health.md),
  [ADR 0060](0060-additive-source-type-descriptors.md),
  [ADR 0100](0100-relational-source-family.md)

## Context

[ADR 0100](0100-relational-source-family.md) fixes identity, snapshot and
change-feed handoff, drift, quarantine, and health for a PostgreSQL-first
relational family. MySQL, SQL Server, and Oracle connectors are next. Their
log positions (GTID sets, LSNs, SCNs), transaction semantics, and schema
change events differ. Without one contract each connector would map them on
its own, and fencing and checkpoints would drift between families.

Connectors run out of process (ADR 0022). The plane owns generation, offset,
and the opaque checkpoint (ADR 0023). Nothing here changes that.

## Decision

Every relational change-capture connector maps its source onto one
source-neutral contract, checked by the change-capture conformance cases in
`sekai-source-sdk` (`assert_change_capture`,
`sekai.change-capture-conformance/v1`).

### Position

- Each source instance has one totally ordered **position**: the commit
  position of a transaction. The family fixes its syntax and comparison:

  | Family | Position | Order |
  | --- | --- | --- |
  | `postgres.lsn` | WAL LSN `X/Y` (hex) | numeric |
  | `mysql.gtid_set` | executed GTID set | set containment |
  | `sqlserver.lsn` | commit LSN `VLF:block:slot` (8, 8, 4 hex digits) | numeric by part |
  | `oracle.scn` | commit SCN (decimal) | numeric |

- Oracle can give several transactions the same commit SCN. They may share
  it, and a checkpoint at an SCN covers every transaction committed at it,
  so a connector checkpoints an SCN only after delivering all of them.
  Positions of other families never tie between transactions.
- GTID sets of one source are ordered by containment. Two sets neither of
  which contains the other are unordered, which is a conformance failure,
  never a guess. Malformed positions fail closed.
- The position is adapter-private resume state stored inside the plane-owned
  opaque checkpoint cursor, as ADR 0100 requires. It is never the plane
  offset or `source_sequence`; those stay contiguous plane integers.

### Snapshot handoff

- A snapshot records the position it is consistent at. Changes are
  delivered strictly after that position, so writes committed during the
  snapshot follow it instead of disappearing between the two paths.
- A resumed stream continues strictly after the checkpoint position, in the
  checkpoint's generation.
- The first snapshot opens generation 1. Every re-snapshot opens the next
  generation at or after the current position (it may repeat the position
  when nothing committed since), and the plane's generation fencing (ADR 0023) refuses the old
  one. A re-snapshot is the only way forward after a breaking schema change
  or retention loss.

### Records

- Only committed changes are delivered. Rolled-back work never appears.
- Each change carries the record kind, `insert`, `update`, or `delete`, the
  complete primary key in registered order (an empty string is a value; a
  NULL component fails in the connector, as ADR 0100 requires), the transaction id, the commit
  position, and the commit time. Insert carries an after image and no before
  image; update carries an after image and may carry a before image; delete
  carries no after image and may carry a before image.
- All changes of one transaction share its id and commit position, and
  transactions arrive in commit order: a later transaction's position is
  strictly after the earlier one (or equal, where the family's commit
  positions can tie), and a transaction never resumes after another began
  or after its own end marker.
- Transaction begin and end markers are optional. When present they pair
  up, do not nest, enclose only their own transaction, and the end carries
  the commit position. Markers describe source boundaries so consumers can
  apply a transaction atomically when they choose; they are not a promise
  of atomic application.
- Long transactions buffer bounded on durable storage in the connector
  until they commit. That bound is the connector's; the contract only sees
  committed transactions.

### Schema change events

Source DDL maps onto ADR 0100 drift handling by class:

| Class | Example | Handling |
| --- | --- | --- |
| additive | new optional column | commits under the current revision on the next source version |
| compatible | mapped-column type change that keeps identity | waits as `unbound_type_revision` until a new revision is registered |
| breaking | primary-key change, dropped mapped column | new revision and object-id space, reached only through a re-snapshot; the kind stops until then |

A breaking primary-key change declares the next revision's key columns;
they apply from the re-snapshot that opens that revision. A schema change is
reported between transactions, never inside one, and ends any transaction
before it. A
connector that cannot establish the historical layout of a row stops before
decoding it under the wrong schema.

### Retention loss

A source that no longer retains its log back to the checkpoint reports
retention loss. It is distinct from unavailability: the stream stops, health
projects as `blocked` (ADR 0046), and an operator decides on a re-snapshot.
The connector never restarts silently from the oldest retained position.

### Proprietary client libraries

A family whose client libraries are proprietary builds behind an optional
connector feature. The default build and its release stay free of them, and
they are never bundled.

## Alternatives considered

- **Per-family contracts.** Rejected: fencing, checkpoints, and drift would
  diverge, and each consumer would learn every family.
- **Use the source position as the plane offset.** Rejected by ADR 0023 and
  ADR 0100: positions are not contiguous integers, so gaps would be invisible.
- **Mandatory transaction markers.** Rejected: some log readers expose only
  committed rows with their transaction id; the id and shared commit
  position already bound a transaction.
- **Restart from the oldest retained log on retention loss.** Rejected: it
  silently skips changes.

## Consequences

- MySQL, SQL Server, and Oracle connectors share one checkpoint, handoff,
  and drift shape, and certify against one suite.
- `sekai-source-sdk` 1.3.0 adds the change-capture module; its source is
  part of `conformance_suite_digest()`, so certification pins move with it.
- The plane, batch contract, and health classes are unchanged.

## Validation

`cargo test -p sekai-source-sdk` runs the change-capture cases below against
the per-family fixtures. A connector certifies by running
`assert_change_capture` over what it read from a containerized source:

- every family's position parses and orders; malformed and diverged
  positions fail closed;
- a stream without a checkpoint starts with a generation-1 snapshot; changes
  follow the snapshot or checkpoint strictly; re-snapshots open the next
  generation only;
- one transaction keeps one id and commit position; markers pair, do not
  nest, and enclose only their transaction; a transaction never resumes;
- every change has a complete key and the images its operation requires;
- a breaking schema change stops its kind until a re-snapshot;
- nothing follows retention loss.
