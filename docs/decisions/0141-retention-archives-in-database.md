# ADR 0141: Retention archives into database tables on both backends

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Discussion: none, resolved in Issue #1788
- Issue: #1788
- Supersedes: none
- Superseded by: none
- Related: [ADR 0129](0129-scheduling-ownership.md),
  [ADR 0130](0130-governed-export.md)

## Context

Retention differs by backend, and nothing runs it. SQLite follows the stored
retention policies, verifies the audit ledger, copies decisions,
attestations, object changes, LLM calls and task observations into a
separate SQLite archive file, then deletes or redacts them in the hot
database. PostgreSQL ignores the policies and archives only content events,
into in-database `sekai_archive_*` tables. `run_retention` and
`purge_old_records` fail closed on PostgreSQL, and no CLI command, admin RPC
or server task invokes any of these functions.

A node-local archive file is not backed up or replicated with the database,
so a failover or restore loses it, and two replicas would each write their
own.

## Decision

1. **Archive target.** Both backends archive into tables in the same
   database: batches, archived records and batch membership, each record
   content-hashed and keyed by its stable source identity. Moving a batch
   into the archive and deleting or redacting it in the hot tables happens in
   one transaction, so a crash never half-applies a batch and a rerun never
   applies it twice. The archive is backed up and replicated with the
   database. Offline copies of archived data use the governed export
   (ADR 0130), not a retention-specific file.
2. **Coverage.** The same policy-driven datasets on both backends:
   decisions, attestations, object changes, LLM calls, task observations and
   content events. Audit records are purged only after the audit ledger
   verifies, on either backend; a failed verification refuses the purge.
3. **Entry points.** One `RuntimeDb` retention entry point (run, dry run,
   status) serves:
   - a plane-owned retention tick under ADR 0129. Every replica may run it;
     a run is idempotent per dataset and cutoff, so no scheduler is elected
     and a run interrupted mid-way is safe to repeat;
   - `sekaictl admin retention` for status, dry run and run-now.

## Alternatives considered

- **A file on both backends.** Keeps today's SQLite shape, but the file is
  node-local, outside backups and replication, and two replicas would write
  two archives.
- **Per-backend targets behind one interface.** Hides the difference from
  callers but keeps two archive formats, two verification paths and two
  sets of operator guidance.
- **A single elected retention scheduler.** Needs leader election for work
  that is already idempotent per dataset and cutoff; ADR 0129 keeps
  scheduling in the plane without one.

## Consequences

- SQLite moves from the archive file to tables and gains content events.
  Existing archive files stay readable for verification; new runs write to
  the tables.
- PostgreSQL gains policy-driven archiving for the remaining datasets, audit
  ledger verification, and object changes, or records object changes as
  SQLite-only with a reason.
- Archived data grows the operational database; operators size storage for
  it or export and prune it through the governed export.
- `admin.retention` leaves the SQLite-only surface list once both backends
  pass the shared conformance suite.

Follow-up work is tracked under #1788: shared archive tables and the entry
point, PostgreSQL datasets, PostgreSQL ledger verification, PostgreSQL
object changes, and the tick with `sekaictl admin retention`.

## Validation

- A shared retention conformance suite runs on SQLite and PostgreSQL and
  covers every dataset above.
- A run interrupted between batches and run again archives each record
  exactly once; two concurrent runs against one database do the same.
- A tampered audit ledger makes the run refuse to purge audit records on
  both backends.
