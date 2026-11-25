# ADR 0163: A source sync reports bounded notes with its outcome

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3014 (#3014)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0046](0046-bounded-source-health.md), [ADR 0148](0148-sources-and-one-connector-runtime.md), [ADR 0149](0149-one-claimable-work-queue.md)

## Context

A Source sync ends with `AckWork`: a fence, an outcome and, for a failure,
one closed failure class. Its only record is the last success, the last
failure and the runtime that finished it, kept in the Source row.

An event-stream connector type (#3014) has two things to report that are
neither success nor failure. Retention can pass a stored offset, so a range
of offsets is never read. A record can be unusable (not JSON, no id field),
and it is skipped so one bad record never stalls a partition. Both must be
visible to an operator, and neither may become a governed object or carry
record content.

## Decision

1. `AckWorkRequest` gains an optional, experimental `source_sync_notes`
   option for the `source_sync` kind, on a completed or a failed sync.
   A note is one of:
   - `offset_gap {partition, from_offset, to_offset}`: offsets from
     `from_offset` up to, not including, `to_offset` were never read;
   - `skipped_record {partition, offset, reason}`, where `reason` is
     `not_json` or `missing_id`.
2. A sync keeps at most 64 notes. Past that the runtime sends only
   `overflow_count`. Notes name positions and never record content. The
   plane refuses more than 64 notes, a negative position or count, an empty
   or reversed gap, and an unknown reason with `INVALID_ARGUMENT`.
3. The plane stores the notes with the sync outcome in the Source row
   (`sync_last_notes_json`, SQLite and PostgreSQL), stamped with the finish
   time. A retried acknowledge under the same fence keeps the first notes,
   as it keeps the first outcome.
4. `ConnectorSourceSync.last_notes` (`GetSource`, `ListSources`, the ack
   response) and `SourceHealth.sync_notes` (`GetSourceHealth`) return the
   notes of the last finished sync. Health attaches them only for a
   disclosed source and only when exactly one Source in the namespace owns
   the `source_instance`.

## Alternatives considered

- **Encode notes into the reason string.** Rejected. It is not typed, and
  the reason is a closed failure class.
- **Record notes as a batch record.** Rejected. A skip would become a
  governed object.
- **Leave gaps unrecorded.** Rejected. An operator could not tell a quiet
  topic from lost data.

## Consequences

- Gaps and skipped records are visible on the Source and its health; the
  plane stores one bounded JSON column more per Source.
- Mixed versions: a plane without the column finishes later syncs without
  clearing the notes. The stamp no longer matches that finish, so the notes
  read as none rather than as the newer sync's. An older plane refuses the
  option, so a runtime sends it only when it has notes and acknowledges
  without them when refused.
- Rollback leaves the defaulted column unread.
- The connector type that sends notes is the remaining delivery of #3014.

## Validation

- Store contract on both backends: a completed sync keeps its notes, and a
  retry with other notes changes nothing.
- A note stamped by an earlier finish reads as none.
- `AckWork` refuses a malformed note; `GetSource` and `GetSourceHealth`
  return the stored notes, and an undisclosed health report carries none.
