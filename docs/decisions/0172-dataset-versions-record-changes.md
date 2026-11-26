# ADR 0172: A dataset version records a change, and its content is computed

- Status: accepted
- Date: 2026-11-26
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3475 (#3475)
- Supersedes: none
- Superseded by: none
- Related: ADR 0161

## Context

Every committed source batch writes a dataset version that copies every row
the dataset holds into `sekai_dataset_version_rows`, and its id hashes every
row. Storage grows with the square of landed records, and each batch costs
time in proportion to everything landed before it. A transform replay pinned
to a version (`input_versions`, #1794) must still read exactly the rows that
version held.

Triage on #3475 settled the model: version kinds, computed content, chained
ids, unchanged old versions, and a reader that ships one release before the
writer. This record adds the storage layout. Established data platforms with
versioned datasets use the same model.

## Decision

1. A version has one kind: `snapshot` replaces the whole content, `append`
   only adds rows and refuses to replace one, `update` adds or replaces rows,
   `delete` removes rows. A landed source batch is `append` when it adds only
   new external ids and `update` otherwise. Rollback writes a `snapshot`.
2. The content of version N is the latest `snapshot` at or before N, then
   every later change up to N, applied in order.
3. Layout: a new table holds each row once with the range of versions it is
   live in.

   ```text
   sekai_dataset_row_spans(
     dataset_id, row_id, data, partition_key,
     from_seq,          -- first version seq that holds this row
     to_seq NULL        -- first version seq that no longer holds it
   )
   ```

   The content of version N is every span of the dataset with
   `from_seq <= N` and (`to_seq` is null or `to_seq > N`). A replaced or
   deleted row closes its span (`to_seq = N`); a replacement opens a new
   span. A `snapshot` closes every open span and opens its own rows. Reads
   go through an index on `(dataset_id, from_seq)`, so a read costs the rows
   live up to N, not the length of the change chain.
4. `sekai_dataset_versions` gains `kind` and `layout`. `layout = 'copy'` (the
   default, and every version written before this change) reads from
   `sekai_dataset_version_rows` by version id, unchanged, as a `snapshot`.
   `layout = 'span'` reads from the span table. Existing ids and rows are
   not rewritten.
5. The first span version of a dataset after the upgrade opens spans for the
   rows of its latest `copy` version, once, so later changes have a base.
6. A new version id hashes the dataset id, seq, time, kind, the previous
   version id, and a digest of the changed rows only.
7. Retention stays opt-in. A purged span version reads as empty. Purging
   deletes only closed spans that no retained span version covers; open
   spans stay. Redaction and erasure rewrite a span's `data` once; every
   version that covers it sees the result.
8. Every reader of a version's rows (replay pins, export, branch, health,
   rollback, retention, redaction, erasure, ad hoc transforms) goes through
   one content function per backend that dispatches on `layout`.
9. Rollout takes two releases. Release N adds the columns, the span table,
   and the reader, and still writes `copy` versions. Release N+1 writes
   `span` versions. An N process in a rolling deploy reads N+1 versions
   correctly; an older process does not, which is why the reader ships
   first.

## Alternatives considered

- Versions reference a shared row set (one row table, a version-to-row
  membership table). Membership still grows with every version's full row
  count, so storage stays quadratic for append-heavy datasets.
- Walk the change chain from the latest snapshot on each read. Simple to
  write, but a read costs the chain length, which triage ruled out.
- Periodic compaction snapshots. Bounds the chain but keeps copies; spans
  need no compaction for append and update workloads.

## Consequences

- Append-only landing stores each row once and costs in proportion to the
  batch. Update-heavy datasets keep closed spans until retention purges
  them; reads skip them by range but still scan them in the index range.
- Two layouts coexist until every `copy` version is purged; nothing forces
  a rewrite.
- SQLite and PostgreSQL get the same table, columns, and content function.

## Validation

- A replay pinned through `input_versions` reads the same rows for `copy`
  and `span` versions, before and after the upgrade, on both backends.
- Rollback, retention, redaction and erasure keep every retained version's
  content correct when spans are shared.
- An `append` that would replace a row is refused.
- Release N reads `span` versions that a test writes in the N+1 shape.
- The 500-record batch loop on the object-path harness stays flat from
  5,000 to 50,000 landed records (release N+1).
