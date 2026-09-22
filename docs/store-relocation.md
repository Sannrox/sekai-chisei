# Two-store relocation

Historical single-file deployments keep Chisei families in the same physical
store as Sekai facts. Combined mode can already open two files
([#1005](https://github.com/Sannrox/sekai-chisei/issues/1005)). Relocation
copies Chisei-owned families into the Chisei destination, then raises a
writer fence so the old single-store process cannot become a writer again.

Do not dual-write production traffic across two stores. Relocation runs
online: the historical process may keep writing during the bulk copy, and
writers are refused only for the short fenced catch-up at the end.

## Before you start

Take a copy of the pre-relocate files. That copy is the rollback point:
relocate changes the source from the moment it starts (capture tables and
triggers), so the live source is not a clean rollback copy. Writers do not
need to be stopped first.

## Relocate

```sh
sekaictl admin store relocate \
  --source ./data/sekai.db \
  --sekai ./data/sekai.db \
  --chisei ./data/chisei.db
```

PostgreSQL uses three URLs instead of paths. `--sekai` must name the same
database as `--source` (loopback aliases compare as one host). A new empty
`--sekai` is refused so Sekai facts are not orphaned behind a fence.
`--sekai` and `--chisei` must be distinct.

```sh
sekaictl admin store relocate \
  --source postgres://user@127.0.0.1:5432/sekai \
  --sekai postgres://user@localhost:5432/sekai \
  --chisei postgres://user@127.0.0.1:5432/chisei
```

The command:

1. Initializes missing destination schema.
2. Installs write capture on every Chisei table of `--source`: a trigger
   records which tables were written (`sekai_relocate_dirty`) and checks a
   one-row gate (`sekai_relocate_capture`).
3. Snapshots the source (SQLite `VACUUM INTO`, PostgreSQL one
   `REPEATABLE READ` `COPY` pass) and copies each Chisei family (`budget`,
   `evaluation`, `portfolio`, …) from that snapshot into `--chisei` while
   writers keep running. Row counts are validated per table and fail closed
   on mismatch. Completed families are recorded in
   `chisei_relocate_families` so a crash can resume from the last completed
   family.
4. Raises the writer fence: closes the capture gate and stamps
   `sekai_store_cutover` on the source in one transaction. From then on the
   source database itself refuses every Chisei write with
   `writer fence raised`, including writes from a process that was already
   running. On PostgreSQL the gate waits for in-flight writer transactions
   to commit first.
5. Copies again only the families written since capture began (plus any
   Chisei table created during the copy), clears the dirty set, and stamps
   the Sekai and Chisei stores.

The JSON report lists the bulk copy in `families`, the fenced catch-up in
`recopied`, and the refuse window in `fence_window_ms`. Writers are refused
only for that window, not for the full family load. The catch-up reloads each
dirty family in full, so the window grows with the size of the families
written during the copy, not with the number of rows changed.

Sekai-owned tables stay in place. Source Chisei rows are left for rollback
until an operator archives the pre-fence snapshot.

## Resume

Re-run the same command. Completed families are skipped. Incomplete families
are copied again and re-validated. A run interrupted after the fence keeps its
dirty set, so the re-run copies those families again before stamping. Once the
fence is raised, the source refuses Chisei writes until a re-run stamps both
destinations; recover a failure in that window by re-running, not by
reopening the source as a Shared writer.

## After the fence

Combined already refuses a lone `DB_PATH` / `DATABASE_URL` unless
`SEKAI_SHARED_STORE=1`. After the fence, that hatch still cannot start a
writer (including `gateway-report`). Stop the historical process, set
`SEKAI_DB_PATH` and `CHISEI_DB_PATH` (or two PostgreSQL URLs), and start
Combined against the destination pair. The capture triggers stay on the
source's Chisei tables, which remain as rollback data and refuse writes.

Rollback after the fence is restore-both from the pre-fence snapshot, not a
mixed pair.

## One-sided restore

Each destination store carries its own split generation in
`sekai_store_cutover`. Combined split open compares the pair. Empty
green-field destinations receive the first stamp on open; relocate stamps
as part of cutover. Dual-unstamped stores that already hold operator facts
are not a pair: writes stay refused until restamp. Mutating admits also
dual-write a pairing epoch. Equal generation after a one-sided restore of
a matched backup is not a pairing proof; the restored plane keeps the old
epoch and writes stay refused until restamp. A Shared or
owned-plane process that opens one stamped dest compares `SEKAI_STORE_PEER`
(read-only; not a writer destination). A missing peer or unequal generation
keeps mutating RPCs refused until an operator restamps both stores:

```sh
sekaictl admin store restamp --sekai ./data/sekai.db --chisei ./data/chisei.db
```

PostgreSQL destinations take two URLs instead of paths. Independent backups
are not a paired restore set. Restoring one store and leaving the other
does not resume writes. Read RPCs stay available so operators can inspect
receipts; `PreviewObjectAction` is refused with the mutating set because
fill, TypeSafe egress, and Decision audit are side effects.
`operation_id` correlation is unchanged after restamp.

## Fresh installs

New combined installs that already use distinct destination paths do not
need relocate. They never had Chisei families in a shared writer.

## Cross-store admission after the split

`SubmitActionInstance` no longer shares one local transaction with Chisei
budget and receipts. Combined mode uses the same reserve → submit →
finalize clerk as a later split process: Chisei keys the reservation by
`(namespace, operation_id)`, Sekai admits and commits, and reconcile
finalizes a pending reservation only after Sekai reports the instance.
A timeout or failed lookup stays pending. Public `GetOperationReceipt`
projects a live Sekai commit handle onto the Chisei decision receipt and
does not copy the Sekai receipt body.

## Separate processes

`sekai-plane` and `chisei-plane` binaries each open only their own store and credentials.
Combined `sekai-chisei` still uses the typed two-store contract. Wrong-plane
RPCs return `FAILED_PRECONDITION`. A Chisei process hops to Sekai with
`SEKAI_ENDPOINT` and `SEKAI_CREDENTIAL`; Sekai rechecks current caller
authorization at commit and does not treat a Chisei decision as authority.
The gateway stays a translator and does not own a third store. See
[two-plane processes](two-plane-processes.md).
