# Two-store relocation

Historical single-file deployments keep Chisei families in the same physical
store as Sekai facts. Combined mode can already open two files
([#1005](https://github.com/Sannrox/sekai-chisei/issues/1005)). Relocation
copies Chisei-owned families into the Chisei destination, then raises a
writer fence so the old single-store process cannot become a writer again.

Do not dual-write production traffic across two stores. Quiesce writers
before copy.

## Quiesce

Stop every `sekai-chisei` process that has the historical file or URL open
for writes. Take a copy of the pre-relocate files. That copy is the rollback
point until the fence is raised.

## Relocate

```sh
sekaictl admin store relocate \
  --source ./data/sekai.db \
  --sekai ./data/sekai.db \
  --chisei ./data/chisei.db
```

The command:

1. Initializes missing destination schema.
2. Copies each Chisei family (`budget`, `evaluation`, `portfolio`, …) from
   `--source` into `--chisei`.
3. Validates row counts per table and fails closed on mismatch.
4. Records completed families in `chisei_relocate_families` so a crash can
   resume from the last completed family.
5. Stamps `sekai_store_cutover` on the source, Sekai file, and Chisei file
   and raises the writer fence.

Sekai-owned tables stay in place. Source Chisei rows are left for rollback
until an operator archives the pre-fence snapshot.

## Resume

Re-run the same command. Completed families are skipped. Incomplete families
are copied again and re-validated.

## After the fence

`DB_PATH` / `DATABASE_URL` alone refuse to start a writer. Set
`SEKAI_DB_PATH` and `CHISEI_DB_PATH` (or two PostgreSQL URLs) and start
combined mode against the destination pair.

Rollback after the fence is restore-both from the pre-fence snapshot, not a
mixed pair.

## One-sided restore

Each destination store carries its own split generation in
`sekai_store_cutover`. Combined or split open compares the pair. A missing
or unequal generation keeps mutating RPCs refused until an operator restamps
both stores:

```sh
sekaictl admin store restamp --sekai ./data/sekai.db --chisei ./data/chisei.db
```

PostgreSQL destinations take two URLs instead of paths. Independent backups
are not a paired restore set. Restoring one store and leaving the other
does not resume writes. Read RPCs stay available so operators can inspect
receipts; `operation_id` correlation is unchanged after restamp.

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
