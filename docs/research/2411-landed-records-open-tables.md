# Research: should landed source records live in open tables on object storage

Issue: [#2411](https://github.com/Sannrox/sekai-chisei/issues/2411)
Date: 2026-11-24
Status: **recommendation complete**; see [ADR 0162](../decisions/0162-landed-source-records-stay-in-the-sql-store.md) (proposed)

## Decision question

Should the records a source batch lands be stored as open tables on object
storage, with the plane keeping the catalog, policy and markings, instead of as
rows in the plane's SQL store?

## Options

- **A. Keep landed records in the SQL store.** Open formats stay an export
  (lakehouse snapshots, warehouse projections) and a registered read
  (open-table projections).
- **B. Land into open tables on object storage.** Objects derive from those
  tables plus the edit log. The plane reads external storage.
- **C. Land in SQL, mirror to open tables.** Two copies, one authority.

## Evidence

### Where landed records live today

`ApplySourceBatch` writes the batch transaction and its stored `batch_json`, per-record results and source
identities, the binding-owned dataset rows (with the optional v3 retained
payload), and a new dataset version. Index apply then derives objects and
object changes. A `full_rebuild` rematerializes members from the landed dataset
rows without another source read ([object sync](../object-sync.md)).

Each dataset version stores a full copy of every row the dataset holds
(`sekai_dataset_version_rows`), and the version id hashes every row. Both
backends do this; PostgreSQL issues one insert round trip per copied row.
Retention can purge versions, but it is opt-in, so a default store keeps every
copy.

### Landed volume at which the SQL store becomes the limit

Measured with the object-path harness (`crates/sekai-harness`, workload
`apply_source_batch_grpc_sqlite_1000`) in 500-record batches (the
`MAX_SOURCE_BATCH_RECORDS` cap) with unique external ids, release build,
SQLite, one in-process gRPC service. Reads are `GetObject` p99 and one
`ListObjects` page p95 after each window.

Store on tmpfs, which removes fsync cost and isolates the CPU and write
volume of the path:

| Landed records | Window records/s | GetObject p99 | ListObjects p95 | Store size |
| --- | --- | --- | --- | --- |
| 1,000 | 2,502 | 0.3 ms | 82 ms | 22 MB |
| 5,000 | 1,388 | 0.3 ms | 81 ms | 74 MB |
| 10,000 | 1,317 | 0.3 ms | 77 ms | 175 MB |
| 20,000 | 604 | 0.3 ms | 80 ms | 481 MB |
| 30,000 | 415 | 0.3 ms | 80 ms | 928 MB |
| 40,000 | 168 | 0.4 ms | 93 ms | 1,512 MB |

Store on a local SSD with fsync:

| Landed records | Window records/s | Store size |
| --- | --- | --- |
| 1,000–5,000 | 82–136 | 22–74 MB |
| 25,000 | 87 | 690 MB |
| 50,000 | 55 | 2,244 MB |

At 78,500 landed rows the store held 5.4M version rows across 157 versions
(500, 1,000, ... 78,500 rows each) and 4.2 GB. The landing path wrote about
130 KB per landed record at an empty store and spent most of its time waiting
on fsync (about 20% CPU).

Findings:

- Landing falls below the documented `ApplySourceBatch` floor
  ([2,000 records/s](../performance-benchmarks.md)) before 10,000 landed
  records, and keeps falling. Store size grows quadratically
  (22 KB per record at 1,000, 38 KB at 40,000).
- The cause is the full-copy dataset version per batch, not the SQL store:
  reads stay flat across the range, and the rows themselves are a small share
  of the store. Filed as #3475.
- On durable storage, per-batch commit and write volume dominate first
  (about 20x the tmpfs cost at an empty store).
- The SQL store is therefore not yet shown to be the limit. The version layout
  is, and it would follow the data to any backend that keeps whole-copy
  versions.

PostgreSQL was not measured. It shares the version layout with a round trip
per copied row, so it is not expected to do better.

### Commit and read-back cost of a landed batch on object storage

Parquet encode with the repository encoder (`crates/sekai-parquet-export`),
four string columns plus id, best of 20:

| Rows | Encode | Bytes |
| --- | --- | --- |
| 500 | 0.16 ms | 37,686 |
| 5,000 | 1.8 ms | 380,802 |
| 50,000 | 21 ms | 3,857,070 |

PUT and GET against a local S3-compatible object store in a container on a
loopback ephemeral port, tmpfs-backed, signed requests, 30 samples:

| Object | PUT p50 / p95 | GET p50 / p95 |
| --- | --- | --- |
| 500-row part | 1.7 / 2.3 ms | 1.4 / 1.9 ms |
| 5,000-row part | 3.0 / 3.8 ms | 1.9 / 2.8 ms |
| 50,000-row part | 8.6 / 9.8 ms | 3.8 / 5.7 ms |
| snapshot pointer | 1.9 / 2.5 ms | |
| LIST of 91 keys | 4.1 / 5.5 ms | |

A 500-record batch commit on object storage is part PUT plus pointer PUT,
about 3.8 ms on loopback; a remote store adds two network round trips. That
does not replace the SQL commit: under B the plane still commits the batch
transaction, checkpoint, identities, markings and the catalog entry in its
store, so B adds a second durable write and a cross-store ordering rule
(part, then pointer, then catalog, with orphan-part cleanup on crash). The
same numbers say the bytes are cheap; the cost under A is the version layout,
which B does not remove unless versions share files, and sharing rows across
versions is available to A directly.

### Can the open-table projection contract describe landed tables

No, not without a new contract revision. `sekai.open-table-source/v1`
([open tables](../open-tables.md), [ADR 0036](../decisions/0036-open-table-projections.md))
binds a format, schema revision, schema and snapshot digests, namespace, a
single owner, column markings, and a locally admitted row snapshot whose digest
matches the registration. It describes an external table the plane does not
write, read through rows admitted into the plane. Landed tables need what it
lacks:

- a writer identity and per-batch lineage (source instance, batch, checkpoint)
  instead of one registering owner;
- appends and tombstones under one table identity, where every new snapshot
  today means re-register and re-admit;
- row and cell policy, retained-payload visibility and retention per landed
  row, where the contract carries only column markings;
- the plane reading the table, which the contract rules out: the admitted
  snapshot is a local copy.

Describing landed tables in v1 terms makes the local snapshot the authority,
which is option C with extra steps.

### What an adopter can read with their own tools

| Option | Adopter read path | Policy before read |
| --- | --- | --- |
| A | Lakehouse snapshot export (SQLite), warehouse projection pages, Parquet export, gRPC/HTTP reads | Applied by the plane on every export and read |
| B | The bucket directly, with any engine that reads the table format | Only as strong as the bucket's own access rules; row and cell policy and markings do not apply to a direct file read |
| C | The mirror directly, plus everything under A | Same as B for the mirror; the plane must redact before it mirrors |

The constraint "markings and row, property and cell policy apply before any
read" rules out a raw-file read under B unless the files hold only what every
reader may see, which is the export under A.

### Backup, restore and rebuild

| Option | Backup | Restore | Rebuild |
| --- | --- | --- | --- |
| A | `VACUUM INTO` per dest plus the object log, one consistent snapshot ([operations](../operations.md#persistence-and-backups)) | Restore databases and log together | `full_rebuild` from landed dataset rows; no source read |
| B | Store snapshot plus a bucket snapshot at the same catalog point; the bucket needs versioning or an immutable-part rule so a restored catalog never points at overwritten parts | Restore both, then reconcile catalog against parts (orphans, missing parts) | `full_rebuild` reads object storage: the plane opens external storage and holds its credentials |
| C | As A; the mirror is rebuildable from the store | Restore as A, then regenerate the mirror | As A |

Under B every recovery path gains a second system whose failure the plane must
detect and fail closed on; ADR 0036 rejected that dependency for registered
reads for the same reason.

## Recommendation

**Option A.** Landed records stay in the SQL store. Open formats stay an
export and a registered read.

- The measured limit is the full-copy dataset version, which costs the same
  under any backend that keeps whole-copy versions. Fixing it in the store
  (#3475) is the step that moves the landing curve; B does not.
- B makes object storage an authority on the read, rebuild and restore paths,
  needs a new contract revision, and lets direct file reads skip row and cell
  policy.
- C is A plus a redacted mirror. For the consuming deployment that needs
  versioned datasets in an open format, the existing lakehouse snapshot export
  is that mirror; widening it (PostgreSQL support, incremental export per
  dataset version) is the path, not moving the authority.

Revisit when, after #3475, a measured workload still finds the SQL store the
limit on landed volume, or when the object log moves to object storage and the
plane already holds a storage dependency with fencing and recovery.

## Method notes

Probes were throwaway programs over the existing harness and encoder; they are
not committed. Absolute numbers depend on the disk and its fsync cost; the
shapes (quadratic store growth, linear per-batch slowdown, flat reads) do not.
