//! Offline, restartable Chisei-family relocation and writer fence.
//!
//! Take a short exclusive `VACUUM INTO` snapshot of the historical source,
//! raise the writer fence, then copy each Chisei-owned family from that
//! snapshot. The live source is not ATTACH'd for the family copy. Rollback
//! before the snapshot keeps the pre-copy files.
//!
//! Destination pairs also carry a split generation. Combined split open
//! compares the pair. Dual-unstamped stores auto-stamp only when both are
//! empty; operator facts without a cutover stay unattested until restamp.
//! A Shared or owned-plane open of a stamped store compares
//! `SEKAI_STORE_PEER` (read-only) or refuses mutations until an operator
//! restamp. Independent backups are not a paired restore set.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::combined_stores::{CombinedStoreLayout, CombinedStoreSources, StoreIdentity};
use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::runtime_backend::{BackendIdentity, RuntimeBackend, RuntimeBackendConfig};

const CUTOVER_TABLE: &str = "sekai_store_cutover";
const JOURNAL_TABLE: &str = "chisei_relocate_families";

#[cfg(test)]
thread_local! {
    static GENERATION_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocateReport {
    pub families: Vec<FamilyReport>,
    pub generation: i64,
    pub fence_raised: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyReport {
    pub family: String,
    pub skipped: bool,
    pub tables: Vec<String>,
    pub row_count: i64,
    pub digest: String,
}

pub fn usage() -> &'static str {
    "sekaictl admin store relocate --source <path-or-url> --sekai <path-or-url> --chisei <path-or-url>\n  Offline copy of Chisei families from the historical single store into the Chisei destination. Three SQLite paths or three PostgreSQL URLs. --sekai must be the same physical identity as --source. Snapshots the source, fences writers, then copies families from the snapshot. Restartable per family. Quiesce writers first. Rollback before the snapshot keeps the pre-copy files.\n\
sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>\n  Operator reconcile after a one-sided restore. Writes the same split generation on both destination stores so mutating RPCs may resume. Independent backups are not a paired restore set."
}

pub fn run_store_command(
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args.first().map(String::as_str) {
        Some("relocate") => {
            let config = parse_relocate(&args[1..])?;
            let report = relocate(&config.source, &config.sekai, &config.chisei)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("restamp") => {
            let config = parse_restamp(&args[1..])?;
            let generation = restamp_destinations(&config.sekai, &config.chisei)?;
            println!("{{\"generation\":{generation}}}");
            Ok(())
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

struct RelocateArgs {
    source: String,
    sekai: String,
    chisei: String,
}

fn parse_relocate(args: &[String]) -> Result<RelocateArgs, String> {
    let mut source = None;
    let mut sekai = None;
    let mut chisei = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                source = Some(require_value(args, i, "--source")?);
                i += 2;
            }
            "--sekai" => {
                sekai = Some(require_value(args, i, "--sekai")?);
                i += 2;
            }
            "--chisei" => {
                chisei = Some(require_value(args, i, "--chisei")?);
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(RelocateArgs {
        source: source.ok_or("--source is required")?,
        sekai: sekai.ok_or("--sekai is required")?,
        chisei: chisei.ok_or("--chisei is required")?,
    })
}

struct RestampArgs {
    sekai: String,
    chisei: String,
}

fn parse_restamp(args: &[String]) -> Result<RestampArgs, String> {
    let mut sekai = None;
    let mut chisei = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sekai" => {
                sekai = Some(require_value(args, i, "--sekai")?);
                i += 2;
            }
            "--chisei" => {
                chisei = Some(require_value(args, i, "--chisei")?);
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(RestampArgs {
        sekai: sekai.ok_or("--sekai is required")?,
        chisei: chisei.ok_or("--chisei is required")?,
    })
}

fn require_value(args: &[String], i: usize, flag: &str) -> Result<String, String> {
    args.get(i + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Copy Chisei families from `source` into `chisei`, stamp both destinations,
/// and raise the writer fence on the historical source.
pub fn relocate(source: &str, sekai: &str, chisei: &str) -> Result<RelocateReport, String> {
    match (
        looks_like_postgres_url(source),
        looks_like_postgres_url(sekai),
        looks_like_postgres_url(chisei),
    ) {
        (true, true, true) => relocate_postgres(source, sekai, chisei),
        (false, false, false) => relocate_sqlite(source, sekai, chisei),
        _ => Err(
            "relocate requires three SQLite paths or three PostgreSQL URLs; mixed backends are refused"
                .into(),
        ),
    }
}

/// Copy Chisei families from `source` into `chisei`, stamp both destinations,
/// and raise the writer fence on the historical source.
pub fn relocate_sqlite(source: &str, sekai: &str, chisei: &str) -> Result<RelocateReport, String> {
    if source.trim().is_empty() || sekai.trim().is_empty() || chisei.trim().is_empty() {
        return Err("relocate paths must not be empty".into());
    }
    let source_id = crate::combined_stores::sqlite_identity(source)?;
    let sekai_id = crate::combined_stores::sqlite_identity(sekai)?;
    let chisei_id = crate::combined_stores::sqlite_identity(chisei)?;
    if source_id != sekai_id && !crate::combined_stores::sqlite_same_inode(&source_id, &sekai_id) {
        return Err(
            "relocate refuses a distinct --sekai; --sekai must be the historical source so Sekai facts are not orphaned"
                .into(),
        );
    }
    if source_id == chisei_id {
        return Err(
            "relocate refuses a shared source and Chisei destination; copy into a distinct file"
                .into(),
        );
    }
    if sekai_id == chisei_id || crate::combined_stores::sqlite_same_inode(&sekai_id, &chisei_id) {
        return Err(
            "relocate refuses the same physical destination for --sekai and --chisei; Split cutover needs two files"
                .into(),
        );
    }

    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Sqlite,
        Some(source),
        source,
        None,
        16,
        None,
    )?)?;
    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Sqlite,
        Some(sekai),
        sekai,
        None,
        16,
        None,
    )?)?;
    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Sqlite,
        Some(chisei),
        chisei,
        None,
        16,
        None,
    )?)?;

    let snapshot = relocate_snapshot_path(chisei);
    snapshot_sqlite(source, &snapshot)?;
    let generation = raise_writer_fence(source)?;
    let reports = copy_chisei_families_from_snapshot(&snapshot, chisei)?;
    remove_sqlite_sidecar(&snapshot);
    raise_writer_fence_with_generation(sekai, generation)?;
    raise_writer_fence_with_generation(chisei, generation)?;

    Ok(RelocateReport {
        families: reports,
        generation,
        fence_raised: true,
    })
}

pub fn relocate_postgres(
    source: &str,
    sekai: &str,
    chisei: &str,
) -> Result<RelocateReport, String> {
    if source.trim().is_empty() || sekai.trim().is_empty() || chisei.trim().is_empty() {
        return Err("relocate URLs must not be empty".into());
    }
    let source_id = crate::combined_stores::postgres_identity(source)?;
    let sekai_id = crate::combined_stores::postgres_identity(sekai)?;
    let chisei_id = crate::combined_stores::postgres_identity(chisei)?;
    if source_id != sekai_id {
        return Err(
            "relocate refuses a distinct --sekai; --sekai must be the historical source so Sekai facts are not orphaned"
                .into(),
        );
    }
    if source_id == chisei_id {
        return Err(
            "relocate refuses a shared source and Chisei destination; copy into a distinct database"
                .into(),
        );
    }

    let ca = postgres_ca_cert_path();
    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Postgres,
        None,
        "unused.db",
        Some(source),
        16,
        ca.as_deref(),
    )?)?;
    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Postgres,
        None,
        "unused.db",
        Some(sekai),
        16,
        ca.as_deref(),
    )?)?;
    RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Postgres,
        None,
        "unused.db",
        Some(chisei),
        16,
        ca.as_deref(),
    )?)?;

    let source_db = connect_postgres(source)?;
    let chisei_db = connect_postgres(chisei)?;
    let snapshot_dir = relocate_postgres_snapshot_dir(chisei);
    snapshot_postgres(&source_db, &snapshot_dir)?;
    let generation = raise_postgres_writer_fence(&source_db)?;
    let reports = copy_chisei_families_from_postgres_snapshot(&snapshot_dir, &chisei_db)?;
    let _ = std::fs::remove_dir_all(&snapshot_dir);
    raise_postgres_writer_fence_with_generation(&connect_postgres(sekai)?, generation)?;
    raise_postgres_writer_fence_with_generation(&chisei_db, generation)?;

    Ok(RelocateReport {
        families: reports,
        generation,
        fence_raised: true,
    })
}

fn postgres_ca_cert_path() -> Option<String> {
    crate::combined_stores::optional_trimmed_env("SEKAI_POSTGRES_CA_CERT")
}

fn connect_postgres(url: &str) -> Result<PostgresDb, String> {
    match postgres_ca_cert_path() {
        Some(path) => {
            let pem = std::fs::read(&path).map_err(|error| error.to_string())?;
            PostgresDb::connect_with_ca_certificate(url, 4, &pem)
        }
        None => PostgresDb::connect(url, 4),
    }
}

fn relocate_postgres_snapshot_dir(chisei: &str) -> String {
    let digest = format!("{:x}", md5_ish(chisei));
    std::env::temp_dir()
        .join(format!("sekai-relocate-{digest}"))
        .to_string_lossy()
        .into_owned()
}

fn md5_ish(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn snapshot_postgres(source: &PostgresDb, snapshot_dir: &str) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(snapshot_dir);
    std::fs::create_dir_all(snapshot_dir).map_err(|error| error.to_string())?;
    let mut conn = source.connection()?;
    conn.batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .map_err(|error| format!("begin postgres snapshot: {error}"))?;
    let tables = list_postgres_chisei_tables(&mut conn)?;
    for table in &tables {
        let path = std::path::Path::new(snapshot_dir).join(table);
        let mut file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
        let mut reader = conn
            .copy_out(&format!("COPY {table} TO STDOUT"))
            .map_err(|error| format!("snapshot {table}: {error}"))?;
        std::io::copy(&mut reader, &mut file)
            .map_err(|error| format!("write {table} snapshot: {error}"))?;
    }
    conn.batch_execute("COMMIT")
        .map_err(|error| format!("commit postgres snapshot: {error}"))?;
    std::fs::write(
        std::path::Path::new(snapshot_dir).join("tables.txt"),
        tables.join("\n"),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn list_postgres_chisei_tables(conn: &mut postgres::Client) -> Result<Vec<String>, String> {
    let rows = conn
        .query(
            "SELECT tablename FROM pg_tables
             WHERE schemaname = 'public'
               AND tablename LIKE 'chisei_%'
               AND tablename <> $1
             ORDER BY tablename",
            &[&JOURNAL_TABLE],
        )
        .map_err(|error| error.to_string())?;
    let mut tables = Vec::new();
    for row in rows {
        let table: String = row.get(0);
        if !table
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(format!("refusing unexpected table name {table}"));
        }
        tables.push(table);
    }
    Ok(tables)
}

fn copy_chisei_families_from_postgres_snapshot(
    snapshot_dir: &str,
    dest: &PostgresDb,
) -> Result<Vec<FamilyReport>, String> {
    let mut conn = dest.connection()?;
    conn.batch_execute(&format!(
        "CREATE TABLE IF NOT EXISTS {JOURNAL_TABLE} (
            family TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            table_count BIGINT NOT NULL,
            row_count BIGINT NOT NULL,
            digest TEXT NOT NULL,
            completed_at_ms BIGINT NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())?;
    let listing = std::fs::read_to_string(std::path::Path::new(snapshot_dir).join("tables.txt"))
        .map_err(|error| error.to_string())?;
    let tables: Vec<String> = listing
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    let families = group_families(&tables);
    let mut reports = Vec::new();
    for (family, family_tables) in families {
        if postgres_family_completed(&mut conn, &family)? {
            reports.push(FamilyReport {
                family,
                skipped: true,
                tables: family_tables,
                row_count: 0,
                digest: "skipped".into(),
            });
            continue;
        }
        let mut row_count = 0;
        let mut digest_parts = Vec::new();
        for table in &family_tables {
            ensure_postgres_dest_table(&mut conn, table)?;
            conn.execute(&format!("DELETE FROM {table}"), &[])
                .map_err(|error| format!("clear {table}: {error}"))?;
            let path = std::path::Path::new(snapshot_dir).join(table);
            let mut file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
            let mut writer = conn
                .copy_in(&format!("COPY {table} FROM STDIN"))
                .map_err(|error| format!("load {table}: {error}"))?;
            std::io::copy(&mut file, &mut writer)
                .map_err(|error| format!("copy {table}: {error}"))?;
            writer
                .finish()
                .map_err(|error| format!("finish {table}: {error}"))?;
            let dest_count = postgres_table_count(&mut conn, table)?;
            row_count += dest_count;
            digest_parts.push(format!("{table}={dest_count}"));
        }
        let digest = digest_parts.join(",");
        conn.execute(
            &format!(
                "INSERT INTO {JOURNAL_TABLE}
                 (family, status, table_count, row_count, digest, completed_at_ms)
                 VALUES ($1, 'completed', $2, $3, $4, $5)
                 ON CONFLICT (family) DO UPDATE SET
                    status = EXCLUDED.status,
                    table_count = EXCLUDED.table_count,
                    row_count = EXCLUDED.row_count,
                    digest = EXCLUDED.digest,
                    completed_at_ms = EXCLUDED.completed_at_ms"
            ),
            &[
                &family,
                &(family_tables.len() as i64),
                &row_count,
                &digest,
                &chrono::Utc::now().timestamp_millis(),
            ],
        )
        .map_err(|error| error.to_string())?;
        reports.push(FamilyReport {
            family,
            skipped: false,
            tables: family_tables,
            row_count,
            digest,
        });
    }
    Ok(reports)
}

fn postgres_family_completed(conn: &mut postgres::Client, family: &str) -> Result<bool, String> {
    match conn.query_opt(
        &format!("SELECT status FROM {JOURNAL_TABLE} WHERE family = $1"),
        &[&family],
    ) {
        Ok(Some(row)) => Ok(row.get::<_, String>(0) == "completed"),
        Ok(None) => Ok(false),
        Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_postgres_dest_table(conn: &mut postgres::Client, table: &str) -> Result<(), String> {
    let exists: bool = conn
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM pg_tables
                WHERE schemaname = 'public' AND tablename = $1
            )",
            &[&table],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if exists {
        Ok(())
    } else {
        Err(format!(
            "destination is missing {table}; initialize the Chisei store with the same schema before relocate"
        ))
    }
}

fn postgres_table_count(conn: &mut postgres::Client, table: &str) -> Result<i64, String> {
    conn.query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .map(|row| row.get::<_, i64>(0))
        .map_err(|error| format!("count {table}: {error}"))
}

fn relocate_snapshot_path(chisei: &str) -> String {
    format!("{chisei}.relocate-snapshot.db")
}

fn snapshot_sqlite(source: &str, snapshot: &str) -> Result<(), String> {
    remove_sqlite_sidecar(snapshot);
    let conn = Connection::open(source).map_err(|error| error.to_string())?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| format!("checkpoint source before snapshot: {error}"))?;
    let escaped = snapshot.replace('\'', "''");
    conn.execute_batch(&format!("VACUUM INTO '{escaped}'"))
        .map_err(|error| format!("snapshot source: {error}"))?;
    Ok(())
}

fn copy_chisei_families_from_snapshot(
    snapshot: &str,
    chisei: &str,
) -> Result<Vec<FamilyReport>, String> {
    let dest = Connection::open(chisei).map_err(|error| error.to_string())?;
    dest.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {JOURNAL_TABLE} (
            family TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            table_count INTEGER NOT NULL,
            row_count INTEGER NOT NULL,
            digest TEXT NOT NULL,
            completed_at_ms INTEGER NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())?;
    dest.execute("ATTACH DATABASE ?1 AS src", params![snapshot])
        .map_err(|error| error.to_string())?;

    let tables = list_chisei_tables(&dest, "src")?;
    let families = group_families(&tables);
    let mut reports = Vec::new();
    for (family, family_tables) in families {
        if family_completed(&dest, &family)? {
            reports.push(FamilyReport {
                family,
                skipped: true,
                tables: family_tables,
                row_count: 0,
                digest: "skipped".into(),
            });
            continue;
        }
        let mut row_count = 0;
        let mut digest_parts = Vec::new();
        for table in &family_tables {
            ensure_dest_table(&dest, table)?;
            dest.execute(&format!("DELETE FROM main.{table}"), [])
                .map_err(|error| format!("clear {table}: {error}"))?;
            dest.execute(
                &format!("INSERT INTO main.{table} SELECT * FROM src.{table}"),
                [],
            )
            .map_err(|error| format!("copy {table}: {error}"))?;
            let source_count = table_count(&dest, "src", table)?;
            let dest_count = table_count(&dest, "main", table)?;
            if source_count != dest_count {
                return Err(format!(
                    "relocate validation failed for {table}: source count {source_count} != destination count {dest_count}"
                ));
            }
            row_count += dest_count;
            digest_parts.push(format!("{table}={dest_count}"));
        }
        let digest = digest_parts.join(",");
        dest.execute(
            &format!(
                "INSERT OR REPLACE INTO {JOURNAL_TABLE}
                 (family, status, table_count, row_count, digest, completed_at_ms)
                 VALUES (?1, 'completed', ?2, ?3, ?4, ?5)"
            ),
            params![
                family,
                family_tables.len() as i64,
                row_count,
                digest,
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|error| error.to_string())?;
        reports.push(FamilyReport {
            family,
            skipped: false,
            tables: family_tables,
            row_count,
            digest,
        });
    }

    dest.execute("DETACH DATABASE src", [])
        .map_err(|error| error.to_string())?;
    Ok(reports)
}

fn remove_sqlite_sidecar(path: &str) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

/// Shared-compatibility writers refuse after the fence is raised.
pub fn refuse_shared_writer_if_fenced(layout: &CombinedStoreLayout) -> Result<(), String> {
    if layout.is_split() {
        return Ok(());
    }
    match layout.sekai_identity() {
        StoreIdentity::Sqlite { canonical_path } => {
            if canonical_path == ":memory:" {
                return Ok(());
            }
            if writer_fence_raised(canonical_path)? {
                return Err(shared_writer_guidance());
            }
        }
        StoreIdentity::Postgres { .. } => {
            if runtime_writer_fence_raised(layout.sekai_runtime().as_ref())? {
                return Err(shared_writer_guidance());
            }
        }
    }
    Ok(())
}

pub fn writer_fence_raised(path: &str) -> Result<bool, String> {
    if !Path::new(path).exists() {
        return Ok(false);
    }
    let conn = Connection::open(path).map_err(|error| error.to_string())?;
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            params![CUTOVER_TABLE],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Ok(false);
    }
    let raised: i64 = conn
        .query_row(
            &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id=1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or(0);
    Ok(raised == 1)
}

fn runtime_writer_fence_raised(db: &RuntimeDb) -> Result<bool, String> {
    match db {
        RuntimeDb::Sqlite(_) => db.with_sqlite_conn(|conn| {
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                    params![CUTOVER_TABLE],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if exists.is_none() {
                return Ok(false);
            }
            let raised: i64 = conn
                .query_row(
                    &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id=1"),
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(0);
            Ok(raised == 1)
        })?,
        RuntimeDb::Postgres(db) => postgres_writer_fence_raised(db),
    }
}

fn postgres_writer_fence_raised(db: &PostgresDb) -> Result<bool, String> {
    let mut conn = db.connection()?;
    match conn.query_opt(
        "SELECT fence_raised FROM sekai_store_cutover WHERE id = 1",
        &[],
    ) {
        // fence_raised is INTEGER (int4); the postgres crate does not widen
        // an int4 column into an i64 read.
        Ok(Some(row)) => Ok(row.get::<_, i32>(0) == 1),
        Ok(None) => Ok(false),
        Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn raise_postgres_writer_fence(db: &PostgresDb) -> Result<i64, String> {
    let generation = chrono::Utc::now().timestamp_millis();
    raise_postgres_writer_fence_with_generation(db, generation)?;
    Ok(generation)
}

fn raise_postgres_writer_fence_with_generation(
    db: &PostgresDb,
    generation: i64,
) -> Result<(), String> {
    let mut conn = db.connection()?;
    conn.batch_execute(
        "CREATE TABLE IF NOT EXISTS sekai_store_cutover (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            generation BIGINT NOT NULL,
            fence_raised INTEGER NOT NULL,
            raised_at_ms BIGINT NOT NULL,
            pairing_epoch BIGINT NOT NULL DEFAULT 0
        );
        ALTER TABLE sekai_store_cutover
            ADD COLUMN IF NOT EXISTS pairing_epoch BIGINT NOT NULL DEFAULT 0;",
    )
    .map_err(|error| error.to_string())?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    conn.execute(
        "INSERT INTO sekai_store_cutover (id, generation, fence_raised, raised_at_ms, pairing_epoch)
         VALUES (1, $1, 1, $2, 0)
         ON CONFLICT (id) DO UPDATE SET
            generation = EXCLUDED.generation,
            fence_raised = 1,
            raised_at_ms = EXCLUDED.raised_at_ms,
            pairing_epoch = 0",
        &[&generation, &now_ms],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn shared_writer_guidance() -> String {
    "this database has a two-store writer fence; set SEKAI_DB_PATH and CHISEI_DB_PATH (or two PostgreSQL URLs) and keep writers quiesced on the historical single file. Rollback is restore-both from the pre-fence snapshot, not a mixed pair".into()
}

/// Compared split-generation state for a combined destination pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SplitGenerationState {
    Shared,
    Matched {
        generation: i64,
    },
    Unstamped,
    Unattested,
    Mismatched {
        sekai: Option<i64>,
        chisei: Option<i64>,
    },
}

impl SplitGenerationState {
    pub fn refuses_mutations(&self) -> bool {
        matches!(self, Self::Mismatched { .. } | Self::Unattested)
    }
}

pub fn compare_split_generations(sekai: Option<i64>, chisei: Option<i64>) -> SplitGenerationState {
    match (sekai, chisei) {
        (None, None) => SplitGenerationState::Unstamped,
        (Some(left), Some(right)) if left == right => {
            SplitGenerationState::Matched { generation: left }
        }
        (sekai, chisei) => SplitGenerationState::Mismatched { sekai, chisei },
    }
}

pub fn split_generation_state(
    layout: &CombinedStoreLayout,
) -> Result<SplitGenerationState, String> {
    split_generation_state_with_peer(layout, store_generation_peer().as_deref())
}

fn store_generation_peer() -> Option<String> {
    crate::combined_stores::optional_trimmed_env("SEKAI_STORE_PEER")
}

pub(crate) fn split_generation_state_with_peer(
    layout: &CombinedStoreLayout,
    peer: Option<&str>,
) -> Result<SplitGenerationState, String> {
    let state = if layout.is_split() {
        compare_split_generations(
            read_runtime_generation(&layout.sekai_runtime())?,
            read_runtime_generation(&layout.chisei_runtime())?,
        )
    } else {
        let local = read_runtime_generation(&layout.sekai_runtime())?;
        if local.is_none() {
            return Ok(SplitGenerationState::Shared);
        }
        let peer_generation = match peer {
            Some(dest) => read_dest_generation(dest)?,
            None => None,
        };
        compare_split_generations(local, peer_generation)
    };
    if matches!(state, SplitGenerationState::Unstamped) && layout_has_operator_facts(layout)? {
        return Ok(SplitGenerationState::Unattested);
    }
    Ok(state)
}

fn layout_has_operator_facts(layout: &CombinedStoreLayout) -> Result<bool, String> {
    Ok(runtime_has_operator_facts(&layout.sekai_runtime())?
        || runtime_has_operator_facts(&layout.chisei_runtime())?)
}

fn runtime_has_operator_facts(db: &RuntimeDb) -> Result<bool, String> {
    match db {
        RuntimeDb::Sqlite(_) => db.with_sqlite_conn(sqlite_has_operator_facts)?,
        RuntimeDb::Postgres(db) => postgres_has_operator_facts(db),
    }
}

const OPERATOR_FACT_TABLES: &[&str] = &[
    "sekai_objects",
    "sekai_grants",
    "sekai_links",
    "sekai_action_instances",
    "sekai_decisions",
];

fn sqlite_has_operator_facts(conn: &Connection) -> Result<bool, String> {
    for table in OPERATOR_FACT_TABLES {
        if sqlite_table_row_count(conn, table)? > 0 {
            return Ok(true);
        }
    }
    for table in list_chisei_tables(conn, "main")? {
        if sqlite_table_row_count(conn, &table)? > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sqlite_table_row_count(conn: &Connection, table: &str) -> Result<i64, String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Ok(0);
    }
    conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
        row.get(0)
    })
    .map_err(|error| error.to_string())
}

fn postgres_has_operator_facts(db: &PostgresDb) -> Result<bool, String> {
    let mut conn = db.connection()?;
    for table in OPERATOR_FACT_TABLES {
        match conn.query_one(&format!("SELECT COUNT(*) FROM {table}"), &[]) {
            Ok(row) => {
                let count: i64 = row.get(0);
                if count > 0 {
                    return Ok(true);
                }
            }
            Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let tables = conn
        .query(
            "SELECT tablename FROM pg_tables
             WHERE schemaname = 'public'
               AND tablename LIKE 'chisei_%'
               AND tablename <> $1
             ORDER BY tablename",
            &[&JOURNAL_TABLE],
        )
        .map_err(|error| error.to_string())?;
    for row in tables {
        let table: String = row.get(0);
        let count: i64 = conn
            .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .map_err(|error| error.to_string())?
            .get(0);
        if count > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_dest_generation(dest: &str) -> Result<Option<i64>, String> {
    if looks_like_postgres_url(dest) {
        return Err(
            "SEKAI_STORE_PEER PostgreSQL compare requires restamp of the destination pair".into(),
        );
    }
    if dest == ":memory:" || !Path::new(dest).exists() {
        return Ok(None);
    }
    let conn = Connection::open(dest).map_err(|error| error.to_string())?;
    read_sqlite_generation(&conn)
}

/// Stamp a matching generation on empty green-field destinations. Dual-
/// unstamped stores that already hold operator facts stay unattested so
/// mutating RPCs remain refused until an operator restamp. Relocate stamps
/// independently as the first cutover.
pub fn align_split_generations(
    layout: &CombinedStoreLayout,
) -> Result<SplitGenerationState, String> {
    match split_generation_state(layout)? {
        SplitGenerationState::Unstamped => {
            let generation = restamp_split_generation(layout)?;
            Ok(SplitGenerationState::Matched { generation })
        }
        other => Ok(other),
    }
}

pub fn refuse_mutating_if_generation_mismatch(layout: &CombinedStoreLayout) -> Result<(), String> {
    if layout.cached_matched_generation().is_some() {
        if pairing_epochs_match(layout)? {
            advance_pairing_epoch(layout)?;
            return Ok(());
        }
        layout.invalidate_matched_generation();
    }
    match split_generation_state(layout)? {
        SplitGenerationState::Mismatched { sekai, chisei } => {
            Err(generation_mismatch_guidance(sekai, chisei))
        }
        SplitGenerationState::Unattested => Err(unattested_guidance()),
        SplitGenerationState::Matched { generation } => {
            if !pairing_epochs_match(layout)? {
                return Err(pairing_epoch_guidance());
            }
            layout.cache_matched_generation(generation);
            advance_pairing_epoch(layout)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn pairing_epoch_guidance() -> String {
    "split pairing epochs disagree after a one-sided restore; mutating RPCs stay refused until an operator restamps both stores with `sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>`. Equal cutover generation is not a pairing proof".into()
}

fn unattested_guidance() -> String {
    "split stores hold operator facts without a cutover generation; mutating RPCs stay refused until an operator restamps both stores with `sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>`. Dual-unstamped is not a green-field pair".into()
}

fn pairing_epochs_match(layout: &CombinedStoreLayout) -> Result<bool, String> {
    if !layout.is_split() {
        return Ok(true);
    }
    Ok(read_runtime_pairing_epoch(&layout.sekai_runtime())?
        == read_runtime_pairing_epoch(&layout.chisei_runtime())?)
}

fn advance_pairing_epoch(layout: &CombinedStoreLayout) -> Result<(), String> {
    if !layout.is_split() {
        return Ok(());
    }
    let next = read_runtime_pairing_epoch(&layout.sekai_runtime())?
        .max(read_runtime_pairing_epoch(&layout.chisei_runtime())?)
        .saturating_add(1);
    write_runtime_pairing_epoch(&layout.sekai_runtime(), next)?;
    write_runtime_pairing_epoch(&layout.chisei_runtime(), next)?;
    Ok(())
}

pub fn generation_mismatch_guidance(sekai: Option<i64>, chisei: Option<i64>) -> String {
    format!(
        "split generations disagree (sekai={sekai:?}, chisei={chisei:?}); mutating RPCs stay refused until an operator restamps both stores with `sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>`. An owned or Shared open of a stamped store must set SEKAI_STORE_PEER to the other dest for the compare. Independent backups are not a paired restore set"
    )
}

pub fn restamp_split_generation(layout: &CombinedStoreLayout) -> Result<i64, String> {
    if !layout.is_split() {
        return Err("restamp requires a destination pair".into());
    }
    layout.invalidate_matched_generation();
    let generation = chrono::Utc::now().timestamp_millis();
    write_runtime_generation(&layout.sekai_runtime(), generation)?;
    write_runtime_generation(&layout.chisei_runtime(), generation)?;
    write_runtime_pairing_epoch(&layout.sekai_runtime(), 0)?;
    write_runtime_pairing_epoch(&layout.chisei_runtime(), 0)?;
    Ok(generation)
}

pub fn restamp_destinations(sekai: &str, chisei: &str) -> Result<i64, String> {
    let layout = open_restamp_layout(sekai, chisei)?;
    restamp_split_generation(&layout)
}

fn open_restamp_layout(sekai: &str, chisei: &str) -> Result<CombinedStoreLayout, String> {
    let sekai_pg = looks_like_postgres_url(sekai);
    let chisei_pg = looks_like_postgres_url(chisei);
    if sekai_pg != chisei_pg {
        return Err("restamp requires two SQLite paths or two PostgreSQL URLs".into());
    }
    if sekai_pg {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Postgres),
            default_sqlite_path: "unused.db".into(),
            sekai_postgres_url: Some(sekai.to_string()),
            chisei_postgres_url: Some(chisei.to_string()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
    } else {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: sekai.to_string(),
            sekai_sqlite_path: Some(sekai.to_string()),
            chisei_sqlite_path: Some(chisei.to_string()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
    }
}

fn looks_like_postgres_url(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://")
}

pub fn is_mutating_rpc(method: &str) -> bool {
    let name = method.rsplit('/').next().unwrap_or(method);
    if name == "PreviewObjectAction" {
        return true;
    }
    !(name.starts_with("Get")
        || name.starts_with("List")
        || name.starts_with("Evaluate")
        || name.starts_with("Describe")
        || name.starts_with("Preview")
        || name.starts_with("Search")
        || name.starts_with("Lookup")
        || name.starts_with("Watch")
        || name == "Check"
        || name == "CheckAccess"
        || name == "CheckReady"
        || name == "HealthCheck")
}

pub fn read_runtime_generation(db: &RuntimeDb) -> Result<Option<i64>, String> {
    #[cfg(test)]
    GENERATION_READS.with(|reads| reads.set(reads.get().saturating_add(1)));
    match db {
        RuntimeDb::Sqlite(_) => db.with_sqlite_conn(read_sqlite_generation)?,
        RuntimeDb::Postgres(db) => read_postgres_generation(db),
    }
}

pub fn write_runtime_generation(db: &RuntimeDb, generation: i64) -> Result<(), String> {
    match db {
        RuntimeDb::Sqlite(_) => {
            db.with_sqlite_conn(|conn| write_sqlite_generation(conn, generation))?
        }
        RuntimeDb::Postgres(db) => write_postgres_generation(db, generation),
    }
}

fn read_sqlite_generation(conn: &Connection) -> Result<Option<i64>, String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            params![CUTOVER_TABLE],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Ok(None);
    }
    conn.query_row(
        &format!("SELECT generation FROM {CUTOVER_TABLE} WHERE id=1"),
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn ensure_sqlite_cutover(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {CUTOVER_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            generation INTEGER NOT NULL,
            fence_raised INTEGER NOT NULL,
            raised_at_ms INTEGER NOT NULL,
            pairing_epoch INTEGER NOT NULL DEFAULT 0
        );"
    ))
    .map_err(|error| error.to_string())?;
    let _ = conn.execute(
        &format!("ALTER TABLE {CUTOVER_TABLE} ADD COLUMN pairing_epoch INTEGER NOT NULL DEFAULT 0"),
        [],
    );
    Ok(())
}

fn write_sqlite_generation(conn: &Connection, generation: i64) -> Result<(), String> {
    ensure_sqlite_cutover(conn)?;
    let fence_raised: i64 = conn
        .query_row(
            &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id=1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or(0);
    let pairing_epoch: i64 = conn
        .query_row(
            &format!("SELECT pairing_epoch FROM {CUTOVER_TABLE} WHERE id=1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or(0);
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {CUTOVER_TABLE}
             (id, generation, fence_raised, raised_at_ms, pairing_epoch)
             VALUES (1, ?1, ?2, ?3, ?4)"
        ),
        params![
            generation,
            fence_raised,
            chrono::Utc::now().timestamp_millis(),
            pairing_epoch
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn read_postgres_generation(db: &PostgresDb) -> Result<Option<i64>, String> {
    let mut conn = db.connection()?;
    match conn.query_opt(
        "SELECT generation FROM sekai_store_cutover WHERE id = 1",
        &[],
    ) {
        Ok(Some(row)) => Ok(Some(row.get(0))),
        Ok(None) => Ok(None),
        Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn write_postgres_generation(db: &PostgresDb, generation: i64) -> Result<(), String> {
    let mut conn = db.connection()?;
    conn.batch_execute(
        "CREATE TABLE IF NOT EXISTS sekai_store_cutover (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            generation BIGINT NOT NULL,
            fence_raised INTEGER NOT NULL,
            raised_at_ms BIGINT NOT NULL,
            pairing_epoch BIGINT NOT NULL DEFAULT 0
        );
        ALTER TABLE sekai_store_cutover
            ADD COLUMN IF NOT EXISTS pairing_epoch BIGINT NOT NULL DEFAULT 0;",
    )
    .map_err(|error| error.to_string())?;
    // fence_raised is INTEGER (int4); the postgres crate does not widen an
    // int4 column into an i64 read, so this must stay i32.
    let fence_raised: i32 = match conn.query_opt(
        "SELECT fence_raised FROM sekai_store_cutover WHERE id = 1",
        &[],
    ) {
        Ok(Some(row)) => row.get(0),
        Ok(None) => 0,
        Err(error) => return Err(error.to_string()),
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let pairing_epoch: i64 = match conn.query_opt(
        "SELECT pairing_epoch FROM sekai_store_cutover WHERE id = 1",
        &[],
    ) {
        Ok(Some(row)) => row.get(0),
        Ok(None) => 0,
        Err(_) => 0,
    };
    conn.execute(
        "INSERT INTO sekai_store_cutover (id, generation, fence_raised, raised_at_ms, pairing_epoch)
         VALUES (1, $1, $2, $3, $4)
         ON CONFLICT (id) DO UPDATE SET
            generation = EXCLUDED.generation,
            raised_at_ms = EXCLUDED.raised_at_ms,
            pairing_epoch = EXCLUDED.pairing_epoch",
        &[&generation, &fence_raised, &now_ms, &pairing_epoch],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn read_runtime_pairing_epoch(db: &RuntimeDb) -> Result<i64, String> {
    match db {
        RuntimeDb::Sqlite(_) => db.with_sqlite_conn(|conn| {
            ensure_sqlite_cutover(conn)?;
            Ok(conn
                .query_row(
                    &format!("SELECT pairing_epoch FROM {CUTOVER_TABLE} WHERE id=1"),
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(0))
        })?,
        RuntimeDb::Postgres(db) => {
            let mut conn = db.connection()?;
            match conn.query_opt(
                "SELECT pairing_epoch FROM sekai_store_cutover WHERE id = 1",
                &[],
            ) {
                Ok(Some(row)) => Ok(row.get(0)),
                Ok(None) => Ok(0),
                Err(error)
                    if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE)
                        || error.code() == Some(&postgres::error::SqlState::UNDEFINED_COLUMN) =>
                {
                    Ok(0)
                }
                Err(error) => Err(error.to_string()),
            }
        }
    }
}

fn write_runtime_pairing_epoch(db: &RuntimeDb, pairing_epoch: i64) -> Result<(), String> {
    match db {
        RuntimeDb::Sqlite(_) => db.with_sqlite_conn(|conn| {
            ensure_sqlite_cutover(conn)?;
            let generation: i64 = conn
                .query_row(
                    &format!("SELECT generation FROM {CUTOVER_TABLE} WHERE id=1"),
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(0);
            let fence_raised: i64 = conn
                .query_row(
                    &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id=1"),
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(0);
            conn.execute(
                &format!(
                    "INSERT OR REPLACE INTO {CUTOVER_TABLE}
                     (id, generation, fence_raised, raised_at_ms, pairing_epoch)
                     VALUES (1, ?1, ?2, ?3, ?4)"
                ),
                params![
                    generation,
                    fence_raised,
                    chrono::Utc::now().timestamp_millis(),
                    pairing_epoch
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })?,
        RuntimeDb::Postgres(db) => {
            let mut conn = db.connection()?;
            conn.batch_execute(
                "ALTER TABLE IF EXISTS sekai_store_cutover
                 ADD COLUMN IF NOT EXISTS pairing_epoch BIGINT NOT NULL DEFAULT 0;",
            )
            .ok();
            let now_ms = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "UPDATE sekai_store_cutover SET pairing_epoch = $1, raised_at_ms = $2 WHERE id = 1",
                &[&pairing_epoch, &now_ms],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        }
    }
}

fn list_chisei_tables(conn: &Connection, schema: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT name FROM {schema}.sqlite_master
             WHERE type='table' AND name LIKE 'chisei_%'
               AND name != '{JOURNAL_TABLE}'
             ORDER BY name"
        ))
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    let mut tables = Vec::new();
    for row in rows {
        tables.push(row.map_err(|error| error.to_string())?);
    }
    Ok(tables)
}

fn group_families(tables: &[String]) -> BTreeMap<String, Vec<String>> {
    let mut families = BTreeMap::new();
    for table in tables {
        families
            .entry(family_for(table).to_string())
            .or_insert_with(Vec::new)
            .push(table.clone());
    }
    families
}

fn family_for(table: &str) -> &'static str {
    if table.starts_with("chisei_budget_") {
        "budget"
    } else if table.starts_with("chisei_eval_")
        || table.starts_with("chisei_evaluator_")
        || table.starts_with("chisei_evaluation_")
    {
        "evaluation"
    } else if table.starts_with("chisei_portfolio_") {
        "portfolio"
    } else if table.starts_with("chisei_learning_") || table.starts_with("chisei_evolve_") {
        "learning"
    } else if table.starts_with("chisei_data_quality_") {
        "data-quality"
    } else if table.starts_with("chisei_gateway_") {
        "gateway"
    } else if table.starts_with("chisei_gunshi_") {
        "gunshi"
    } else if table.starts_with("chisei_operation_") {
        "receipts"
    } else if table.starts_with("chisei_governed_") {
        "governed-subject"
    } else if table.starts_with("chisei_sample_") {
        "sampling"
    } else {
        "chisei-remainder"
    }
}

fn family_completed(conn: &Connection, family: &str) -> Result<bool, String> {
    let status: Option<String> = conn
        .query_row(
            &format!("SELECT status FROM {JOURNAL_TABLE} WHERE family=?1"),
            params![family],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(status.as_deref() == Some("completed"))
}

fn ensure_dest_table(conn: &Connection, table: &str) -> Result<(), String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM main.sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(format!(
            "destination is missing {table}; initialize the Chisei store with the same schema before relocate"
        ))
    }
}

fn table_count(conn: &Connection, schema: &str, table: &str) -> Result<i64, String> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {schema}.{table}"),
        [],
        |row| row.get(0),
    )
    .map_err(|error| format!("count {schema}.{table}: {error}"))
}

fn raise_writer_fence(path: &str) -> Result<i64, String> {
    let generation = chrono::Utc::now().timestamp_millis();
    raise_writer_fence_with_generation(path, generation)?;
    Ok(generation)
}

fn raise_writer_fence_with_generation(path: &str, generation: i64) -> Result<(), String> {
    let conn = Connection::open(path).map_err(|error| error.to_string())?;
    ensure_sqlite_cutover(&conn)?;
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {CUTOVER_TABLE}
             (id, generation, fence_raised, raised_at_ms, pairing_epoch)
             VALUES (1, ?1, 1, ?2, 0)"
        ),
        params![generation, chrono::Utc::now().timestamp_millis()],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

impl serde::Serialize for RelocateReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RelocateReport", 3)?;
        state.serialize_field("families", &self.families)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("fence_raised", &self.fence_raised)?;
        state.end()
    }
}

impl serde::Serialize for FamilyReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FamilyReport", 5)?;
        state.serialize_field("family", &self.family)?;
        state.serialize_field("skipped", &self.skipped)?;
        state.serialize_field("tables", &self.tables)?;
        state.serialize_field("row_count", &self.row_count)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

/// Hook used after opening a layout so shared fenced files cannot become writers.
pub fn enforce_layout_writer_fence(layout: &CombinedStoreLayout) -> Result<(), String> {
    refuse_shared_writer_if_fenced(layout)
}

pub fn open_layout_or_fence(default_sqlite_path: &str) -> Result<CombinedStoreLayout, String> {
    let layout = CombinedStoreSources::from_env(default_sqlite_path)?.open()?;
    enforce_layout_writer_fence(&layout)?;
    align_split_generations(&layout)?;
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::budget::{BudgetTracker, PeriodType};
    use crate::db::store::ChiseiStore;
    use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};

    #[test]
    fn relocate_copies_budget_family_and_fences_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();

        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(source_s),
                source_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("relocate-user", 9_000, PeriodType::Daily)
            .unwrap();

        let report = relocate_sqlite(source_s, source_s, chisei_s).unwrap();
        assert!(report.fence_raised);
        assert!(
            report
                .families
                .iter()
                .any(|family| family.family == "budget" && !family.skipped && family.row_count > 0)
        );

        assert_eq!(
            BudgetTracker::new(ChiseiStore::open_sqlite(chisei_s))
                .get_usage("relocate-user")
                .max_tokens,
            9_000
        );
        assert!(writer_fence_raised(source_s).unwrap());

        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: source_s.into(),
            legacy_sqlite_path: Some(source_s.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("writer fence"), "{err}");
    }

    #[test]
    fn relocate_refuses_the_same_sekai_and_chisei_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let source_s = source.to_str().unwrap();
        std::fs::write(&source, []).unwrap();
        let err = relocate_sqlite(source_s, source_s, source_s).unwrap_err();
        assert!(err.contains("shared source"), "{err}");

        let linked = dir.path().join("linked.db");
        std::fs::hard_link(&source, &linked).unwrap();
        let linked_s = linked.to_str().unwrap();
        let hardlink_err = relocate_sqlite(source_s, source_s, linked_s).unwrap_err();
        assert!(
            hardlink_err.contains("shared source")
                || hardlink_err.contains("same physical destination"),
            "{hardlink_err}"
        );
    }

    #[test]
    fn relocate_is_restartable_from_completed_families() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(source_s),
                source_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("restart-user", 4_000, PeriodType::Daily)
            .unwrap();
        relocate_sqlite(source_s, source_s, chisei_s).unwrap();
        let second = relocate_sqlite(source_s, source_s, chisei_s).unwrap();
        assert!(
            second
                .families
                .iter()
                .filter(|family| family.family == "budget")
                .all(|family| family.skipped)
        );
        assert_eq!(
            BudgetTracker::new(ChiseiStore::open_sqlite(chisei_s))
                .get_usage("restart-user")
                .max_tokens,
            4_000
        );
        assert!(!Path::new(&relocate_snapshot_path(chisei_s)).exists());
    }

    #[test]
    fn relocate_snapshots_source_and_fences_before_family_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let sekai_s = sekai.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(source_s),
                source_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("snapshot-user", 3_000, PeriodType::Daily)
            .unwrap();
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(sekai_s),
                sekai_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(chisei_s),
                chisei_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();

        let snapshot = relocate_snapshot_path(chisei_s);
        snapshot_sqlite(source_s, &snapshot).unwrap();
        let generation = raise_writer_fence(source_s).unwrap();
        assert!(writer_fence_raised(source_s).unwrap());
        assert_eq!(
            BudgetTracker::new(ChiseiStore::open_sqlite(chisei_s))
                .get_usage("snapshot-user")
                .max_tokens,
            0
        );

        let reports = copy_chisei_families_from_snapshot(&snapshot, chisei_s).unwrap();
        assert!(
            reports
                .iter()
                .any(|family| family.family == "budget" && family.row_count > 0)
        );
        raise_writer_fence_with_generation(sekai_s, generation).unwrap();
        raise_writer_fence_with_generation(chisei_s, generation).unwrap();
        remove_sqlite_sidecar(&snapshot);
        assert_eq!(
            BudgetTracker::new(ChiseiStore::open_sqlite(chisei_s))
                .get_usage("snapshot-user")
                .max_tokens,
            3_000
        );
    }

    #[test]
    fn same_source_and_destination_is_refused() {
        let err = relocate_sqlite("shared.db", "shared.db", "shared.db").unwrap_err();
        assert!(err.contains("shared source"), "{err}");
    }

    #[test]
    fn relocate_refuses_a_distinct_sekai_path() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        std::fs::write(&source, []).unwrap();
        std::fs::write(&sekai, []).unwrap();
        std::fs::write(&chisei, []).unwrap();
        let err = relocate_sqlite(
            source.to_str().unwrap(),
            sekai.to_str().unwrap(),
            chisei.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(err.contains("distinct --sekai"), "{err}");
    }

    fn open_shared(path: &str) -> CombinedStoreLayout {
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(path),
                path,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: path.into(),
            legacy_sqlite_path: Some(path.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap()
    }

    fn open_dest_pair(sekai: &str, chisei: &str) -> CombinedStoreLayout {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: sekai.into(),
            sekai_sqlite_path: Some(sekai.into()),
            chisei_sqlite_path: Some(chisei.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap()
    }

    #[test]
    fn compare_split_generations_classifies_pairs() {
        assert_eq!(
            compare_split_generations(None, None),
            SplitGenerationState::Unstamped
        );
        assert_eq!(
            compare_split_generations(Some(7), Some(7)),
            SplitGenerationState::Matched { generation: 7 }
        );
        assert_eq!(
            compare_split_generations(Some(7), Some(8)),
            SplitGenerationState::Mismatched {
                sekai: Some(7),
                chisei: Some(8)
            }
        );
        assert_eq!(
            compare_split_generations(Some(7), None),
            SplitGenerationState::Mismatched {
                sekai: Some(7),
                chisei: None
            }
        );
        assert!(compare_split_generations(Some(1), Some(2)).refuses_mutations());
        assert!(!compare_split_generations(Some(1), Some(1)).refuses_mutations());
        assert!(SplitGenerationState::Unattested.refuses_mutations());
        assert!(!SplitGenerationState::Unstamped.refuses_mutations());
    }

    #[test]
    fn mutating_rpc_names_are_classified() {
        assert!(is_mutating_rpc("SubmitActionInstance"));
        assert!(is_mutating_rpc("/sekai.SekaiService/SubmitActionInstance"));
        assert!(is_mutating_rpc("PutGovernedActionType"));
        assert!(is_mutating_rpc("RecordDecision"));
        assert!(!is_mutating_rpc("GetActionInstance"));
        assert!(!is_mutating_rpc("ListGrants"));
        assert!(!is_mutating_rpc("EvaluateObjectSet"));
        assert!(is_mutating_rpc("PreviewObjectAction"));
        assert!(is_mutating_rpc("/sekai.SekaiService/PreviewObjectAction"));
        assert!(!is_mutating_rpc("DescribeObjectAction"));
        assert!(!is_mutating_rpc("CheckAccess"));
    }

    fn insert_sekai_object(layout: &CombinedStoreLayout, object_id: &str) {
        layout
            .sekai_runtime()
            .with_sqlite_conn(|conn| {
                conn.execute(
                    "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated)
                     VALUES (?1, 'thing', 'n', 'ns', 'ext', '{}', 1, 1)",
                    params![object_id],
                )
            })
            .unwrap()
            .unwrap();
    }

    fn insert_action_instance(layout: &CombinedStoreLayout, instance_id: &str) {
        layout
            .sekai_runtime()
            .put_action_instance(&ActionInstance {
                instance_id: instance_id.into(),
                namespace: "ns".into(),
                type_id: "type-1043".into(),
                version: "1".into(),
                principal: "root".into(),
                parameters_json: "{}".into(),
                request_digest: format!("digest-{instance_id}"),
                idempotency_key: format!("idem-{instance_id}"),
                operation_id: format!("op-{instance_id}"),
                status: STATUS_ADMITTED.into(),
                deny_reason: String::new(),
                evidence_submission_ids: vec![],
                policy_decision: String::new(),
                budget_decision: String::new(),
                created_at_ms: 1,
                decided_at_ms: 1,
                system_one_fill_json: String::new(),
            })
            .unwrap();
    }

    fn wipe_cutover(layout: &CombinedStoreLayout) {
        for runtime in [layout.sekai_runtime(), layout.chisei_runtime()] {
            runtime
                .with_sqlite_conn(|conn| {
                    conn.execute_batch(&format!("DROP TABLE IF EXISTS {CUTOVER_TABLE}"))
                })
                .unwrap()
                .unwrap();
        }
        layout.invalidate_matched_generation();
    }

    #[test]
    fn dest_pair_aligns_empty_generations_and_allows_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        let aligned = align_split_generations(&layout).unwrap();
        assert!(matches!(aligned, SplitGenerationState::Matched { .. }));
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(
            read_runtime_generation(&layout.sekai_runtime()).unwrap(),
            read_runtime_generation(&layout.chisei_runtime()).unwrap()
        );
    }

    #[test]
    fn dual_unstamped_with_facts_refuses_until_restamp() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        insert_sekai_object(&layout, "obj-1043");
        BudgetTracker::new(ChiseiStore::from_shared_runtime(layout.chisei_runtime()))
            .set_limit("unattested-user", 100, PeriodType::Daily)
            .unwrap();
        wipe_cutover(&layout);

        assert_eq!(
            split_generation_state(&layout).unwrap(),
            SplitGenerationState::Unattested
        );
        assert!(
            read_runtime_generation(&layout.sekai_runtime())
                .unwrap()
                .is_none()
        );
        assert!(
            read_runtime_generation(&layout.chisei_runtime())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            align_split_generations(&layout).unwrap(),
            SplitGenerationState::Unattested
        );
        assert!(
            read_runtime_generation(&layout.sekai_runtime())
                .unwrap()
                .is_none()
        );
        let err = refuse_mutating_if_generation_mismatch(&layout).unwrap_err();
        assert!(err.contains("operator facts"), "{err}");
        assert!(err.contains("restamp"), "{err}");
        restamp_split_generation(&layout).unwrap();
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
    }

    #[test]
    fn dual_unstamped_with_only_action_instance_facts_refuses_until_restamp() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        // No sekai_objects/grants/links/decisions rows: only a live action
        // instance. The pre-#1103 misspelled table name counted zero facts
        // here and Matched despite this live row.
        insert_action_instance(&layout, "instance-1103");
        wipe_cutover(&layout);

        assert_eq!(
            split_generation_state(&layout).unwrap(),
            SplitGenerationState::Unattested
        );
        assert_eq!(
            align_split_generations(&layout).unwrap(),
            SplitGenerationState::Unattested
        );
        let err = refuse_mutating_if_generation_mismatch(&layout).unwrap_err();
        assert!(err.contains("operator facts"), "{err}");
        assert!(err.contains("restamp"), "{err}");
        restamp_split_generation(&layout).unwrap();
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
    }

    #[test]
    fn matched_generation_is_read_once_per_admit_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        align_split_generations(&layout).unwrap();
        GENERATION_READS.with(|reads| reads.set(0));
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.with(|reads| reads.replace(0)), 2);
        for _ in 0..8 {
            refuse_mutating_if_generation_mismatch(&layout).unwrap();
        }
        assert_eq!(GENERATION_READS.with(|reads| reads.get()), 0);
        layout.invalidate_matched_generation();
        GENERATION_READS.with(|reads| reads.set(0));
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.with(|reads| reads.replace(0)), 2);
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.with(|reads| reads.get()), 0);
    }

    #[test]
    fn one_sided_restore_refuses_mutations_until_restamp() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        align_split_generations(&layout).unwrap();
        write_runtime_generation(&layout.sekai_runtime(), 11).unwrap();
        write_runtime_generation(&layout.chisei_runtime(), 22).unwrap();
        let err = refuse_mutating_if_generation_mismatch(&layout).unwrap_err();
        assert!(err.contains("split generations disagree"), "{err}");
        assert!(err.contains("restamp"), "{err}");
        restamp_split_generation(&layout).unwrap();
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(
            read_runtime_generation(&layout.sekai_runtime()).unwrap(),
            read_runtime_generation(&layout.chisei_runtime()).unwrap()
        );
    }

    #[test]
    fn same_generation_one_sided_restore_refuses_until_restamp() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let backup = dir.path().join("sekai.bak");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        align_split_generations(&layout).unwrap();
        drop(layout);
        std::fs::copy(&sekai, &backup).unwrap();
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        drop(layout);
        std::fs::copy(&backup, &sekai).unwrap();
        let restored = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        assert_eq!(
            read_runtime_generation(&restored.sekai_runtime()).unwrap(),
            read_runtime_generation(&restored.chisei_runtime()).unwrap()
        );
        let err = refuse_mutating_if_generation_mismatch(&restored).unwrap_err();
        assert!(err.contains("pairing epochs"), "{err}");
        restamp_split_generation(&restored).unwrap();
        refuse_mutating_if_generation_mismatch(&restored).unwrap();
    }

    #[test]
    fn missing_generation_on_one_store_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        write_runtime_generation(&layout.sekai_runtime(), 9).unwrap();
        let state = split_generation_state(&layout).unwrap();
        assert_eq!(
            state,
            SplitGenerationState::Mismatched {
                sekai: Some(9),
                chisei: None
            }
        );
        assert!(
            refuse_mutating_if_generation_mismatch(&layout)
                .unwrap_err()
                .contains("restamp")
        );
    }

    #[test]
    fn shared_layout_does_not_compare_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        let layout = open_shared(path.to_str().unwrap());
        assert_eq!(
            split_generation_state_with_peer(&layout, None).unwrap(),
            SplitGenerationState::Shared
        );
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
    }

    #[test]
    fn stamped_shared_layout_refuses_without_a_matching_peer() {
        let dir = tempfile::tempdir().unwrap();
        let owned = dir.path().join("owned.db");
        let peer = dir.path().join("peer.db");
        let owned_s = owned.to_str().unwrap();
        let peer_s = peer.to_str().unwrap();
        let layout = open_shared(owned_s);
        write_runtime_generation(&layout.sekai_runtime(), 11).unwrap();
        assert_eq!(
            split_generation_state_with_peer(&layout, None).unwrap(),
            SplitGenerationState::Mismatched {
                sekai: Some(11),
                chisei: None
            }
        );
        let peer_layout = open_shared(peer_s);
        write_runtime_generation(&peer_layout.sekai_runtime(), 11).unwrap();
        assert_eq!(
            split_generation_state_with_peer(&layout, Some(peer_s)).unwrap(),
            SplitGenerationState::Matched { generation: 11 }
        );
        write_runtime_generation(&peer_layout.sekai_runtime(), 12).unwrap();
        let mismatch = split_generation_state_with_peer(&layout, Some(peer_s)).unwrap();
        assert!(mismatch.refuses_mutations(), "{mismatch:?}");
    }

    #[test]
    fn relocate_stamps_the_same_generation_on_both_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(source_s),
                source_s,
                None,
                16,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let report = relocate_sqlite(source_s, source_s, chisei.to_str().unwrap()).unwrap();
        let layout = open_dest_pair(source_s, chisei.to_str().unwrap());
        assert_eq!(
            split_generation_state(&layout).unwrap(),
            SplitGenerationState::Matched {
                generation: report.generation
            }
        );
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
    }

    #[test]
    fn restamp_cli_rewrites_a_mismatched_sqlite_pair() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let sekai_s = sekai.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        let layout = open_dest_pair(sekai_s, chisei_s);
        write_runtime_generation(&layout.sekai_runtime(), 1).unwrap();
        write_runtime_generation(&layout.chisei_runtime(), 2).unwrap();
        drop(layout);
        let generation = restamp_destinations(sekai_s, chisei_s).unwrap();
        let reopened = open_dest_pair(sekai_s, chisei_s);
        assert_eq!(
            split_generation_state(&reopened).unwrap(),
            SplitGenerationState::Matched { generation }
        );
    }

    #[test]
    fn relocate_refuses_mixed_sqlite_and_postgres_arguments() {
        let err = relocate(
            "legacy.db",
            "postgres://alice@localhost:5432/sekai",
            "postgres://alice@localhost:5432/chisei",
        )
        .unwrap_err();
        assert!(
            err.contains("three SQLite paths or three PostgreSQL URLs"),
            "{err}"
        );
    }

    #[test]
    fn relocate_postgres_refuses_a_distinct_sekai_url() {
        let err = relocate(
            "postgres://alice@localhost:5432/source",
            "postgres://alice@localhost:5432/sekai",
            "postgres://alice@localhost:5432/chisei",
        )
        .unwrap_err();
        assert!(err.contains("distinct --sekai"), "{err}");
    }

    #[test]
    fn relocate_postgres_refuses_the_same_source_and_chisei() {
        let err = relocate(
            "postgres://alice@127.0.0.1:5432/shared",
            "postgres://alice@localhost:5432/shared",
            "postgres://bob@localhost:5432/shared",
        )
        .unwrap_err();
        assert!(
            err.contains("shared source and Chisei destination"),
            "{err}"
        );
    }

    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    #[test]
    fn postgres_generation_roundtrip_covers_the_fence() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
        let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let pem = std::fs::read(&path).expect("read PostgreSQL test CA certificate");
            PostgresDb::connect_with_ca_certificate(&url, 4, &pem).unwrap()
        } else {
            PostgresDb::connect(&url, 4).unwrap()
        };
        let runtime = RuntimeDb::Postgres(std::sync::Arc::new(db));
        write_runtime_generation(&runtime, 41).unwrap();
        assert_eq!(read_runtime_generation(&runtime).unwrap(), Some(41));
        write_runtime_generation(&runtime, 42).unwrap();
        assert_eq!(read_runtime_generation(&runtime).unwrap(), Some(42));
        assert!(
            !postgres_writer_fence_raised(match &runtime {
                RuntimeDb::Postgres(db) => db,
                RuntimeDb::Sqlite(_) => panic!("expected postgres"),
            })
            .unwrap()
        );
        raise_postgres_writer_fence_with_generation(
            match &runtime {
                RuntimeDb::Postgres(db) => db,
                RuntimeDb::Sqlite(_) => panic!("expected postgres"),
            },
            42,
        )
        .unwrap();
        assert!(
            postgres_writer_fence_raised(match &runtime {
                RuntimeDb::Postgres(db) => db,
                RuntimeDb::Sqlite(_) => panic!("expected postgres"),
            })
            .unwrap()
        );
        assert!(compare_split_generations(Some(42), Some(41)).refuses_mutations());
        assert!(!compare_split_generations(Some(42), Some(42)).refuses_mutations());
    }

    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    #[test]
    fn greenfield_postgres_fence_then_generation_stamp_succeeds() {
        // #1105: raise_postgres_writer_fence's CREATE previously omitted
        // pairing_epoch while its INSERT named it, so a truly greenfield
        // database (fence raised before any generation write ever created the
        // table) failed the INSERT with "column pairing_epoch does not
        // exist". Explicitly drop first: another test in this binary may have
        // already created the table against the same SEKAI_TEST_POSTGRES_URL.
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
        let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let pem = std::fs::read(&path).expect("read PostgreSQL test CA certificate");
            PostgresDb::connect_with_ca_certificate(&url, 4, &pem).unwrap()
        } else {
            PostgresDb::connect(&url, 4).unwrap()
        };
        db.connection()
            .unwrap()
            .batch_execute("DROP TABLE IF EXISTS sekai_store_cutover;")
            .unwrap();

        raise_postgres_writer_fence_with_generation(&db, 7).unwrap();
        assert!(postgres_writer_fence_raised(&db).unwrap());

        let runtime = RuntimeDb::Postgres(std::sync::Arc::new(db));
        write_runtime_generation(&runtime, 7).unwrap();
        assert_eq!(read_runtime_generation(&runtime).unwrap(), Some(7));
        assert_eq!(read_runtime_pairing_epoch(&runtime).unwrap(), 0);
    }
}
