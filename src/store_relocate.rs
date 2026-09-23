//! Online, restartable Chisei-family relocation and writer fence.
//!
//! Install write capture on every Chisei table of the historical source,
//! snapshot it, and bulk-copy each Chisei-owned family from that snapshot
//! while writers keep running. Then raise the writer fence in the source
//! database itself (capture triggers refuse Chisei writes from then on),
//! re-copy only the families written since the capture began, and stamp the
//! destinations. The refuse window covers the dirty families, not the full
//! family load. Capture changes the source from the start, so the rollback
//! point is a copy taken before the run.
//!
//! Destination pairs also carry a split generation. Combined split open
//! compares the pair. Dual-unstamped stores auto-stamp only when both are
//! empty; operator facts without a cutover stay unattested until restamp.
//! A Shared or owned-plane open of a stamped store compares
//! `SEKAI_STORE_PEER` (read-only) or refuses mutations until an operator
//! restamp. Independent backups are not a paired restore set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::combined_stores::{CombinedStoreLayout, CombinedStoreSources, StoreIdentity};
use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::runtime_backend::{BackendIdentity, RuntimeBackend, RuntimeBackendConfig};

const CUTOVER_TABLE: &str = "sekai_store_cutover";
const JOURNAL_TABLE: &str = "chisei_relocate_families";
/// Single-row gate on the source that capture triggers read on every Chisei
/// write; `fenced = 1` makes the triggers refuse the write.
const CAPTURE_GATE_TABLE: &str = "sekai_relocate_capture";
/// Source Chisei tables written since capture was installed.
const CAPTURE_DIRTY_TABLE: &str = "sekai_relocate_dirty";
const FENCED_WRITE_MESSAGE: &str = "writer fence raised: Chisei families moved to the Chisei store";

#[cfg(test)]
thread_local! {
    static GENERATION_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PAIRING_EPOCH_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PAIRING_EPOCH_WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocateReport {
    pub families: Vec<FamilyReport>,
    /// Families copied again under the fence because a writer touched them
    /// after capture began.
    pub recopied: Vec<FamilyReport>,
    pub generation: i64,
    pub fence_raised: bool,
    /// Wall time from raising the source fence to stamping both destinations.
    pub fence_window_ms: u64,
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
    "sekaictl admin store relocate --source <path-or-url> --sekai <path-or-url> --chisei <path-or-url>\n  Online copy of Chisei families from the historical single store into the Chisei destination. Three SQLite paths or three PostgreSQL URLs. --sekai must be the same physical identity as --source. Captures source writes, bulk-copies families from a snapshot while writers run, then fences Chisei writes in the source database and re-copies only the families written during the copy. Restartable per family. Capture changes the source from the start; roll back from a copy taken before the run.\n\
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

    relocate_sqlite_online(source, sekai, chisei, || Ok(()))
}

/// `before_fence` runs between the unfenced bulk copy and the fence, where
/// live writers may still land on the source.
fn relocate_sqlite_online(
    source: &str,
    sekai: &str,
    chisei: &str,
    before_fence: impl FnOnce() -> Result<(), String>,
) -> Result<RelocateReport, String> {
    let _lock = lock_relocate_destination(chisei)?;
    let captured = install_sqlite_change_capture(source)?;
    let snapshot = relocate_snapshot_path(chisei);
    snapshot_sqlite(source, &snapshot)?;
    let families = copy_chisei_families_from_snapshot(&snapshot, chisei)?;
    remove_sqlite_sidecar(&snapshot);
    before_fence()?;

    let fenced_at = std::time::Instant::now();
    let generation = raise_sqlite_source_fence(source, chisei)?;
    let dirty = sqlite_dirty_families(source, &captured)?;
    // Reads the live source: safe only because the gate is closed, so the
    // capture triggers refuse every Chisei write while this copy and its
    // row-count validation run.
    let recopied = if dirty.is_empty() {
        Vec::new()
    } else {
        copy_chisei_families(source, chisei, Some(&dirty))?
    };
    clear_sqlite_dirty(source)?;
    raise_writer_fence_with_generation(sekai, generation)?;
    raise_writer_fence_with_generation(chisei, generation)?;

    Ok(RelocateReport {
        families,
        recopied,
        generation,
        fence_raised: true,
        fence_window_ms: elapsed_ms(fenced_at),
    })
}

fn elapsed_ms(since: std::time::Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Opens the live source with a busy timeout: capture and fence DDL wait for
/// running writers instead of failing on the first lock conflict.
fn open_live_sqlite(path: &str) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|error| error.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    Ok(conn)
}

fn checked_table_name(table: &str) -> Result<&str, String> {
    if !table.is_empty()
        && table
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        Ok(table)
    } else {
        Err(format!("refusing unexpected table name {table}"))
    }
}

/// Installs capture triggers on every Chisei table of the SQLite source and
/// returns the captured tables. Idempotent: a restart keeps the gate state
/// and the dirty set of the interrupted run.
fn install_sqlite_change_capture(source: &str) -> Result<Vec<String>, String> {
    let conn = open_live_sqlite(source)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {CAPTURE_GATE_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            fenced INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO {CAPTURE_GATE_TABLE} (id, fenced) VALUES (1, 0);
        CREATE TABLE IF NOT EXISTS {CAPTURE_DIRTY_TABLE} (tbl TEXT PRIMARY KEY);"
    ))
    .map_err(|error| format!("install relocate capture: {error}"))?;
    let tables = list_chisei_tables(&conn, "main")?;
    for table in &tables {
        let table = checked_table_name(table)?;
        for (suffix, event) in [("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")] {
            // The dirty mark avoids an OR IGNORE clause: an outer statement's
            // conflict policy would override it inside the trigger.
            conn.execute_batch(&format!(
                "CREATE TRIGGER IF NOT EXISTS sekai_relocate_capture_{table}_{suffix}
                 BEFORE {event} ON {table}
                 BEGIN
                    SELECT RAISE(ABORT, '{FENCED_WRITE_MESSAGE}')
                    WHERE (SELECT fenced FROM {CAPTURE_GATE_TABLE} WHERE id = 1) = 1;
                    INSERT INTO {CAPTURE_DIRTY_TABLE} (tbl)
                    SELECT '{table}'
                    WHERE NOT EXISTS (SELECT 1 FROM {CAPTURE_DIRTY_TABLE} WHERE tbl = '{table}');
                 END;"
            ))
            .map_err(|error| format!("capture {table}: {error}"))?;
        }
    }
    Ok(tables)
}

/// Closes the capture gate and raises the cutover fence in one write
/// transaction, so every Chisei write either committed its dirty mark before
/// the fence or is refused by the capture triggers after it.
///
/// Refuses to fence when the destination lacks a source Chisei table, so a
/// table created during the copy fails the run while writers are unfenced.
/// The check holds the write lock `CREATE TABLE` also needs, so no table can
/// appear between the check and the fence.
fn raise_sqlite_source_fence(source: &str, chisei: &str) -> Result<i64, String> {
    let mut conn = open_live_sqlite(source)?;
    ensure_sqlite_cutover(&conn)?;
    let generation = chrono::Utc::now().timestamp_millis();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("begin source fence: {error}"))?;
    let dest = Connection::open(chisei).map_err(|error| error.to_string())?;
    for table in list_chisei_tables(&tx, "main")? {
        ensure_dest_table(&dest, &table)?;
    }
    tx.execute(
        &format!("UPDATE {CAPTURE_GATE_TABLE} SET fenced = 1 WHERE id = 1"),
        [],
    )
    .map_err(|error| format!("close capture gate: {error}"))?;
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO {CUTOVER_TABLE}
             (id, generation, fence_raised, raised_at_ms, pairing_epoch)
             VALUES (1, ?1, 1, ?2, 0)"
        ),
        params![generation, chrono::Utc::now().timestamp_millis()],
    )
    .map_err(|error| format!("raise source fence: {error}"))?;
    tx.commit()
        .map_err(|error| format!("commit source fence: {error}"))?;
    Ok(generation)
}

/// Families to copy again under the fence: tables marked dirty since capture
/// began, plus Chisei tables created after it (no trigger saw their writes).
fn sqlite_dirty_families(source: &str, captured: &[String]) -> Result<BTreeSet<String>, String> {
    let current = install_sqlite_change_capture(source)?;
    let conn = open_live_sqlite(source)?;
    let mut stmt = conn
        .prepare(&format!("SELECT tbl FROM {CAPTURE_DIRTY_TABLE}"))
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    let mut dirty = Vec::new();
    for row in rows {
        dirty.push(row.map_err(|error| error.to_string())?);
    }
    Ok(dirty_families(dirty, &current, captured))
}

fn dirty_families(dirty: Vec<String>, current: &[String], captured: &[String]) -> BTreeSet<String> {
    dirty
        .into_iter()
        .chain(
            current
                .iter()
                .filter(|table| !captured.contains(table))
                .cloned(),
        )
        .map(|table| family_for(&table).to_string())
        .collect()
}

fn clear_sqlite_dirty(source: &str) -> Result<(), String> {
    open_live_sqlite(source)?
        .execute(&format!("DELETE FROM {CAPTURE_DIRTY_TABLE}"), [])
        .map(|_| ())
        .map_err(|error| format!("clear relocate dirty set: {error}"))
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

    relocate_postgres_online(source, sekai, chisei, || Ok(()))
}

/// `before_fence` runs between the unfenced bulk copy and the fence, where
/// live writers may still land on the source.
fn relocate_postgres_online(
    source: &str,
    sekai: &str,
    chisei: &str,
    before_fence: impl FnOnce() -> Result<(), String>,
) -> Result<RelocateReport, String> {
    let _lock = lock_relocate_destination(chisei)?;
    let source_db = connect_postgres(source)?;
    let chisei_db = connect_postgres(chisei)?;
    let captured = install_postgres_change_capture(&source_db)?;
    let snapshot_dir = relocate_postgres_snapshot_dir(chisei);
    snapshot_postgres(&source_db, &snapshot_dir, None)?;
    let families = copy_chisei_families_from_postgres_snapshot(&snapshot_dir, &chisei_db, None)?;
    let _ = std::fs::remove_dir_all(&snapshot_dir);
    before_fence()?;

    let fenced_at = std::time::Instant::now();
    let generation = raise_postgres_source_fence(&source_db, &chisei_db)?;
    let dirty = postgres_dirty_families(&source_db, &captured)?;
    let recopied = if dirty.is_empty() {
        Vec::new()
    } else {
        let fenced_dir = format!("{snapshot_dir}-fenced");
        snapshot_postgres(&source_db, &fenced_dir, Some(&dirty))?;
        let recopied =
            copy_chisei_families_from_postgres_snapshot(&fenced_dir, &chisei_db, Some(&dirty))?;
        let _ = std::fs::remove_dir_all(&fenced_dir);
        recopied
    };
    source_db
        .connection()?
        .execute(&format!("DELETE FROM {CAPTURE_DIRTY_TABLE}"), &[])
        .map_err(|error| format!("clear relocate dirty set: {error}"))?;
    raise_postgres_writer_fence_with_generation(&connect_postgres(sekai)?, generation)?;
    raise_postgres_writer_fence_with_generation(&chisei_db, generation)?;

    Ok(RelocateReport {
        families,
        recopied,
        generation,
        fence_raised: true,
        fence_window_ms: elapsed_ms(fenced_at),
    })
}

/// Installs one statement-level capture trigger per Chisei table of the
/// PostgreSQL source and returns the captured tables. Each trigger takes a
/// share lock on the gate row for the rest of the writer's transaction, so
/// closing the gate waits for in-flight writers and every later write sees
/// the closed gate (READ COMMITTED) or fails to serialize (REPEATABLE READ).
fn install_postgres_change_capture(source: &PostgresDb) -> Result<Vec<String>, String> {
    let mut conn = source.connection()?;
    conn.batch_execute(&format!(
        "CREATE TABLE IF NOT EXISTS {CAPTURE_GATE_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            fenced INTEGER NOT NULL
        );
        INSERT INTO {CAPTURE_GATE_TABLE} (id, fenced) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
        CREATE TABLE IF NOT EXISTS {CAPTURE_DIRTY_TABLE} (tbl TEXT PRIMARY KEY);
        CREATE OR REPLACE FUNCTION sekai_relocate_capture_write() RETURNS trigger
        LANGUAGE plpgsql AS $capture$
        DECLARE
            gate INTEGER;
        BEGIN
            SELECT fenced INTO gate FROM {CAPTURE_GATE_TABLE} WHERE id = 1 FOR SHARE;
            IF gate = 1 THEN
                RAISE EXCEPTION '{FENCED_WRITE_MESSAGE}' USING ERRCODE = 'object_not_in_prerequisite_state';
            END IF;
            -- Read first: once a mark is committed, writers skip the row lock.
            IF NOT EXISTS (SELECT 1 FROM {CAPTURE_DIRTY_TABLE} WHERE tbl = TG_TABLE_NAME) THEN
                INSERT INTO {CAPTURE_DIRTY_TABLE} (tbl) VALUES (TG_TABLE_NAME)
                ON CONFLICT (tbl) DO NOTHING;
            END IF;
            RETURN NULL;
        END
        $capture$;"
    ))
    .map_err(|error| format!("install relocate capture: {error}"))?;
    let tables = list_postgres_chisei_tables(&mut *conn)?;
    for table in &tables {
        conn.batch_execute(&format!(
            "CREATE OR REPLACE TRIGGER sekai_relocate_capture
             BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {table}
             FOR EACH STATEMENT EXECUTE FUNCTION sekai_relocate_capture_write();"
        ))
        .map_err(|error| format!("capture {table}: {error}"))?;
    }
    Ok(tables)
}

fn ensure_postgres_cutover(conn: &mut postgres::Client) -> Result<(), String> {
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
    .map_err(|error| error.to_string())
}

const POSTGRES_FENCE_UPSERT: &str =
    "INSERT INTO sekai_store_cutover (id, generation, fence_raised, raised_at_ms, pairing_epoch)
     VALUES (1, $1, 1, $2, 0)
     ON CONFLICT (id) DO UPDATE SET
        generation = EXCLUDED.generation,
        fence_raised = 1,
        raised_at_ms = EXCLUDED.raised_at_ms,
        pairing_epoch = 0";

/// Closes the capture gate and raises the cutover fence in one transaction,
/// refusing to fence when the destination lacks a source Chisei table. A
/// table created concurrently with this check fails the fenced catch-up
/// instead; the kept dirty set lets a re-run finish after the destination
/// schema is initialized.
fn raise_postgres_source_fence(source: &PostgresDb, chisei: &PostgresDb) -> Result<i64, String> {
    let mut conn = source.connection()?;
    ensure_postgres_cutover(&mut conn)?;
    let generation = chrono::Utc::now().timestamp_millis();
    let mut tx = conn
        .transaction()
        .map_err(|error| format!("begin source fence: {error}"))?;
    let mut dest = chisei.connection()?;
    for table in list_postgres_chisei_tables(&mut tx)? {
        ensure_postgres_dest_table(&mut dest, &table)?;
    }
    tx.execute(
        &format!("UPDATE {CAPTURE_GATE_TABLE} SET fenced = 1 WHERE id = 1"),
        &[],
    )
    .map_err(|error| format!("close capture gate: {error}"))?;
    tx.execute(
        POSTGRES_FENCE_UPSERT,
        &[&generation, &chrono::Utc::now().timestamp_millis()],
    )
    .map_err(|error| format!("raise source fence: {error}"))?;
    tx.commit()
        .map_err(|error| format!("commit source fence: {error}"))?;
    Ok(generation)
}

fn postgres_dirty_families(
    source: &PostgresDb,
    captured: &[String],
) -> Result<BTreeSet<String>, String> {
    let current = install_postgres_change_capture(source)?;
    let dirty = source
        .connection()?
        .query(&format!("SELECT tbl FROM {CAPTURE_DIRTY_TABLE}"), &[])
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect();
    Ok(dirty_families(dirty, &current, captured))
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

/// Held for a whole relocate run. The OS releases it when the process exits,
/// so a crashed run never blocks its resume (which reuses and cleans the same
/// snapshot path), while a concurrent run against the same destination is
/// refused before it can remove this run's snapshot.
fn lock_relocate_destination(chisei: &str) -> Result<std::fs::File, String> {
    let digest = format!("{:x}", md5_ish(chisei));
    let path = std::env::temp_dir().join(format!("sekai-relocate-{digest}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|error| format!("open relocate lock: {error}"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err("another relocate is running against this Chisei destination".into())
        }
        Err(std::fs::TryLockError::Error(error)) => {
            Err(format!("lock relocate destination: {error}"))
        }
    }
}

fn md5_ish(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Writes one `COPY` file per Chisei table from a single `REPEATABLE READ`
/// snapshot. `only` restricts the snapshot to those families.
fn snapshot_postgres(
    source: &PostgresDb,
    snapshot_dir: &str,
    only: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(snapshot_dir);
    std::fs::create_dir_all(snapshot_dir).map_err(|error| error.to_string())?;
    let mut conn = source.connection()?;
    conn.batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .map_err(|error| format!("begin postgres snapshot: {error}"))?;
    let mut tables = list_postgres_chisei_tables(&mut *conn)?;
    if let Some(only) = only {
        tables.retain(|table| only.contains(family_for(table)));
    }
    let mut listing = Vec::new();
    for table in &tables {
        // Counted inside the same snapshot so the load can fail closed.
        let source_count = postgres_table_count(&mut conn, table)?;
        let path = std::path::Path::new(snapshot_dir).join(table);
        let mut file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
        let mut reader = conn
            .copy_out(&format!("COPY {table} TO STDOUT"))
            .map_err(|error| format!("snapshot {table}: {error}"))?;
        std::io::copy(&mut reader, &mut file)
            .map_err(|error| format!("write {table} snapshot: {error}"))?;
        listing.push(format!("{table}\t{source_count}"));
    }
    conn.batch_execute("COMMIT")
        .map_err(|error| format!("commit postgres snapshot: {error}"))?;
    std::fs::write(
        std::path::Path::new(snapshot_dir).join("tables.txt"),
        listing.join("\n"),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn list_postgres_chisei_tables(
    conn: &mut impl postgres::GenericClient,
) -> Result<Vec<String>, String> {
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

/// `only` restricts the copy to those families and re-copies them even when
/// the journal already records them as completed.
fn copy_chisei_families_from_postgres_snapshot(
    snapshot_dir: &str,
    dest: &PostgresDb,
    only: Option<&BTreeSet<String>>,
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
    let mut source_counts = BTreeMap::new();
    for line in listing.lines().filter(|line| !line.is_empty()) {
        let (table, count) = line
            .split_once('\t')
            .ok_or_else(|| format!("malformed relocate snapshot listing line {line}"))?;
        let count: i64 = count
            .parse()
            .map_err(|_| format!("malformed relocate snapshot count for {table}"))?;
        source_counts.insert(table.to_string(), count);
    }
    let tables: Vec<String> = source_counts.keys().cloned().collect();
    let families = group_families(&tables);
    let mut reports = Vec::new();
    for (family, family_tables) in families {
        if only.is_some_and(|only| !only.contains(&family)) {
            continue;
        }
        if only.is_none() && postgres_family_completed(&mut conn, &family)? {
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
            let source_count = source_counts[table];
            if source_count != dest_count {
                return Err(format!(
                    "relocate validation failed for {table}: source count {source_count} != destination count {dest_count}"
                ));
            }
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
    let conn = open_live_sqlite(source)?;
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
    copy_chisei_families(snapshot, chisei, None)
}

/// Copies Chisei families from the SQLite file at `origin` into `chisei`.
/// `only` restricts the copy to those families and re-copies them even when
/// the journal already records them as completed.
fn copy_chisei_families(
    origin: &str,
    chisei: &str,
    only: Option<&BTreeSet<String>>,
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
    dest.execute("ATTACH DATABASE ?1 AS src", params![origin])
        .map_err(|error| error.to_string())?;

    let tables = list_chisei_tables(&dest, "src")?;
    let families = group_families(&tables);
    let mut reports = Vec::new();
    for (family, family_tables) in families {
        if only.is_some_and(|only| !only.contains(&family)) {
            continue;
        }
        if only.is_none() && family_completed(&dest, &family)? {
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

fn raise_postgres_writer_fence_with_generation(
    db: &PostgresDb,
    generation: i64,
) -> Result<(), String> {
    let mut conn = db.connection()?;
    ensure_postgres_cutover(&mut conn)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    conn.execute(POSTGRES_FENCE_UPSERT, &[&generation, &now_ms])
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
        // #1108: on a matched-generation cache hit this still dual-reads the
        // pairing epoch on every mutating RPC — it is the only check left
        // that can still catch a one-sided restore while the coarser
        // generation recheck is skipped from cache, so the read stays. What
        // is avoidable is `advance_pairing_epoch` re-reading both stores a
        // second time just to recompute the value `matched_pairing_epoch`
        // already read: reuse it instead.
        match matched_pairing_epoch(layout)? {
            Some(current) => {
                advance_pairing_epoch_from(layout, current)?;
                return Ok(());
            }
            None => layout.invalidate_matched_generation(),
        }
    }
    match split_generation_state(layout)? {
        SplitGenerationState::Mismatched { sekai, chisei } => {
            Err(generation_mismatch_guidance(sekai, chisei))
        }
        SplitGenerationState::Unattested => Err(unattested_guidance()),
        SplitGenerationState::Matched { generation } => match matched_pairing_epoch(layout)? {
            Some(current) => {
                layout.cache_matched_generation(generation);
                advance_pairing_epoch_from(layout, current)?;
                Ok(())
            }
            None => Err(pairing_epoch_guidance()),
        },
        _ => Ok(()),
    }
}

fn pairing_epoch_guidance() -> String {
    "split pairing epochs disagree after a one-sided restore; mutating RPCs stay refused until an operator restamps both stores with `sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>`. Equal cutover generation is not a pairing proof".into()
}

fn unattested_guidance() -> String {
    "split stores hold operator facts without a cutover generation; mutating RPCs stay refused until an operator restamps both stores with `sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>`. Dual-unstamped is not a green-field pair".into()
}

/// #1108: kept for the ignored Postgres regression tests that call this
/// exact pair of functions directly to exercise `advance_pairing_epoch`'s
/// own read-then-write. Production code now goes through
/// [`matched_pairing_epoch`] / [`advance_pairing_epoch_from`] instead, which
/// skip the redundant second read.
#[cfg(test)]
fn pairing_epochs_match(layout: &CombinedStoreLayout) -> Result<bool, String> {
    if !layout.is_split() {
        return Ok(true);
    }
    Ok(read_runtime_pairing_epoch(&layout.sekai_runtime())?
        == read_runtime_pairing_epoch(&layout.chisei_runtime())?)
}

#[cfg(test)]
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

/// #1108: like [`pairing_epochs_match`], but returns the matched value
/// itself so a caller that is about to advance can reuse it instead of
/// paying [`advance_pairing_epoch`]'s own dual read to recompute the same
/// number. `Ok(None)` means the epochs disagree. Shared layouts have no
/// pairing epoch to disagree on — matching `pairing_epochs_match`, this
/// reports a trivial match; the placeholder value is never written, since
/// [`advance_pairing_epoch_from`] no-ops on a Shared layout too.
fn matched_pairing_epoch(layout: &CombinedStoreLayout) -> Result<Option<i64>, String> {
    if !layout.is_split() {
        return Ok(Some(0));
    }
    let sekai = read_runtime_pairing_epoch(&layout.sekai_runtime())?;
    let chisei = read_runtime_pairing_epoch(&layout.chisei_runtime())?;
    Ok((sekai == chisei).then_some(sekai))
}

/// Advance from an already-known matched epoch (see [`matched_pairing_epoch`]).
/// Semantically identical to [`advance_pairing_epoch`] — same next value,
/// same two writes — it only skips recomputing `current` from a fresh read.
fn advance_pairing_epoch_from(layout: &CombinedStoreLayout, current: i64) -> Result<(), String> {
    if !layout.is_split() {
        return Ok(());
    }
    let next = current.saturating_add(1);
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
    #[cfg(test)]
    PAIRING_EPOCH_READS.with(|reads| reads.set(reads.get().saturating_add(1)));
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
    #[cfg(test)]
    PAIRING_EPOCH_WRITES.with(|writes| writes.set(writes.get().saturating_add(1)));
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
            // A missing schema/column failure must not be silently discarded:
            // it would surface later only as a confusing "column does not
            // exist" on the UPDATE below, or not at all if the column already
            // existed for an unrelated reason.
            conn.batch_execute(
                "ALTER TABLE IF EXISTS sekai_store_cutover
                 ADD COLUMN IF NOT EXISTS pairing_epoch BIGINT NOT NULL DEFAULT 0;",
            )
            .map_err(|error| error.to_string())?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let updated = conn
                .execute(
                    "UPDATE sekai_store_cutover SET pairing_epoch = $1, raised_at_ms = $2 WHERE id = 1",
                    &[&pairing_epoch, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            // An UPDATE that matches no row returns Ok with an affected count
            // of 0, not an error. Silently accepting that would let one side
            // of a split pair advance while the other no-ops, leaving the
            // pairing epoch one-sided and stale with no signal to the caller.
            if updated != 1 {
                return Err(format!(
                    "pairing epoch stamp affected {updated} rows, expected exactly 1; \
                     sekai_store_cutover has no id=1 row on this store (it has not been \
                     generation-stamped yet). Failing closed instead of a silent no-op"
                ));
            }
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

fn raise_writer_fence_with_generation(path: &str, generation: i64) -> Result<(), String> {
    let conn = open_live_sqlite(path)?;
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
        let mut state = serializer.serialize_struct("RelocateReport", 5)?;
        state.serialize_field("families", &self.families)?;
        state.serialize_field("recopied", &self.recopied)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("fence_raised", &self.fence_raised)?;
        state.serialize_field("fence_window_ms", &self.fence_window_ms)?;
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

    fn init_sqlite(path: &str) {
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
    }

    fn budget_limit(path: &str, user: &str) -> i32 {
        BudgetTracker::new(ChiseiStore::open_sqlite(path))
            .get_usage(user)
            .max_tokens
    }

    #[test]
    fn relocate_recopies_only_families_written_during_the_bulk_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        init_sqlite(source_s);
        init_sqlite(chisei_s);
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("before-copy", 3_000, PeriodType::Daily)
            .unwrap();

        let report = relocate_sqlite_online(source_s, source_s, chisei_s, || {
            // A live writer lands after the snapshot the bulk copy read.
            BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
                .set_limit("during-copy", 5_000, PeriodType::Daily)
                .map_err(|error| error.to_string())?;
            assert_eq!(budget_limit(chisei_s, "before-copy"), 3_000);
            assert_eq!(budget_limit(chisei_s, "during-copy"), 0);
            Ok(())
        })
        .unwrap();

        assert_eq!(budget_limit(chisei_s, "before-copy"), 3_000);
        assert_eq!(budget_limit(chisei_s, "during-copy"), 5_000);
        let recopied: Vec<&str> = report
            .recopied
            .iter()
            .map(|family| family.family.as_str())
            .collect();
        assert_eq!(recopied, ["budget"]);
        assert!(report.families.len() > 1);
    }

    #[test]
    fn relocate_without_concurrent_writes_recopies_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        init_sqlite(source_s);
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("quiet-user", 2_000, PeriodType::Daily)
            .unwrap();
        let report = relocate_sqlite(source_s, source_s, chisei.to_str().unwrap()).unwrap();
        assert!(report.recopied.is_empty());
    }

    #[test]
    fn the_source_database_refuses_chisei_writes_after_the_fence() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        init_sqlite(source_s);
        relocate_sqlite(source_s, source_s, chisei_s).unwrap();

        // A Shared writer that was already running when the fence rose.
        let err = BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("late-writer", 1_000, PeriodType::Daily)
            .unwrap_err()
            .to_string();
        assert!(err.contains("writer fence raised"), "{err}");

        // The destination and restarted relocates stay writable.
        BudgetTracker::new(ChiseiStore::open_sqlite(chisei_s))
            .set_limit("split-writer", 1_000, PeriodType::Daily)
            .unwrap();
        let rerun = relocate_sqlite(source_s, source_s, chisei_s).unwrap();
        assert!(rerun.recopied.is_empty());
        assert_eq!(budget_limit(chisei_s, "split-writer"), 1_000);
    }

    #[test]
    fn a_chisei_table_missing_from_the_destination_fails_before_the_fence() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        init_sqlite(source_s);
        init_sqlite(chisei_s);
        let err = relocate_sqlite_online(source_s, source_s, chisei_s, || {
            Connection::open(source_s)
                .unwrap()
                .execute_batch("CREATE TABLE chisei_budget_added_mid_copy (id INTEGER);")
                .map_err(|error| error.to_string())
        })
        .unwrap_err();
        assert!(err.contains("chisei_budget_added_mid_copy"), "{err}");
        assert!(!writer_fence_raised(source_s).unwrap());
        BudgetTracker::new(ChiseiStore::open_sqlite(source_s))
            .set_limit("still-unfenced", 1_000, PeriodType::Daily)
            .unwrap();
    }

    #[test]
    fn a_concurrent_relocate_to_the_same_destination_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let chisei = dir.path().join("chisei.db");
        let source_s = source.to_str().unwrap();
        let chisei_s = chisei.to_str().unwrap();
        init_sqlite(source_s);
        let held = lock_relocate_destination(chisei_s).unwrap();
        let err = relocate_sqlite(source_s, source_s, chisei_s).unwrap_err();
        assert!(err.contains("another relocate"), "{err}");
        assert!(!writer_fence_raised(source_s).unwrap());
        drop(held);
        relocate_sqlite(source_s, source_s, chisei_s).unwrap();
    }

    #[test]
    fn dirty_families_include_tables_created_after_capture() {
        let captured = vec!["chisei_budget_limits".to_string()];
        let current = vec![
            "chisei_budget_limits".to_string(),
            "chisei_portfolio_new".to_string(),
        ];
        let families = dirty_families(Vec::new(), &current, &captured);
        assert_eq!(
            families.into_iter().collect::<Vec<_>>(),
            ["portfolio".to_string()]
        );
        let families = dirty_families(vec!["chisei_eval_runs".into()], &captured, &captured);
        assert_eq!(
            families.into_iter().collect::<Vec<_>>(),
            ["evaluation".to_string()]
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
                autonomous_envelope_id: String::new(),
                parked_object_digest: String::new(),
                decided_by: String::new(),
                approval_decision: String::new(),
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
    fn pairing_epoch_check_and_advance_read_each_store_once_per_admit() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        align_split_generations(&layout).unwrap();

        PAIRING_EPOCH_READS.with(|reads| reads.set(0));
        PAIRING_EPOCH_WRITES.with(|writes| writes.set(0));
        for _ in 0..5 {
            refuse_mutating_if_generation_mismatch(&layout).unwrap();
        }
        // #1108: `advance_pairing_epoch` used to re-read both stores to
        // recompute the value the match check had already just read; each
        // of the 5 admits now reads each store exactly once instead of
        // twice.
        assert_eq!(PAIRING_EPOCH_READS.with(|reads| reads.get()), 5 * 2);
        // Every admit still advances the epoch on both stores — nothing is
        // ever skipped, so a one-sided restore stays detectable on the
        // very next admit regardless of timing.
        assert_eq!(PAIRING_EPOCH_WRITES.with(|writes| writes.get()), 5 * 2);

        // The optimization never trades away detection: a divergence
        // introduced between admits is still caught immediately.
        write_runtime_pairing_epoch(&layout.chisei_runtime(), 999).unwrap();
        let err = refuse_mutating_if_generation_mismatch(&layout).unwrap_err();
        assert!(err.contains("pairing epochs"), "{err}");
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
        // #1105: the fence write's CREATE previously omitted
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

        // Leave a clean greenfield state: this test and
        // postgres_generation_roundtrip_covers_the_fence share one
        // SEKAI_TEST_POSTGRES_URL singleton cutover row and can run in either
        // order, so raising the fence here must not leak into a sibling test's
        // unfenced assertion.
        match &runtime {
            RuntimeDb::Postgres(db) => db
                .connection()
                .unwrap()
                .batch_execute("DROP TABLE IF EXISTS sekai_store_cutover;")
                .unwrap(),
            RuntimeDb::Sqlite(_) => unreachable!("constructed as RuntimeDb::Postgres above"),
        }
    }

    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    #[test]
    fn postgres_pairing_epoch_stamp_fails_closed_on_a_missing_row() {
        // #1104: write_runtime_pairing_epoch's Postgres branch ran a plain
        // UPDATE and discarded the affected-row count. An UPDATE that matches
        // no row returns Ok, not an error, so a store whose cutover table
        // exists but has no id=1 row (a corrupted or incompletely
        // initialized store; the normal write paths always create the table
        // and its row together) silently no-opped: the caller believed the
        // stamp succeeded while nothing was persisted. Create the schema
        // directly, without ever inserting the row, to reproduce that state.
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
            .batch_execute(
                "DROP TABLE IF EXISTS sekai_store_cutover;
                 CREATE TABLE sekai_store_cutover (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    generation BIGINT NOT NULL,
                    fence_raised INTEGER NOT NULL,
                    raised_at_ms BIGINT NOT NULL,
                    pairing_epoch BIGINT NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
        let runtime = RuntimeDb::Postgres(std::sync::Arc::new(db));

        let error = write_runtime_pairing_epoch(&runtime, 5).unwrap_err();
        assert!(error.contains("affected 0 rows"), "{error}");

        // A store that was properly generation-stamped first has a row, and
        // the stamp succeeds normally.
        write_runtime_generation(&runtime, 1).unwrap();
        write_runtime_pairing_epoch(&runtime, 5).unwrap();
        assert_eq!(read_runtime_pairing_epoch(&runtime).unwrap(), 5);

        match &runtime {
            RuntimeDb::Postgres(db) => db
                .connection()
                .unwrap()
                .batch_execute("DROP TABLE IF EXISTS sekai_store_cutover;")
                .unwrap(),
            RuntimeDb::Sqlite(_) => unreachable!("constructed as RuntimeDb::Postgres above"),
        }
    }

    #[ignore = "requires SEKAI_TEST_POSTGRES_URL and SEKAI_TEST_POSTGRES_CHISEI_URL, two \
                isolated TLS PostgreSQL databases whose public schema this test resets; \
                a private CA also needs SEKAI_POSTGRES_CA_CERT for the relocate connections"]
    #[test]
    fn postgres_relocate_waits_for_in_flight_writers_and_recopies_them() {
        // #1107: the fence must wait for a writer transaction that already
        // wrote a Chisei row, and the fenced catch-up must carry that row.
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
        let chisei_url = std::env::var("SEKAI_TEST_POSTGRES_CHISEI_URL").expect(
            "SEKAI_TEST_POSTGRES_CHISEI_URL must identify a second isolated PostgreSQL database",
        );
        let ca_cert_path = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").ok();
        let connect = |connection_url: &str| {
            if let Some(path) = &ca_cert_path {
                let pem = std::fs::read(path).expect("read PostgreSQL test CA certificate");
                PostgresDb::connect_with_ca_certificate(connection_url, 4, &pem).unwrap()
            } else {
                PostgresDb::connect(connection_url, 4).unwrap()
            }
        };
        let (source, chisei) = (connect(&url), connect(&chisei_url));
        for db in [&source, &chisei] {
            db.connection()
                .unwrap()
                .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                .unwrap();
        }
        for target in [&url, &chisei_url] {
            RuntimeBackend::initialize(
                RuntimeBackendConfig::from_sources(
                    BackendIdentity::Postgres,
                    None,
                    "unused.db",
                    Some(target),
                    4,
                    ca_cert_path.as_deref(),
                )
                .unwrap(),
            )
            .unwrap();
        }
        fn insert_limit(
            client: &mut impl postgres::GenericClient,
            scope: &str,
            amount: i64,
        ) -> Result<(), postgres::Error> {
            client
                .execute(
                    "INSERT INTO chisei_budget_limits (scope_id, max_amount, period_type)
                     VALUES ($1, $2, 'daily')",
                    &[&scope, &amount],
                )
                .map(|_| ())
        }
        insert_limit(&mut *source.connection().unwrap(), "before-copy", 1).unwrap();

        let (written_tx, written_rx) = std::sync::mpsc::channel();
        let in_flight = connect(&url);
        let (stale_db, watcher) = (connect(&url), connect(&url));
        let mut stale_writer = None;
        let report = relocate_postgres_online(&url, &url, &chisei_url, || {
            std::thread::spawn(move || {
                let mut conn = in_flight.connection().unwrap();
                let mut tx = conn.transaction().unwrap();
                insert_limit(&mut tx, "in-flight", 2).unwrap();
                written_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                tx.commit().unwrap();
            });
            written_rx.recv().map_err(|error| error.to_string())?;
            // A REPEATABLE READ writer whose snapshot predates the fence and
            // writes only after the gate closed.
            let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
            stale_writer = Some(std::thread::spawn(move || {
                let mut conn = stale_db.connection().unwrap();
                let mut tx = conn
                    .build_transaction()
                    .isolation_level(postgres::IsolationLevel::RepeatableRead)
                    .start()
                    .unwrap();
                tx.query_one("SELECT 1", &[]).unwrap();
                snapshot_tx.send(()).unwrap();
                let gate_closed = |db: &PostgresDb| {
                    db.connection()
                        .unwrap()
                        .query_one(
                            &format!("SELECT fenced FROM {CAPTURE_GATE_TABLE} WHERE id = 1"),
                            &[],
                        )
                        .unwrap()
                        .get::<_, i32>(0)
                        == 1
                };
                while !gate_closed(&watcher) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                insert_limit(&mut tx, "stale-snapshot", 4).and_then(|()| tx.commit())
            }));
            snapshot_rx.recv().map_err(|error| error.to_string())
        })
        .unwrap();
        let stale = stale_writer.unwrap().join().unwrap().unwrap_err();
        assert!(
            format!("{stale:?}").contains("could not serialize"),
            "a stale-snapshot writer must not pass the closed gate"
        );

        let amount = |db: &PostgresDb, scope: &str| -> Option<i64> {
            db.connection()
                .unwrap()
                .query_opt(
                    "SELECT max_amount FROM chisei_budget_limits WHERE scope_id = $1",
                    &[&scope],
                )
                .unwrap()
                .map(|row| row.get(0))
        };
        assert_eq!(amount(&chisei, "before-copy"), Some(1));
        assert_eq!(amount(&chisei, "in-flight"), Some(2));
        let recopied: Vec<&str> = report
            .recopied
            .iter()
            .map(|family| family.family.as_str())
            .collect();
        assert_eq!(recopied, ["budget"]);

        // A load short of the snapshot's own count fails closed.
        let tampered = tempfile::tempdir().unwrap();
        std::fs::write(
            tampered.path().join("tables.txt"),
            "chisei_budget_limits\t99",
        )
        .unwrap();
        std::fs::write(tampered.path().join("chisei_budget_limits"), "").unwrap();
        let budget = BTreeSet::from(["budget".to_string()]);
        let mismatch = copy_chisei_families_from_postgres_snapshot(
            tampered.path().to_str().unwrap(),
            &chisei,
            Some(&budget),
        )
        .unwrap_err();
        assert!(mismatch.contains("relocate validation failed"));

        let err = insert_limit(&mut *source.connection().unwrap(), "after-fence", 3).unwrap_err();
        assert!(format!("{err:?}").contains("writer fence raised"));
        assert!(postgres_writer_fence_raised(&source).unwrap());
    }

    #[ignore = "requires SEKAI_TEST_POSTGRES_URL and SEKAI_TEST_POSTGRES_CHISEI_URL, two \
                isolated TLS PostgreSQL databases simulating a Split pair"]
    #[test]
    fn postgres_pairing_epoch_advance_is_never_one_sided_on_a_fresh_pair() {
        // #1104: advance_pairing_epoch writes both stores sequentially with
        // no cross-store transaction. If a store's row is missing, the write
        // used to silently no-op instead of erroring, so the pair could end
        // up one-sided (one side advanced, the other stale) with no signal.
        // With the fail-closed fix, a missing row on either side surfaces as
        // an Err from advance_pairing_epoch instead of a silent partial
        // advance, and pairing_epochs_match still correctly detects the
        // divergence if one ever occurs. This exercises advance_pairing_epoch
        // itself (not just write_runtime_pairing_epoch) through a real Split
        // Postgres CombinedStoreLayout, so it proves the caller's error
        // propagation and divergence detection, not only the lower-level write.
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
        // A real Split pair is two physically distinct databases; reusing one
        // URL for both sides would make them share a single table/row and
        // could not exercise "the other side's row is missing" at all. The
        // second, sibling database name is fixed and only used by this test.
        let chisei_url = std::env::var("SEKAI_TEST_POSTGRES_CHISEI_URL").expect(
            "SEKAI_TEST_POSTGRES_CHISEI_URL must identify a second isolated PostgreSQL \
             database distinct from SEKAI_TEST_POSTGRES_URL",
        );
        let ca_cert_path = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").ok();
        let connect = |connection_url: &str| {
            if let Some(path) = &ca_cert_path {
                let pem = std::fs::read(path).expect("read PostgreSQL test CA certificate");
                PostgresDb::connect_with_ca_certificate(connection_url, 4, &pem).unwrap()
            } else {
                PostgresDb::connect(connection_url, 4).unwrap()
            }
        };
        // Reset both sides to a truly greenfield state before opening the
        // layout: no table on the sekai side, an existing table without a row
        // on the chisei side, matching the scenario under test.
        connect(&url)
            .connection()
            .unwrap()
            .batch_execute("DROP TABLE IF EXISTS sekai_store_cutover;")
            .unwrap();
        connect(&chisei_url)
            .connection()
            .unwrap()
            .batch_execute(
                "DROP TABLE IF EXISTS sekai_store_cutover;
                 CREATE TABLE sekai_store_cutover (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    generation BIGINT NOT NULL,
                    fence_raised INTEGER NOT NULL,
                    raised_at_ms BIGINT NOT NULL,
                    pairing_epoch BIGINT NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();

        let layout = CombinedStoreSources {
            backend: Some(BackendIdentity::Postgres),
            sekai_postgres_url: Some(url.clone()),
            chisei_postgres_url: Some(chisei_url.clone()),
            postgres_max_connections: 4,
            postgres_ca_cert_path: ca_cert_path.clone(),
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        assert!(layout.is_split());

        // The sekai side has no row at all yet either: stamp a generation on
        // it (as align/restamp normally would first) so only the chisei side
        // is missing its row, isolating the one-sided-advance scenario.
        write_runtime_generation(&layout.sekai_runtime(), 1).unwrap();
        assert!(pairing_epochs_match(&layout).unwrap());

        // advance_pairing_epoch writes the sekai side first, then the chisei
        // side. The chisei side's missing row must make the whole call fail
        // closed instead of silently leaving sekai advanced and chisei stale.
        let before = read_runtime_pairing_epoch(&layout.sekai_runtime()).unwrap();
        let error = advance_pairing_epoch(&layout).unwrap_err();
        assert!(error.contains("affected 0 rows"), "{error}");
        assert_eq!(
            read_runtime_pairing_epoch(&layout.sekai_runtime()).unwrap(),
            before + 1,
            "advance_pairing_epoch writes sekai before chisei, so sekai does \
             advance even though the call as a whole reports failure"
        );
        assert!(
            !pairing_epochs_match(&layout).unwrap(),
            "the one-sided write must be a detectable divergence, not a \
             silent success"
        );

        // Once the chisei side is properly generation-stamped, the pair is
        // no longer divergent and advance succeeds on both sides together.
        write_runtime_generation(&layout.chisei_runtime(), 1).unwrap();
        write_runtime_pairing_epoch(&layout.chisei_runtime(), before + 1).unwrap();
        assert!(pairing_epochs_match(&layout).unwrap());
        advance_pairing_epoch(&layout).unwrap();
        assert_eq!(
            read_runtime_pairing_epoch(&layout.sekai_runtime()).unwrap(),
            before + 2
        );
        assert_eq!(
            read_runtime_pairing_epoch(&layout.chisei_runtime()).unwrap(),
            before + 2
        );

        for runtime in [layout.sekai_runtime(), layout.chisei_runtime()] {
            match runtime.as_ref() {
                RuntimeDb::Postgres(db) => db
                    .connection()
                    .unwrap()
                    .batch_execute("DROP TABLE IF EXISTS sekai_store_cutover;")
                    .unwrap(),
                RuntimeDb::Sqlite(_) => unreachable!("opened as Postgres above"),
            }
        }
    }
}
