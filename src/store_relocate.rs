//! Offline, restartable Chisei-family relocation and writer fence.
//!
//! Take a short exclusive `VACUUM INTO` snapshot of the historical source,
//! raise the writer fence, then copy each Chisei-owned family from that
//! snapshot. The live source is not ATTACH'd for the family copy. Rollback
//! before the snapshot keeps the pre-copy files.
//!
//! Destination pairs also carry a split generation. Combined split open
//! compares the pair. A Shared or owned-plane open of a stamped store
//! compares `SEKAI_STORE_PEER` (read-only) or refuses mutations until an
//! operator restamp. Independent backups are not a paired restore set.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OptionalExtension, params};

use crate::combined_stores::{CombinedStoreLayout, CombinedStoreSources};
use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::runtime_backend::{BackendIdentity, RuntimeBackend, RuntimeBackendConfig};

const CUTOVER_TABLE: &str = "sekai_store_cutover";
const JOURNAL_TABLE: &str = "chisei_relocate_families";

static GENERATION_READS: AtomicUsize = AtomicUsize::new(0);

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
    "sekaictl admin store relocate --source <path> --sekai <path> --chisei <path>\n  Offline copy of Chisei families from the historical single store into the Chisei destination. Snapshots the source, fences writers, then copies families from the snapshot. Restartable per family. Quiesce writers first. Rollback before the snapshot keeps the pre-copy files.\n\
sekaictl admin store restamp --sekai <path-or-url> --chisei <path-or-url>\n  Operator reconcile after a one-sided restore. Writes the same split generation on both destination stores so mutating RPCs may resume. Independent backups are not a paired restore set."
}

pub fn run_store_command(
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args.first().map(String::as_str) {
        Some("relocate") => {
            let config = parse_relocate(&args[1..])?;
            let report = relocate_sqlite(&config.source, &config.sekai, &config.chisei)?;
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
pub fn relocate_sqlite(source: &str, sekai: &str, chisei: &str) -> Result<RelocateReport, String> {
    if source.trim().is_empty() || sekai.trim().is_empty() || chisei.trim().is_empty() {
        return Err("relocate paths must not be empty".into());
    }
    let source_id = crate::combined_stores::sqlite_identity(source)?;
    let sekai_id = crate::combined_stores::sqlite_identity(sekai)?;
    let chisei_id = crate::combined_stores::sqlite_identity(chisei)?;
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
    if let crate::combined_stores::StoreIdentity::Sqlite { canonical_path } =
        layout.sekai_identity()
    {
        if canonical_path == ":memory:" {
            return Ok(());
        }
        if writer_fence_raised(canonical_path)? {
            return Err(shared_writer_guidance());
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
    Mismatched {
        sekai: Option<i64>,
        chisei: Option<i64>,
    },
}

impl SplitGenerationState {
    pub fn refuses_mutations(&self) -> bool {
        matches!(self, Self::Mismatched { .. })
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
    if layout.is_split() {
        return Ok(compare_split_generations(
            read_runtime_generation(&layout.sekai_runtime())?,
            read_runtime_generation(&layout.chisei_runtime())?,
        ));
    }
    let local = read_runtime_generation(&layout.sekai_runtime())?;
    if local.is_none() {
        return Ok(SplitGenerationState::Shared);
    }
    let peer_generation = match peer {
        Some(dest) => read_dest_generation(dest)?,
        None => None,
    };
    Ok(compare_split_generations(local, peer_generation))
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

/// Stamp a matching generation when both destinations are empty; leave a
/// mismatch in place so mutating RPCs stay refused.
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
        return Ok(());
    }
    match split_generation_state(layout)? {
        SplitGenerationState::Mismatched { sekai, chisei } => {
            Err(generation_mismatch_guidance(sekai, chisei))
        }
        SplitGenerationState::Matched { generation } => {
            layout.cache_matched_generation(generation);
            Ok(())
        }
        _ => Ok(()),
    }
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
    GENERATION_READS.fetch_add(1, Ordering::Relaxed);
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

fn write_sqlite_generation(conn: &Connection, generation: i64) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {CUTOVER_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            generation INTEGER NOT NULL,
            fence_raised INTEGER NOT NULL,
            raised_at_ms INTEGER NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())?;
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
             (id, generation, fence_raised, raised_at_ms)
             VALUES (1, ?1, ?2, ?3)"
        ),
        params![
            generation,
            fence_raised,
            chrono::Utc::now().timestamp_millis()
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
            raised_at_ms BIGINT NOT NULL
        );",
    )
    .map_err(|error| error.to_string())?;
    let fence_raised: i64 = match conn.query_opt(
        "SELECT fence_raised FROM sekai_store_cutover WHERE id = 1",
        &[],
    ) {
        Ok(Some(row)) => row.get(0),
        Ok(None) => 0,
        Err(error) => return Err(error.to_string()),
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    conn.execute(
        "INSERT INTO sekai_store_cutover (id, generation, fence_raised, raised_at_ms)
         VALUES (1, $1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET
            generation = EXCLUDED.generation,
            raised_at_ms = EXCLUDED.raised_at_ms",
        &[&generation, &fence_raised, &now_ms],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
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
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {CUTOVER_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            generation INTEGER NOT NULL,
            fence_raised INTEGER NOT NULL,
            raised_at_ms INTEGER NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())?;
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {CUTOVER_TABLE}
             (id, generation, fence_raised, raised_at_ms)
             VALUES (1, ?1, 1, ?2)"
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

    #[test]
    fn relocate_copies_budget_family_and_fences_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let sekai = dir.path().join("sekai.db");
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

        let report = relocate_sqlite(source_s, sekai.to_str().unwrap(), chisei_s).unwrap();
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
        let dest = dir.path().join("shared.db");
        let source_s = source.to_str().unwrap();
        let dest_s = dest.to_str().unwrap();
        std::fs::write(&source, []).unwrap();
        std::fs::write(&dest, []).unwrap();
        let err = relocate_sqlite(source_s, dest_s, dest_s).unwrap_err();
        assert!(err.contains("same physical destination"), "{err}");

        let linked = dir.path().join("linked.db");
        std::fs::hard_link(&dest, &linked).unwrap();
        let linked_s = linked.to_str().unwrap();
        let hardlink_err = relocate_sqlite(source_s, dest_s, linked_s).unwrap_err();
        assert!(
            hardlink_err.contains("same physical destination"),
            "{hardlink_err}"
        );
    }

    #[test]
    fn relocate_is_restartable_from_completed_families() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.db");
        let sekai = dir.path().join("sekai.db");
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
        relocate_sqlite(source_s, sekai.to_str().unwrap(), chisei_s).unwrap();
        let second = relocate_sqlite(source_s, sekai.to_str().unwrap(), chisei_s).unwrap();
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
        let err = relocate_sqlite("shared.db", "sekai.db", "shared.db").unwrap_err();
        assert!(err.contains("shared source"), "{err}");
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
    fn matched_generation_is_read_once_per_admit_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
        align_split_generations(&layout).unwrap();
        GENERATION_READS.store(0, Ordering::Relaxed);
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.swap(0, Ordering::Relaxed), 2);
        for _ in 0..8 {
            refuse_mutating_if_generation_mismatch(&layout).unwrap();
        }
        assert_eq!(GENERATION_READS.load(Ordering::Relaxed), 0);
        layout.invalidate_matched_generation();
        GENERATION_READS.store(0, Ordering::Relaxed);
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.swap(0, Ordering::Relaxed), 2);
        refuse_mutating_if_generation_mismatch(&layout).unwrap();
        assert_eq!(GENERATION_READS.load(Ordering::Relaxed), 0);
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
        let sekai = dir.path().join("sekai.db");
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
        let report =
            relocate_sqlite(source_s, sekai.to_str().unwrap(), chisei.to_str().unwrap()).unwrap();
        let layout = open_dest_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap());
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
        assert!(compare_split_generations(Some(42), Some(41)).refuses_mutations());
        assert!(!compare_split_generations(Some(42), Some(42)).refuses_mutations());
    }
}
