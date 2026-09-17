//! Offline, restartable Chisei-family relocation and writer fence.
//!
//! Quiesce writers, copy each Chisei-owned family into the destination store,
//! validate counts, then raise a fence so a single `DB_PATH` / `DATABASE_URL`
//! writer refuses to start. Rollback before the fence keeps the pre-copy files.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::combined_stores::{CombinedStoreLayout, CombinedStoreSources};
use crate::runtime_backend::{BackendIdentity, RuntimeBackend, RuntimeBackendConfig};

const CUTOVER_TABLE: &str = "sekai_store_cutover";
const JOURNAL_TABLE: &str = "chisei_relocate_families";

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
    "sekaictl admin store relocate --source <path> --sekai <path> --chisei <path>\n  Offline copy of Chisei families from the historical single store into the Chisei destination. Restartable per family. Raises a writer fence so DB_PATH-only writers refuse to start. Quiesce writers first. Rollback before the fence keeps the pre-copy files."
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
    let chisei_id = crate::combined_stores::sqlite_identity(chisei)?;
    if source_id == chisei_id {
        return Err(
            "relocate refuses a shared source and Chisei destination; copy into a distinct file"
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
    dest.execute("ATTACH DATABASE ?1 AS src", params![source])
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
    drop(dest);

    let generation = raise_writer_fence(source)?;
    raise_writer_fence_with_generation(sekai, generation)?;
    raise_writer_fence_with_generation(chisei, generation)?;

    Ok(RelocateReport {
        families: reports,
        generation,
        fence_raised: true,
    })
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

        let shared = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: source_s.into(),
            legacy_sqlite_path: Some(source_s.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        assert!(
            refuse_shared_writer_if_fenced(&shared)
                .unwrap_err()
                .contains("writer fence")
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
    }

    #[test]
    fn same_source_and_destination_is_refused() {
        let err = relocate_sqlite("shared.db", "sekai.db", "shared.db").unwrap_err();
        assert!(err.contains("shared source"), "{err}");
    }
}
