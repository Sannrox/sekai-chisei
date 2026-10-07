//! Which schema families a physical store migrates and will accept rows in.
//!
//! [`SchemaPlane::Shared`] keeps the historical dual-schema (in-process
//! fixtures, relocate source). Sekai and Chisei opens migrate only their
//! owned families plus the shared decision ledger and the per-store
//! `chisei_operation_receipts` table. Receipts are plane-local on every dest
//! (Combined Split writes admission receipts onto the Sekai dest). Existing
//! foreign-plane tables stay; populated ones refuse unless a relocate writer
//! fence is already raised, so a missed relocation cannot hide. Known
//! migration-seeded and historical Chisei-plane startup rows (default
//! retention policies, `object_query_cursor_hmac`, `chisei-gateway`
//! credentials) do not count as missed relocation.

use rusqlite::OptionalExtension;

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

const CUTOVER_TABLE: &str = "sekai_store_cutover";

/// Schema families this open should create and treat as owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaPlane {
    /// Both families. Fixtures, relocate source, and Postgres conformance.
    Shared,
    Sekai,
    Chisei,
}

impl SchemaPlane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Sekai => "sekai",
            Self::Chisei => "chisei",
        }
    }

    pub fn includes_sekai(self) -> bool {
        matches!(self, Self::Shared | Self::Sekai)
    }

    pub fn includes_chisei(self) -> bool {
        matches!(self, Self::Shared | Self::Chisei)
    }

    fn foreign_name(self) -> &'static str {
        match self {
            Self::Sekai => "Chisei",
            Self::Chisei => "Sekai",
            Self::Shared => "foreign-plane",
        }
    }

    /// Offline single-store CLIs keep a historical dual-schema file readable.
    /// A missing path or a Sekai-only file stays Sekai-owned so reports do not
    /// recreate Chisei tables. Populated unfenced Chisei rows mean the file is
    /// still the pre-split shared store.
    pub fn for_existing_sqlite(path: &str) -> Self {
        if !std::path::Path::new(path).exists() {
            return Self::Sekai;
        }
        let Ok(conn) = rusqlite::Connection::open(path) else {
            return Self::Sekai;
        };
        match reject_populated_foreign_sqlite_conn(&conn, Self::Sekai) {
            Ok(()) => Self::Sekai,
            Err(_) => Self::Shared,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TableClass {
    Infrastructure,
    Shared,
    Sekai,
    Chisei,
    Unknown,
}

fn classify_table(name: &str) -> TableClass {
    match name {
        "sekai_schema_migrations"
        | "sekai_action_effect_migrations"
        | "sekai_store_plane"
        | "sekai_store_cutover"
        | "sekai_relocate_capture"
        | "sekai_relocate_dirty"
        | "chisei_relocate_families" => TableClass::Infrastructure,
        "sekai_decisions" | "sekai_ledger_anchors" | "chisei_operation_receipts" => {
            TableClass::Shared
        }
        name if name.starts_with("chisei_") => TableClass::Chisei,
        name if name.starts_with("sekai_") => TableClass::Sekai,
        _ => TableClass::Unknown,
    }
}

fn plane_owns(plane: SchemaPlane, class: TableClass) -> bool {
    matches!(
        (plane, class),
        (_, TableClass::Infrastructure | TableClass::Shared)
            | (SchemaPlane::Shared, _)
            | (SchemaPlane::Sekai, TableClass::Sekai)
            | (SchemaPlane::Chisei, TableClass::Chisei)
    )
}

pub(crate) fn reject_populated_foreign_sqlite(
    db: &SekaiDb,
    plane: SchemaPlane,
) -> Result<(), String> {
    if plane == SchemaPlane::Shared {
        return Ok(());
    }
    let conn = db.conn();
    reject_populated_foreign_sqlite_conn(&conn, plane)
}

pub(crate) fn reject_populated_foreign_sqlite_conn(
    conn: &rusqlite::Connection,
    plane: SchemaPlane,
) -> Result<(), String> {
    if plane == SchemaPlane::Shared {
        return Ok(());
    }
    if sqlite_cutover_fence_raised(conn)? {
        return Ok(());
    }
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(|error| error.to_string())?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    for name in names {
        let name = name.map_err(|error| error.to_string())?;
        if plane_owns(plane, classify_table(&name)) {
            continue;
        }
        let count = sqlite_foreign_row_count(conn, &name)?;
        if count > 0 {
            return Err(foreign_rows_message(plane, &name, count));
        }
    }
    Ok(())
}

pub(crate) fn reject_populated_foreign_postgres(
    db: &PostgresDb,
    plane: SchemaPlane,
) -> Result<(), String> {
    if plane == SchemaPlane::Shared {
        return Ok(());
    }
    let mut conn = db.connection()?;
    if postgres_cutover_fence_raised(&mut *conn)? {
        return Ok(());
    }
    let tables = conn
        .query(
            "SELECT tablename FROM pg_tables
             WHERE schemaname = current_schema()
             ORDER BY tablename",
            &[],
        )
        .map_err(|error| error.to_string())?;
    for row in tables {
        let name: String = row.get(0);
        if plane_owns(plane, classify_table(&name)) {
            continue;
        }
        let count = postgres_foreign_row_count(&mut *conn, &name)?;
        if count > 0 {
            return Err(foreign_rows_message(plane, &name, count));
        }
    }
    Ok(())
}

/// Shared migrate used to insert these three global defaults into every dest,
/// including Combined Split Chisei files. They are not operator data. A
/// namespaced, day-changed, or otherwise custom policy still counts as
/// missed relocation.
const MIGRATION_SEEDED_RETENTION_POLICIES: [(&str, i64); 3] =
    [("audit", 365), ("llm_calls", 90), ("task_observations", 90)];

/// Historical Chisei-plane constructed a real `SekaiServiceImpl` against the
/// owned dest, which INSERT OR IGNOREd this cursor HMAC. Other secrets count.
const HISTORICAL_CURSOR_HMAC_SECRET: &str = "object_query_cursor_hmac";

/// Historical Chisei-plane UDS startup rotated this reserved gateway
/// principal onto the Chisei dest. Other principals count.
const HISTORICAL_GATEWAY_PRINCIPAL: &str = "chisei-gateway";

fn foreign_row_count_sql(table: &str) -> String {
    match table {
        "sekai_retention_policies" => {
            let seeded = MIGRATION_SEEDED_RETENTION_POLICIES
                .map(|(dataset, days)| {
                    format!("(dataset = '{dataset}' AND retention_days = {days})")
                })
                .join(" OR ");
            format!(
                "SELECT COUNT(*) FROM \"{table}\"
                 WHERE NOT (
                   namespace = '' AND data_class = ''
                   AND ({seeded})
                 )"
            )
        }
        "sekai_object_security_runtime_secrets" => format!(
            "SELECT COUNT(*) FROM \"{table}\" WHERE name != '{HISTORICAL_CURSOR_HMAC_SECRET}'"
        ),
        "sekai_principal_credentials" => format!(
            "SELECT COUNT(*) FROM \"{table}\" WHERE principal != '{HISTORICAL_GATEWAY_PRINCIPAL}'"
        ),
        _ => format!("SELECT COUNT(*) FROM \"{table}\""),
    }
}

fn sqlite_foreign_row_count(conn: &rusqlite::Connection, table: &str) -> Result<i64, String> {
    conn.query_row(&foreign_row_count_sql(table), [], |row| row.get(0))
        .map_err(|error| format!("count {table}: {error}"))
}

fn postgres_foreign_row_count(
    conn: &mut impl postgres::GenericClient,
    table: &str,
) -> Result<i64, String> {
    conn.query_one(&foreign_row_count_sql(table), &[])
        .map(|row| row.get(0))
        .map_err(|error| format!("count {table}: {error}"))
}

fn sqlite_cutover_fence_raised(conn: &rusqlite::Connection) -> Result<bool, String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [CUTOVER_TABLE],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Ok(false);
    }
    let raised: Option<i64> = conn
        .query_row(
            &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(raised == Some(1))
}

fn postgres_cutover_fence_raised(conn: &mut impl postgres::GenericClient) -> Result<bool, String> {
    match conn.query_opt(
        &format!("SELECT fence_raised FROM {CUTOVER_TABLE} WHERE id = 1"),
        &[],
    ) {
        Ok(Some(row)) => {
            let raised: i32 = row.get(0);
            Ok(raised == 1)
        }
        Ok(None) => Ok(false),
        Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn foreign_rows_message(plane: SchemaPlane, table: &str, count: i64) -> String {
    format!(
        "this {} store still holds {count} {} row(s) in {table}; a missed relocation cannot hide. Move the other plane with `sekaictl admin store relocate --source <this-store> --sekai <sekai-dest> --chisei <chisei-dest>` before opening it as a {}-only store",
        plane.as_str(),
        plane.foreign_name(),
        plane.as_str(),
    )
}

#[cfg(test)]
pub(crate) fn sqlite_user_tables(conn: &rusqlite::Connection) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chisei_prefix_is_chisei_owned() {
        assert_eq!(classify_table("chisei_budget_limits"), TableClass::Chisei);
        assert_eq!(classify_table("sekai_objects"), TableClass::Sekai);
        assert_eq!(classify_table("sekai_decisions"), TableClass::Shared);
        assert_eq!(
            classify_table("chisei_relocate_families"),
            TableClass::Infrastructure
        );
        assert_eq!(
            classify_table("sekai_action_effect_migrations"),
            TableClass::Infrastructure
        );
    }

    #[test]
    fn plane_owns_shared_decision_ledger() {
        assert!(plane_owns(SchemaPlane::Sekai, TableClass::Shared));
        assert!(plane_owns(SchemaPlane::Chisei, TableClass::Shared));
        assert!(!plane_owns(SchemaPlane::Sekai, TableClass::Chisei));
        assert!(!plane_owns(SchemaPlane::Chisei, TableClass::Sekai));
    }

    #[test]
    fn retention_seed_datasets_match_migrate_retention() {
        assert_eq!(
            MIGRATION_SEEDED_RETENTION_POLICIES,
            [
                (crate::sekai::retention::AUDIT_DATASET, 365),
                (crate::sekai::retention::LLM_CALLS_DATASET, 90),
                (crate::sekai::retention::TASK_OBSERVATIONS_DATASET, 90),
            ]
        );
    }

    #[test]
    fn existing_sqlite_plane_keeps_historical_shared_files_readable() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.db");
        assert_eq!(
            SchemaPlane::for_existing_sqlite(missing.to_str().unwrap()),
            SchemaPlane::Sekai
        );

        let sekai_only = directory.path().join("sekai.db");
        let _ = crate::db::store::SekaiStore::open_sqlite(sekai_only.to_str().unwrap());
        assert_eq!(
            SchemaPlane::for_existing_sqlite(sekai_only.to_str().unwrap()),
            SchemaPlane::Sekai
        );

        let shared = directory.path().join("shared.db");
        let db = crate::db::sekai::SekaiDb::new(shared.to_str().unwrap()).unwrap();
        db.conn()
            .execute(
                "INSERT INTO chisei_budget_limits
                 (scope_id, metric, parent_scope_id, max_amount, period_type, home_site_id, pool_id)
                 VALUES ('agent:report', 'tokens', '', 1, 'month', '', '')",
                [],
            )
            .unwrap();
        drop(db);
        assert_eq!(
            SchemaPlane::for_existing_sqlite(shared.to_str().unwrap()),
            SchemaPlane::Shared
        );
    }
}
