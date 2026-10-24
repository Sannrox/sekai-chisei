//! Exclusive plane ownership stamp on a physical store.
//!
//! A Sekai process refuses a store stamped `chisei`, and the reverse. Combined
//! mode stamps each destination after a dest-pair open. Shared compatibility
//! files stay unstamped so one-file writers keep working until relocation.

use rusqlite::OptionalExtension;

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;

const TABLE: &str = "sekai_store_plane";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorePlaneRole {
    Sekai,
    Chisei,
}

impl StorePlaneRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sekai => "sekai",
            Self::Chisei => "chisei",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "sekai" => Some(Self::Sekai),
            "chisei" => Some(Self::Chisei),
            _ => None,
        }
    }
}

pub fn ensure_store_plane(db: &RuntimeDb, role: StorePlaneRole) -> Result<(), String> {
    match db {
        RuntimeDb::Sqlite(db) => sqlite_ensure(db, role),
        RuntimeDb::Postgres(db) => postgres_ensure(db, role),
    }
}

fn sqlite_ensure(db: &SekaiDb, role: StorePlaneRole) -> Result<(), String> {
    let conn = db.conn();
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            role TEXT NOT NULL CHECK (role IN ('sekai', 'chisei')),
            stamped_at_ms INTEGER NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())?;
    let existing: Option<String> = conn
        .query_row(
            &format!("SELECT role FROM {TABLE} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match existing.as_deref().and_then(StorePlaneRole::parse) {
        None => {
            conn.execute(
                &format!("INSERT INTO {TABLE} (id, role, stamped_at_ms) VALUES (1, ?1, ?2)"),
                rusqlite::params![role.as_str(), chrono::Utc::now().timestamp_millis()],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        }
        Some(existing) if existing == role => Ok(()),
        Some(existing) => Err(foreign_store_message(existing)),
    }
}

fn postgres_ensure(db: &PostgresDb, role: StorePlaneRole) -> Result<(), String> {
    let mut connection = db.connection()?;
    connection
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                role TEXT NOT NULL CHECK (role IN ('sekai', 'chisei')),
                stamped_at_ms BIGINT NOT NULL
            );"
        ))
        .map_err(|error| error.to_string())?;
    let existing: Option<String> = connection
        .query_opt(&format!("SELECT role FROM {TABLE} WHERE id = 1"), &[])
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    match existing.as_deref().and_then(StorePlaneRole::parse) {
        None => {
            connection
                .execute(
                    &format!("INSERT INTO {TABLE} (id, role, stamped_at_ms) VALUES (1, $1, $2)"),
                    &[&role.as_str(), &chrono::Utc::now().timestamp_millis()],
                )
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        Some(existing) if existing == role => Ok(()),
        Some(existing) => Err(foreign_store_message(existing)),
    }
}

fn foreign_store_message(existing: StorePlaneRole) -> String {
    format!(
        "this process cannot open a store stamped for {}; each process opens only its own store",
        existing.as_str()
    )
}
