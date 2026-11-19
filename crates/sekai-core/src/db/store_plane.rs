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
    // Concurrent first openers race the stamp: the insert is a no-op for the
    // loser, which then compares against the winner's role (#2725).
    conn.execute(
        &format!(
            "INSERT INTO {TABLE} (id, role, stamped_at_ms) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO NOTHING"
        ),
        rusqlite::params![role.as_str(), chrono::Utc::now().timestamp_millis()],
    )
    .map_err(|error| error.to_string())?;
    let stamped: Option<String> = conn
        .query_row(
            &format!("SELECT role FROM {TABLE} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    check_stamp(stamped, role)
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
    connection
        .execute(
            &format!(
                "INSERT INTO {TABLE} (id, role, stamped_at_ms) VALUES (1, $1, $2)
                 ON CONFLICT (id) DO NOTHING"
            ),
            &[&role.as_str(), &chrono::Utc::now().timestamp_millis()],
        )
        .map_err(|error| error.to_string())?;
    let stamped: Option<String> = connection
        .query_opt(&format!("SELECT role FROM {TABLE} WHERE id = 1"), &[])
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    check_stamp(stamped, role)
}

/// Compares the stamp read after the insert-if-absent with `role`. A missing
/// or unparseable stamp is an error, never a reason to stamp again.
fn check_stamp(stamped: Option<String>, role: StorePlaneRole) -> Result<(), String> {
    let stamped = stamped.ok_or_else(|| format!("{TABLE} has no stamp after stamping"))?;
    match StorePlaneRole::parse(&stamped) {
        Some(existing) if existing == role => Ok(()),
        Some(existing) => Err(foreign_store_message(existing)),
        None => Err(format!("{TABLE} holds an unknown plane role {stamped:?}")),
    }
}

fn foreign_store_message(existing: StorePlaneRole) -> String {
    format!(
        "this process cannot open a store stamped for {}; each process opens only its own store",
        existing.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_store(dir: &tempfile::TempDir) -> SekaiDb {
        SekaiDb::new(dir.path().join("plane.db").to_str().unwrap()).unwrap()
    }

    /// Opens an unstamped PostgreSQL store while another opener's stamp is
    /// inserted but not committed, then commits it with `held` as the role.
    fn open_behind_an_uncommitted_stamp(
        held: StorePlaneRole,
        opening: StorePlaneRole,
    ) -> Result<(), String> {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = scratch.connect();
        let mut first = db.connection().unwrap();
        first
            .batch_execute(&format!(
                "CREATE TABLE {TABLE} (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    role TEXT NOT NULL CHECK (role IN ('sekai', 'chisei')),
                    stamped_at_ms BIGINT NOT NULL
                );"
            ))
            .unwrap();
        let mut winner = first.transaction().unwrap();
        winner
            .execute(
                &format!("INSERT INTO {TABLE} (id, role, stamped_at_ms) VALUES (1, $1, 1)"),
                &[&held.as_str()],
            )
            .unwrap();
        std::thread::scope(|scope| {
            let opener = scope.spawn(|| postgres_ensure(&db, opening));
            // The opener blocks on the winner's uncommitted row.
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(!opener.is_finished(), "the opener must wait for the stamp");
            winner.commit().unwrap();
            opener.join().unwrap()
        })
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_concurrent_openers_get_the_role_verdict() {
        open_behind_an_uncommitted_stamp(StorePlaneRole::Sekai, StorePlaneRole::Sekai).unwrap();
        let error = open_behind_an_uncommitted_stamp(StorePlaneRole::Chisei, StorePlaneRole::Sekai)
            .unwrap_err();
        assert!(
            error.contains("cannot open a store stamped for chisei"),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_stamped_role_fails_with_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_store(&dir);
        // A stamp table from before the role check could hold any value.
        db.conn()
            .execute_batch(&format!(
                "CREATE TABLE {TABLE} (id INTEGER PRIMARY KEY, role TEXT NOT NULL, stamped_at_ms INTEGER NOT NULL);
                 INSERT INTO {TABLE} VALUES (1, 'other', 1);"
            ))
            .unwrap();
        let error = sqlite_ensure(&db, StorePlaneRole::Sekai).unwrap_err();
        assert!(error.contains("unknown plane role"), "{error}");
    }
}
