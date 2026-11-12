//! r2d2 connection manager for the embedded SQLite store.
//!
//! Kept in-tree so the store follows `rusqlite` releases (and the bundled
//! SQLite they carry) without waiting on a pool adapter crate.

use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

enum Source {
    File(PathBuf),
    /// A named shared-cache in-memory database. `keep_alive` holds one
    /// connection open so the database outlives pool connection churn.
    Memory {
        uri: String,
        keep_alive: Mutex<Option<Connection>>,
    },
}

/// Opens connections to one SQLite file, or to one in-memory database that
/// every connection from this manager shares.
pub struct SqliteConnectionManager {
    source: Source,
}

impl SqliteConnectionManager {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            source: Source::File(path.into()),
        }
    }

    pub fn memory() -> Self {
        Self {
            source: Source::Memory {
                uri: format!("file:{}?mode=memory&cache=shared", uuid::Uuid::new_v4()),
                keep_alive: Mutex::new(None),
            },
        }
    }
}

impl r2d2::ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        match &self.source {
            Source::File(path) => Connection::open_with_flags(path, OpenFlags::default()),
            Source::Memory { uri, keep_alive } => {
                let mut keep_alive = keep_alive.lock().unwrap_or_else(PoisonError::into_inner);
                if keep_alive.is_none() {
                    *keep_alive = Some(Connection::open_with_flags(uri, OpenFlags::default())?);
                }
                Connection::open_with_flags(uri, OpenFlags::default())
            }
        }
    }

    fn is_valid(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("")
    }

    fn has_broken(&self, _: &mut Connection) -> bool {
        false
    }
}
