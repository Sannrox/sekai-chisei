//! Dual-backend community-store dispatch for open table.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_open_table_source(
        &self,
        source: &crate::sekai::open_table::OpenTableSource,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_source(source),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_open_table_source(source))
            }
        }
    }

    pub fn get_open_table_source(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSource>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_source(source_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_open_table_source(source_id))
            }
        }
    }

    pub fn put_open_table_snapshot(
        &self,
        snapshot: &crate::sekai::open_table::OpenTableSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_snapshot(snapshot),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_open_table_snapshot(snapshot))
            }
        }
    }

    pub fn get_open_table_snapshot(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSnapshot>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_snapshot(source_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_open_table_snapshot(source_id))
            }
        }
    }
}
