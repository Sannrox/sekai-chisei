//! Dual-backend community-store dispatch for lakehouse.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_lakehouse_snapshot(
        &self,
        namespace: &str,
        snapshot_id: &str,
    ) -> Result<Option<crate::sekai::lakehouse_snapshot::LakehouseSnapshot>, String> {
        match self {
            Self::Sqlite(db) => db.get_lakehouse_snapshot(namespace, snapshot_id),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_lakehouse_snapshot(
        &self,
        snapshot: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_lakehouse_snapshot(snapshot),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_lakehouse_snapshot(
        &self,
        expected: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
        next: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_lakehouse_snapshot(expected, next),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }
}
