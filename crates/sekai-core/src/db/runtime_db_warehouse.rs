//! Dual-backend community-store dispatch for warehouse.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_warehouse_projection(
        &self,
        namespace: &str,
        projection_id: &str,
    ) -> Result<Option<crate::sekai::warehouse_projection::WarehouseProjection>, String> {
        match self {
            Self::Sqlite(db) => db.get_warehouse_projection(namespace, projection_id),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn put_warehouse_projection(
        &self,
        projection: &crate::sekai::warehouse_projection::WarehouseProjection,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_warehouse_projection(projection),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn commit_warehouse_export(
        &self,
        expected: &crate::sekai::warehouse_projection::WarehouseProjection,
        next: &crate::sekai::warehouse_projection::WarehouseProjection,
        page: Option<&crate::sekai::warehouse_projection::WarehousePage>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_warehouse_export(expected, next, page),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }
}
