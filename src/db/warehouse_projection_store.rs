//! SQLite persistence for warehouse projections (#711).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::warehouse_projection::{
    WAREHOUSE_UNAVAILABLE, WarehousePage, WarehouseProjection,
};

impl SekaiDb {
    pub fn get_warehouse_projection(
        &self,
        namespace: &str,
        projection_id: &str,
    ) -> Result<Option<WarehouseProjection>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_warehouse_projections
                 WHERE namespace = ?1 AND projection_id = ?2",
                params![namespace, projection_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode warehouse projection: {error}"))
        })
        .transpose()
    }

    pub fn put_warehouse_projection(&self, projection: &WarehouseProjection) -> Result<(), String> {
        let json = serde_json::to_string(projection)
            .map_err(|error| format!("encode warehouse projection: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_warehouse_projections
                    (namespace, projection_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, projection_id) DO NOTHING",
                params![
                    projection.namespace,
                    projection.projection_id,
                    projection.owner,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_warehouse_projection(
        &self,
        expected: &WarehouseProjection,
        next: &WarehouseProjection,
    ) -> Result<(), String> {
        self.commit_warehouse_export(expected, next, None)
    }

    pub fn commit_warehouse_export(
        &self,
        expected: &WarehouseProjection,
        next: &WarehouseProjection,
        page: Option<&WarehousePage>,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.projection_id != next.projection_id
            || expected.owner != next.owner
        {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode warehouse projection: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_warehouse_projections
                 WHERE namespace = ?1 AND projection_id = ?2",
                params![expected.namespace, expected.projection_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: WarehouseProjection =
            serde_json::from_str(&current.ok_or(WAREHOUSE_UNAVAILABLE)?)
                .map_err(|error| format!("decode warehouse projection: {error}"))?;
        if current != *expected {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_warehouse_projections
                 SET record_json = ?1
                 WHERE namespace = ?2 AND projection_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.projection_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if let Some(page) = page {
            if page.namespace != next.namespace || page.projection_id != next.projection_id {
                return Err(WAREHOUSE_UNAVAILABLE.into());
            }
            let page_json = serde_json::to_string(page)
                .map_err(|error| format!("encode warehouse page: {error}"))?;
            let inserted = tx
                .execute(
                    "INSERT INTO sekai_warehouse_pages
                        (namespace, projection_id, page_digest, record_json)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        page.namespace,
                        page.projection_id,
                        page.page_digest,
                        page_json
                    ],
                )
                .map_err(|error| error.to_string())?;
            if inserted == 0 {
                return Err(WAREHOUSE_UNAVAILABLE.into());
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}
