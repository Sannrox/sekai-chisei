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
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, projection_id, page_digest) DO NOTHING",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::warehouse_projection::{
        WarehouseColumn, WarehouseCursor, WarehousePage, WarehouseProjection, WarehouseRow,
        WarehouseSecurity,
    };
    use std::collections::BTreeMap;

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn projection() -> WarehouseProjection {
        WarehouseProjection {
            contract_version: "sekai.warehouse-projection/v1".into(),
            projection_id: "wh:pages".into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            adapter_id: "adapter.warehouse.orders".into(),
            adapter_version: "1.0.0".into(),
            columns: vec![WarehouseColumn {
                name: "id".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            }],
            security: WarehouseSecurity {
                contract_version: "sekai.security-metadata/v1".into(),
                classification_ceiling: "internal".into(),
                purpose: "analytics".into(),
                residency_class: "eu".into(),
                trust_pin_digest: digest(1),
            },
            lineage_digest: digest(2),
            cursor: WarehouseCursor {
                generation: 0,
                offset: 0,
                last_page_digest: String::new(),
            },
            status: "live".into(),
            projection_digest: digest(3),
            admitted_by: "integrator".into(),
            admitted_at_ms: 1_000,
        }
    }

    fn page() -> WarehousePage {
        WarehousePage {
            projection_id: "wh:pages".into(),
            namespace: "ops".into(),
            mode: "snapshot".into(),
            generation: 0,
            offset_start: 0,
            offset_end: 1,
            rows: vec![WarehouseRow {
                row_id: "1".into(),
                values: BTreeMap::from([("id".into(), "1".into())]),
                deleted: false,
            }],
            page_digest: digest(9),
            lineage_digest: digest(4),
        }
    }

    #[test]
    fn a_duplicate_warehouse_page_write_returns_unavailable_and_rolls_back() {
        let db = SekaiDb::new(":memory:").unwrap();
        let expected = projection();
        db.put_warehouse_projection(&expected).unwrap();
        let page = page();
        let mut next = expected.clone();
        next.cursor.offset = 1;
        next.cursor.last_page_digest = page.page_digest.clone();
        db.commit_warehouse_export(&expected, &next, Some(&page))
            .unwrap();
        let mut later = next.clone();
        later.cursor.offset = 2;
        later.cursor.last_page_digest = digest(10);
        let error = db
            .commit_warehouse_export(&next, &later, Some(&page))
            .unwrap_err();
        assert_eq!(error, WAREHOUSE_UNAVAILABLE);
        assert_eq!(
            db.get_warehouse_projection(&expected.namespace, &expected.projection_id)
                .unwrap()
                .unwrap(),
            next
        );
    }
}
