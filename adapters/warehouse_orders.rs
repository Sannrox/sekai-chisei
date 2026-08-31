//! Domain-neutral orders warehouse adapter (#711).

use sekai_chisei::sekai::warehouse_projection::{
    PROFILE_ORDERS, PROFILE_VERSION, SECURITY_CONTRACT, WAREHOUSE_CONTRACT, WarehouseColumn,
    WarehouseCursor, WarehouseProjection, WarehouseRow, WarehouseSecurity,
};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const ADAPTER_ID: &str = PROFILE_ORDERS;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdersDocument {
    pub projection_id: String,
    pub namespace: String,
    pub owner: String,
    pub purpose: String,
    pub residency_class: String,
    pub trust_pin_digest: String,
    pub rows: Vec<OrdersRow>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdersRow {
    pub id: String,
    pub sku: String,
}

pub fn parse(bytes: &[u8]) -> Result<OrdersDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("orders document is invalid: {error}"))
}

pub fn translate_projection(document: &OrdersDocument) -> Result<WarehouseProjection, String> {
    Ok(WarehouseProjection {
        contract_version: WAREHOUSE_CONTRACT.into(),
        projection_id: document.projection_id.clone(),
        namespace: document.namespace.clone(),
        owner: document.owner.clone(),
        adapter_id: PROFILE_ORDERS.into(),
        adapter_version: PROFILE_VERSION.into(),
        columns: vec![
            WarehouseColumn {
                name: "id".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
            WarehouseColumn {
                name: "sku".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
        ],
        security: WarehouseSecurity {
            contract_version: SECURITY_CONTRACT.into(),
            classification_ceiling: "internal".into(),
            purpose: document.purpose.clone(),
            residency_class: document.residency_class.clone(),
            trust_pin_digest: document.trust_pin_digest.clone(),
        },
        lineage_digest: String::new(),
        cursor: WarehouseCursor {
            generation: 0,
            offset: 0,
            last_page_digest: String::new(),
        },
        status: "live".into(),
        projection_digest: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    })
}

pub fn translate_rows(document: &OrdersDocument) -> Result<Vec<WarehouseRow>, String> {
    document
        .rows
        .iter()
        .map(|row| {
            if row.id.trim().is_empty() || row.sku.trim().is_empty() {
                return Err("orders row identity is required".into());
            }
            Ok(WarehouseRow {
                row_id: row.id.clone(),
                values: BTreeMap::from([
                    ("id".into(), row.id.clone()),
                    ("sku".into(), row.sku.clone()),
                ]),
                deleted: false,
            })
        })
        .collect()
}
