//! Domain-neutral events lakehouse adapter (#712).

use sekai_chisei::sekai::lakehouse_snapshot::{
    LAKEHOUSE_CONTRACT, LakehouseColumn, LakehousePartition, LakehouseRow, LakehouseSecurity,
    LakehouseSnapshot, PROFILE_EVENTS, PROFILE_VERSION, SECURITY_CONTRACT,
};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const ADAPTER_ID: &str = PROFILE_EVENTS;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsDocument {
    pub snapshot_id: String,
    pub namespace: String,
    pub owner: String,
    pub purpose: String,
    pub residency_class: String,
    pub trust_pin_digest: String,
    pub partitions: Vec<EventsPartition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsPartition {
    pub day: String,
    pub rows: Vec<EventsRow>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsRow {
    pub id: String,
    pub kind: String,
}

pub fn parse(bytes: &[u8]) -> Result<EventsDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("events document is invalid: {error}"))
}

pub fn translate_snapshot(document: &EventsDocument) -> Result<LakehouseSnapshot, String> {
    Ok(LakehouseSnapshot {
        contract_version: LAKEHOUSE_CONTRACT.into(),
        snapshot_id: document.snapshot_id.clone(),
        namespace: document.namespace.clone(),
        owner: document.owner.clone(),
        adapter_id: PROFILE_EVENTS.into(),
        adapter_version: PROFILE_VERSION.into(),
        schema_version: 1,
        partition_keys: vec!["day".into()],
        columns: vec![
            LakehouseColumn {
                name: "id".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
            LakehouseColumn {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
        ],
        partitions: document
            .partitions
            .iter()
            .map(|partition| {
                Ok(LakehousePartition {
                    partition_key: partition.day.clone(),
                    rows: partition
                        .rows
                        .iter()
                        .map(|row| {
                            if row.id.trim().is_empty() || row.kind.trim().is_empty() {
                                return Err("events row identity is required".into());
                            }
                            Ok(LakehouseRow {
                                row_id: row.id.clone(),
                                values: BTreeMap::from([
                                    ("id".into(), row.id.clone()),
                                    ("kind".into(), row.kind.clone()),
                                ]),
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                    partition_digest: String::new(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        security: LakehouseSecurity {
            contract_version: SECURITY_CONTRACT.into(),
            classification_ceiling: "internal".into(),
            purpose: document.purpose.clone(),
            residency_class: document.residency_class.clone(),
            trust_pin_digest: document.trust_pin_digest.clone(),
        },
        redacted_columns: Vec::new(),
        deleted_partitions: Vec::new(),
        provenance_digest: String::new(),
        snapshot_digest: String::new(),
        status: "live".into(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    })
}
