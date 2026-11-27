//! Binding-owned dataset rows for inbound source batches.
//!
//! ApplySourceBatch lands mapped records here. Object-type index members
//! rebuild from these rows. Clerk object ids stay the source-sync ids.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::sekai::dataset::ColumnDef;
use crate::sekai::object_type_index::{
    CONTRACT_VERSION, ObjectTypeDatasource, SOURCE_PAYLOAD_COLUMN,
};
use crate::sekai::schema::default_property_classification;

/// The row key. The `idx_*_source_key` indexes and `latest_source_batch_row`
/// spell it as `$.source_id` / `->>'source_id'`; keep them in step.
pub const KEY_COLUMN: &str = "source_id";
pub const HIDDEN_COLUMN: &str = "hidden";
pub const PAYLOAD_COLUMN: &str = SOURCE_PAYLOAD_COLUMN;
pub const DATASET_ID_PREFIX: &str = "srcds:";

pub fn binding_dataset_id(binding_id: &str, kind: &str) -> String {
    format!("{DATASET_ID_PREFIX}{binding_id}:{kind}")
}

pub fn kind_from_binding_dataset_id<'a>(binding_id: &str, dataset_id: &'a str) -> Option<&'a str> {
    let prefix = format!("{DATASET_ID_PREFIX}{binding_id}:");
    dataset_id
        .strip_prefix(&prefix)
        .filter(|kind| !kind.is_empty())
}

/// Ordinary dataset RPCs must not read or mutate land-path source datasets.
pub fn is_source_owned_dataset_id(id: &str) -> bool {
    id.starts_with(DATASET_ID_PREFIX)
}

pub fn dataset_name(source_instance: &str, kind: &str) -> String {
    format!("source {source_instance} {kind}")
}

pub fn columns_for_property_keys<'a>(keys: impl IntoIterator<Item = &'a str>) -> Vec<ColumnDef> {
    columns_for_record_keys(keys, false)
}

pub fn columns_for_record_keys<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    retain_payload: bool,
) -> Vec<ColumnDef> {
    let mut names = BTreeSet::new();
    names.insert(KEY_COLUMN.to_string());
    names.insert(HIDDEN_COLUMN.to_string());
    if retain_payload {
        names.insert(PAYLOAD_COLUMN.to_string());
    }
    for key in keys {
        if !key.is_empty() {
            names.insert(key.to_string());
        }
    }
    names
        .into_iter()
        .map(|name| ColumnDef {
            name,
            col_type: "string".into(),
            classification: default_property_classification(),
        })
        .collect()
}

pub fn row_for_record(
    source_id: &str,
    tombstoned: bool,
    properties: &BTreeMap<String, crate::sekai::object_schema::PropertyValue>,
    payload: Option<&str>,
) -> HashMap<String, String> {
    let mut row = HashMap::new();
    row.insert(KEY_COLUMN.into(), source_id.to_string());
    row.insert(
        HIDDEN_COLUMN.into(),
        if tombstoned { "1".into() } else { "0".into() },
    );
    if let Some(payload) = payload.filter(|value| !value.is_empty()) {
        row.insert(PAYLOAD_COLUMN.into(), payload.to_string());
    }
    for (key, value) in properties {
        if key == KEY_COLUMN || key == HIDDEN_COLUMN || key == PAYLOAD_COLUMN {
            continue;
        }
        row.insert(key.clone(), value.as_cell());
    }
    row
}

/// The rows that land from one batch: the last row of each external id, in
/// batch order. A row without an id always lands.
pub fn last_row_per_key(rows: &[HashMap<String, String>]) -> Vec<&HashMap<String, String>> {
    let mut last = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        if let Some(key) = row.get(KEY_COLUMN) {
            last.insert(key.as_str(), index);
        }
    }
    rows.iter()
        .enumerate()
        .filter(|(index, row)| {
            row.get(KEY_COLUMN)
                .is_none_or(|key| last.get(key.as_str()) == Some(index))
        })
        .map(|(_, row)| row)
        .collect()
}

pub fn identity_mapping(columns: &[ColumnDef]) -> BTreeMap<String, String> {
    columns
        .iter()
        .filter(|column| {
            column.name != KEY_COLUMN
                && column.name != HIDDEN_COLUMN
                && column.name != PAYLOAD_COLUMN
        })
        .map(|column| (column.name.clone(), column.name.clone()))
        .collect()
}

pub fn is_identity_mapping(mapping: &BTreeMap<String, String>) -> bool {
    mapping.iter().all(|(property, column)| property == column)
}

/// Union new identity columns into an existing identity mapping.
/// Returns `None` when the mapping is custom or already covers `incoming`.
pub fn expand_identity_mapping(
    previous: &BTreeMap<String, String>,
    incoming: &BTreeMap<String, String>,
) -> Option<BTreeMap<String, String>> {
    if !is_identity_mapping(previous) {
        return None;
    }
    let mut merged = previous.clone();
    let mut expanded = false;
    for (property, column) in incoming {
        match merged.get(property) {
            Some(existing) if existing == column => {}
            _ => {
                merged.insert(property.clone(), column.clone());
                expanded = true;
            }
        }
    }
    expanded.then_some(merged)
}

pub fn datasource(
    namespace: &str,
    kind: &str,
    definition_digest: &str,
    dataset_id: &str,
    columns: &[ColumnDef],
) -> ObjectTypeDatasource {
    ObjectTypeDatasource {
        contract_version: CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        kind: kind.into(),
        definition_digest: definition_digest.into(),
        dataset_id: dataset_id.into(),
        key_column: KEY_COLUMN.into(),
        property_mapping: identity_mapping(columns),
        hidden_column: HIDDEN_COLUMN.into(),
        edits_only: false,
        conflict_rule: String::new(),
        source_timestamp_property: String::new(),
    }
}

/// Keep plane-owned sync_* keys; replace mapped payload from the index member.
pub fn merge_mapped_properties(
    existing: &HashMap<String, String>,
    mapped: &BTreeMap<String, String>,
    hidden: bool,
    reserved: &[&str],
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (key, value) in existing {
        if reserved.contains(&key.as_str()) {
            out.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in mapped {
        out.insert(key.clone(), value.clone());
    }
    out.insert("sync_tombstoned".into(), hidden.to_string());
    out
}
