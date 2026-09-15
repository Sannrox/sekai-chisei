//! Rebuildable object-type membership projection (#877).
//!
//! A registered dataset plus key mapping is the source of members. The index is
//! not object authority: deleting it and rematerializing from dataset rows and
//! Action deltas must restore visible membership. Hidden rows never contribute
//! to members, counts, order, errors, or continuation tokens.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub fn join_value_digest(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

pub const CONTRACT_VERSION: &str = "sekai.object-type-index/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectTypeIndexError {
    InvalidArgument(String),
    Quarantined(String),
    Stale(&'static str),
    NotFound(&'static str),
}

impl ObjectTypeIndexError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidArgument(message) | Self::Quarantined(message) => message.clone(),
            Self::Stale(message) | Self::NotFound(message) => (*message).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectTypeDatasource {
    pub contract_version: String,
    pub namespace: String,
    pub kind: String,
    pub definition_digest: String,
    pub dataset_id: String,
    pub key_column: String,
    pub property_mapping: BTreeMap<String, String>,
    pub hidden_column: String,
    pub edits_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectTypeIndexStatus {
    pub namespace: String,
    pub kind: String,
    pub indexed_at_ms: i64,
    pub last_dataset_row_id: i64,
    pub member_count: i32,
    pub stale: bool,
    pub quarantine_reason: String,
    pub lag_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectTypeIndexMember {
    pub namespace: String,
    pub kind: String,
    pub source_key: String,
    pub object_id: String,
    pub properties: BTreeMap<String, String>,
    pub content_hash: String,
    pub hidden: bool,
    pub from_edit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectTypeIndexEdit {
    pub namespace: String,
    pub kind: String,
    pub source_key: String,
    pub properties: BTreeMap<String, String>,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReindexReport {
    pub rewritten_keys: i32,
    pub skipped_unchanged: i32,
    pub quarantined: bool,
    pub quarantine_reason: String,
}

impl ObjectTypeDatasource {
    pub fn prepare(self) -> Result<Self, ObjectTypeIndexError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ObjectTypeIndexError::InvalidArgument(
                "unsupported object-type-index contract version".into(),
            ));
        }
        require_token("namespace", &self.namespace)?;
        require_token("kind", &self.kind)?;
        require_token("definition_digest", &self.definition_digest)?;
        if !self.edits_only {
            require_token("dataset_id", &self.dataset_id)?;
            require_token("key_column", &self.key_column)?;
        }
        for (property, column) in &self.property_mapping {
            require_token("property", property)?;
            require_token("column", column)?;
        }
        Ok(self)
    }
}

pub fn schema_drift(
    binding: &ObjectTypeDatasource,
    columns: &[crate::sekai::dataset::ColumnDef],
) -> Option<String> {
    if binding.edits_only {
        return None;
    }
    let names: Vec<&str> = columns.iter().map(|column| column.name.as_str()).collect();
    if !names.contains(&binding.key_column.as_str()) {
        return Some(format!(
            "datasource schema drift: missing key column {}",
            binding.key_column
        ));
    }
    for column in binding.property_mapping.values() {
        if !names.contains(&column.as_str()) {
            return Some(format!(
                "datasource schema drift: missing mapped column {column}"
            ));
        }
    }
    if !binding.hidden_column.is_empty() && !names.contains(&binding.hidden_column.as_str()) {
        return Some(format!(
            "datasource schema drift: missing hidden column {}",
            binding.hidden_column
        ));
    }
    None
}

pub fn member_from_row(
    binding: &ObjectTypeDatasource,
    row: &HashMap<String, String>,
) -> Result<ObjectTypeIndexMember, ObjectTypeIndexError> {
    let source_key = row
        .get(&binding.key_column)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ObjectTypeIndexError::InvalidArgument("source key required".into()))?
        .to_string();
    let mut properties = BTreeMap::new();
    for (property, column) in &binding.property_mapping {
        if let Some(value) = row.get(column) {
            properties.insert(property.clone(), value.clone());
        }
    }
    let hidden = if binding.hidden_column.is_empty() {
        false
    } else {
        row.get(&binding.hidden_column)
            .is_some_and(|value| is_hidden_value(value))
    };
    Ok(ObjectTypeIndexMember {
        namespace: binding.namespace.clone(),
        kind: binding.kind.clone(),
        object_id: sourced_object_id(&binding.kind, &source_key),
        source_key,
        content_hash: content_hash(&properties, hidden),
        properties,
        hidden,
        from_edit: false,
    })
}

pub fn member_from_edit(
    binding: &ObjectTypeDatasource,
    edit: &ObjectTypeIndexEdit,
) -> ObjectTypeIndexMember {
    ObjectTypeIndexMember {
        namespace: binding.namespace.clone(),
        kind: binding.kind.clone(),
        object_id: sourced_object_id(&binding.kind, &edit.source_key),
        source_key: edit.source_key.clone(),
        content_hash: content_hash(&edit.properties, edit.hidden),
        properties: edit.properties.clone(),
        hidden: edit.hidden,
        from_edit: true,
    }
}

pub fn sourced_object_id(kind: &str, source_key: &str) -> String {
    format!("{kind}:{source_key}")
}

pub fn content_hash(properties: &BTreeMap<String, String>, hidden: bool) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&(properties, hidden)).unwrap_or_default());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn is_hidden_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "hidden"
    )
}

pub fn freshness_holds(status: &ObjectTypeIndexStatus, required_freshness_ms: i64) -> bool {
    if required_freshness_ms <= 0 {
        return true;
    }
    !status.stale && status.lag_ms <= required_freshness_ms
}

fn require_token(field: &str, value: &str) -> Result<(), ObjectTypeIndexError> {
    if value.trim().is_empty() {
        return Err(ObjectTypeIndexError::InvalidArgument(format!(
            "{field} required"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::ColumnDef;

    fn binding() -> ObjectTypeDatasource {
        ObjectTypeDatasource {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: "rev-1".into(),
            dataset_id: "ds-customers".into(),
            key_column: "customer_id".into(),
            property_mapping: BTreeMap::from([("region".into(), "region".into())]),
            hidden_column: "hidden".into(),
            edits_only: false,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn hidden_rows_do_not_share_content_hash_with_visible_twins() {
        let visible = member_from_row(
            &binding(),
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let hidden = member_from_row(
            &binding(),
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "true".into()),
            ]),
        )
        .unwrap();
        assert!(!visible.hidden);
        assert!(hidden.hidden);
        assert_ne!(visible.content_hash, hidden.content_hash);
    }

    #[test]
    fn missing_mapped_column_is_schema_drift() {
        let reason = schema_drift(
            &binding(),
            &[ColumnDef {
                name: "customer_id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
        )
        .unwrap();
        assert!(reason.contains("region"));
    }

    #[test]
    fn freshness_fails_closed_when_stale_or_lagging() {
        let mut status = ObjectTypeIndexStatus {
            namespace: "sales".into(),
            kind: "Customer".into(),
            indexed_at_ms: 10,
            last_dataset_row_id: 3,
            member_count: 1,
            stale: false,
            quarantine_reason: String::new(),
            lag_ms: 5,
        };
        assert!(freshness_holds(&status, 0));
        assert!(freshness_holds(&status, 10));
        status.lag_ms = 50;
        assert!(!freshness_holds(&status, 10));
        status.lag_ms = 1;
        status.stale = true;
        assert!(!freshness_holds(&status, 10_000));
    }
}
