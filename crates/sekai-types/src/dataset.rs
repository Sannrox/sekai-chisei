//! Dataset records, row filters, and partition-key helpers.
//!
//! SQLite/Postgres hosts stay in the plane. These values are shared with the
//! store so query and index signatures do not name the mega crate.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::governed_transform::partition_value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetRedaction {
    pub rows_updated: i32,
    pub fields_redacted: i32,
}

pub fn llm_call_column_classification(name: &str) -> &'static str {
    if matches!(
        name,
        "request_id" | "agent" | "user_id" | "key_id" | "work_unit_id" | "refusal_reason"
    ) {
        "sensitive"
    } else if matches!(
        name,
        "project" | "route_bias" | "policy_scope" | "policy_version"
    ) {
        "internal"
    } else {
        "public"
    }
}

pub type DatasetRowRecord = (i64, HashMap<String, String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub id: String,
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub object_id: String,
    pub created: i64,
    pub partition_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowFilter {
    pub column: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RowQuery {
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualTable {
    pub id: String,
    pub name: String,
    pub dataset_id: String,
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub created: i64,
}

pub fn encode_partition_keys(keys: &[String]) -> Result<String, String> {
    serde_json::to_string(keys).map_err(|error| error.to_string())
}

pub fn parse_partition_keys(value: &str) -> Result<Vec<String>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(value).map_err(|error| format!("corrupt dataset partition_keys: {error}"))
}

pub fn partition_key_for_row_json(keys: &[String], data: &str) -> Result<String, String> {
    let row: HashMap<String, String> =
        serde_json::from_str(data).map_err(|error| format!("corrupt dataset row: {error}"))?;
    Ok(partition_value(keys, &row))
}

fn compare_numeric(left: &str, right: &str, op: &str) -> bool {
    let (Ok(left), Ok(right)) = (left.parse::<f64>(), right.parse::<f64>()) else {
        return false;
    };
    match op {
        "gt" => left > right,
        "lt" => left < right,
        "gte" => left >= right,
        "lte" => left <= right,
        _ => false,
    }
}

/// Shared property compare for dataset rows and object-type index reads.
/// Unknown operators and non-numeric inequalities fail closed (no match).
pub fn row_value_matches(actual: &str, op: &str, expected: &str) -> bool {
    match op {
        "eq" | "" => actual == expected,
        "neq" => actual != expected,
        "gt" | "lt" | "gte" | "lte" => compare_numeric(actual, expected, op),
        _ => false,
    }
}

pub fn matches_row_filters(row: &HashMap<String, String>, filters: &[RowFilter]) -> bool {
    for filter in filters {
        let Some(value) = row.get(&filter.column) else {
            return false;
        };
        if !row_value_matches(value, &filter.op, &filter.value) {
            return false;
        }
    }
    true
}
