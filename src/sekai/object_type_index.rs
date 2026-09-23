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

/// Keep only plan-needed properties from a stored member JSON map.
/// `None` keeps the full map. An empty slice skips deserialize of unused keys
/// by returning an empty map when `raw` is ignored by callers; when `raw` is
/// present this still parses once and retains named keys.
pub fn project_member_properties(
    raw: &str,
    needed: Option<&[String]>,
) -> Result<BTreeMap<String, String>, String> {
    match needed {
        None => serde_json::from_str(raw).map_err(|error| error.to_string()),
        Some([]) => Ok(BTreeMap::new()),
        Some(keys) => {
            let value: serde_json::Value =
                serde_json::from_str(raw).map_err(|error| error.to_string())?;
            let Some(object) = value.as_object() else {
                return Err("index member properties must be a JSON object".into());
            };
            let mut properties = BTreeMap::new();
            for key in keys {
                if let Some(serde_json::Value::String(text)) = object.get(key) {
                    properties.insert(key.clone(), text.clone());
                }
            }
            Ok(properties)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexSqlDialect {
    Sqlite,
    Postgres,
}

/// Push eq/gt/gte/lt/lte onto stored member JSON so evaluate does not
/// decode every kind row. Unknown ops fail closed (no rows).
pub fn member_filter_sql(
    dialect: IndexSqlDialect,
    filters: &[crate::sekai::dataset::RowFilter],
) -> Result<(String, Vec<String>), String> {
    let mut clause = String::new();
    let mut values = Vec::new();
    let mut param = 3usize;
    for filter in filters {
        if filter.column.is_empty() || filter.column.contains('\'') || filter.column.contains('"') {
            return Err(format!("invalid index filter key {}", filter.column));
        }
        let extract = match dialect {
            IndexSqlDialect::Sqlite => {
                format!("json_extract(properties, '$.{}')", filter.column)
            }
            IndexSqlDialect::Postgres => {
                format!("(properties::json ->> '{}')", filter.column)
            }
        };
        let placeholder = match dialect {
            IndexSqlDialect::Sqlite => format!("?{param}"),
            IndexSqlDialect::Postgres => format!("${param}"),
        };
        let pred = match filter.op.as_str() {
            "eq" | "" => {
                values.push(filter.value.clone());
                param += 1;
                format!("{extract} = {placeholder}")
            }
            "gt" | "lt" | "gte" | "lte" => {
                let cmp = match filter.op.as_str() {
                    "gt" => ">",
                    "lt" => "<",
                    "gte" => ">=",
                    _ => "<=",
                };
                values.push(filter.value.clone());
                param += 1;
                match dialect {
                    IndexSqlDialect::Sqlite => format!(
                        "({extract} IS NOT NULL AND {extract} GLOB '*[0-9]*' AND {extract} NOT GLOB '*[A-Za-z]*' AND CAST({extract} AS REAL) {cmp} CAST({placeholder} AS REAL))"
                    ),
                    IndexSqlDialect::Postgres => format!(
                        "({extract} IS NOT NULL AND {extract} ~ '^[+-]?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$' AND ({extract})::float8 {cmp} ({placeholder})::float8)"
                    ),
                }
            }
            _ => "0".into(),
        };
        clause.push_str(" AND ");
        clause.push_str(&pred);
    }
    Ok((clause, values))
}

/// SQL expression for the member properties column. `None` keeps the stored
/// wide JSON. Named keys are projected with `json_object` / `jsonb_build_object`.
pub fn member_properties_sql(
    dialect: IndexSqlDialect,
    needed: Option<&[String]>,
) -> Result<String, String> {
    let Some(keys) = needed else {
        return Ok("properties".into());
    };
    for key in keys {
        if key.is_empty() || key.contains('\'') || key.contains('"') {
            return Err(format!("invalid index projection key {key}"));
        }
    }
    if keys.is_empty() {
        return Ok(match dialect {
            IndexSqlDialect::Sqlite => "json_object()".into(),
            IndexSqlDialect::Postgres => "'{}'::text".into(),
        });
    }
    Ok(match dialect {
        IndexSqlDialect::Sqlite => {
            let pairs = keys
                .iter()
                .map(|key| format!("'{key}', json_extract(properties, '$.{key}')"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("json_object({pairs})")
        }
        IndexSqlDialect::Postgres => {
            let pairs = keys
                .iter()
                .map(|key| format!("'{key}', properties::json -> '{key}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("jsonb_build_object({pairs})::text")
        }
    })
}

/// `LIMIT`/`OFFSET` after a filter clause. `next_param` is the next bind index.
pub fn member_page_sql(
    dialect: IndexSqlDialect,
    limit: i32,
    offset: i32,
    mut next_param: usize,
) -> (String, Vec<i64>, usize) {
    // PostgreSQL infers LIMIT and OFFSET parameters as bigint.
    let mut sql = String::new();
    let mut values = Vec::new();
    let offset = offset.max(0);
    if limit > 0 {
        sql.push_str(&match dialect {
            IndexSqlDialect::Sqlite => format!(" LIMIT ?{next_param}"),
            IndexSqlDialect::Postgres => format!(" LIMIT ${next_param}"),
        });
        values.push(i64::from(limit));
        next_param += 1;
        sql.push_str(&match dialect {
            IndexSqlDialect::Sqlite => format!(" OFFSET ?{next_param}"),
            IndexSqlDialect::Postgres => format!(" OFFSET ${next_param}"),
        });
        values.push(i64::from(offset));
        next_param += 1;
    } else if offset > 0 {
        sql.push_str(&match dialect {
            IndexSqlDialect::Sqlite => format!(" LIMIT -1 OFFSET ?{next_param}"),
            IndexSqlDialect::Postgres => format!(" OFFSET ${next_param}"),
        });
        values.push(i64::from(offset));
        next_param += 1;
    }
    (sql, values, next_param)
}

/// One evaluate fence row: ready bit, join generation, and catalog digest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HopProjectionFence {
    pub ready: bool,
    pub generation: String,
    pub definition_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopProjectionAdmit {
    Admit,
    Reject,
    CountFallback,
}

/// Admit from the stamped receipt. Skip COUNT when generation matches the
/// published catalog. Digest mismatch fails closed. Empty generation keeps
/// the wipe-detector COUNT path for rows that have not been restamped.
pub fn admit_hop_projection_fence(
    fence: &HopProjectionFence,
    published: &str,
) -> HopProjectionAdmit {
    if !fence.ready {
        return HopProjectionAdmit::Reject;
    }
    if !published.is_empty()
        && !fence.definition_digest.is_empty()
        && fence.definition_digest != published
    {
        return HopProjectionAdmit::Reject;
    }
    if !fence.generation.is_empty() && (published.is_empty() || fence.generation == published) {
        return HopProjectionAdmit::Admit;
    }
    HopProjectionAdmit::CountFallback
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
    /// Physical join generation, distinct from catalog `definition_digest`.
    /// Changing dataset, key, mapping, hidden, edits-only, or digest is a new
    /// hop-projection generation and must fail closed until reindex.
    pub fn changes_hop_generation(&self, next: &Self) -> bool {
        self.definition_digest != next.definition_digest
            || self.dataset_id != next.dataset_id
            || self.key_column != next.key_column
            || self.property_mapping != next.property_mapping
            || self.hidden_column != next.hidden_column
            || self.edits_only != next.edits_only
    }

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

    #[test]
    fn project_member_properties_keeps_only_needed_keys() {
        let raw = r#"{"region":"eu","amount":"10","extra":"drop"}"#;
        let needed = ["region".into(), "amount".into()];
        let projected = project_member_properties(raw, Some(&needed)).unwrap();
        assert_eq!(
            projected,
            BTreeMap::from([
                ("region".into(), "eu".into()),
                ("amount".into(), "10".into())
            ])
        );
        assert!(
            project_member_properties(raw, Some(&[]))
                .unwrap()
                .is_empty()
        );
        assert_eq!(project_member_properties(raw, None).unwrap().len(), 3);
    }

    #[test]
    fn member_filter_sql_pushes_eq_and_numeric_predicates() {
        let filters = [
            crate::sekai::dataset::RowFilter {
                column: "tier".into(),
                op: "gte".into(),
                value: "2".into(),
            },
            crate::sekai::dataset::RowFilter {
                column: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            },
        ];
        let (sqlite, values) = member_filter_sql(IndexSqlDialect::Sqlite, &filters).unwrap();
        assert!(sqlite.contains("json_extract(properties, '$.tier')"));
        assert!(sqlite.contains("CAST("));
        assert!(sqlite.contains("json_extract(properties, '$.region') = ?4"));
        assert_eq!(values, ["2".to_string(), "eu".into()]);
        let (postgres, _) = member_filter_sql(IndexSqlDialect::Postgres, &filters).unwrap();
        assert!(postgres.contains("properties::json ->> 'tier'"));
        assert!(postgres.contains("::float8"));
    }

    #[test]
    fn member_properties_and_page_sql_are_exact() {
        let needed = ["region".into()];
        let sqlite_props = member_properties_sql(IndexSqlDialect::Sqlite, Some(&needed)).unwrap();
        assert_eq!(
            sqlite_props,
            "json_object('region', json_extract(properties, '$.region'))"
        );
        let postgres_props =
            member_properties_sql(IndexSqlDialect::Postgres, Some(&needed)).unwrap();
        assert_eq!(
            postgres_props,
            "jsonb_build_object('region', properties::json -> 'region')::text"
        );
        let (sqlite_page, sqlite_values, next) = member_page_sql(IndexSqlDialect::Sqlite, 1, 1, 4);
        assert_eq!(sqlite_page, " LIMIT ?4 OFFSET ?5");
        assert_eq!(sqlite_values, [1, 1]);
        assert_eq!(next, 6);
        let (postgres_page, postgres_values, _) =
            member_page_sql(IndexSqlDialect::Postgres, 1, 1, 4);
        assert_eq!(postgres_page, " LIMIT $4 OFFSET $5");
        assert_eq!(postgres_values, [1, 1]);
    }

    #[test]
    fn admit_hop_projection_fence_skips_count_when_generation_matches() {
        let fence = HopProjectionFence {
            ready: true,
            generation: "rev-1".into(),
            definition_digest: "rev-1".into(),
        };
        assert_eq!(
            admit_hop_projection_fence(&fence, "rev-1"),
            HopProjectionAdmit::Admit
        );
        assert_eq!(
            admit_hop_projection_fence(&fence, "rev-2"),
            HopProjectionAdmit::Reject
        );
        assert_eq!(
            admit_hop_projection_fence(
                &HopProjectionFence {
                    ready: true,
                    generation: String::new(),
                    definition_digest: "rev-1".into(),
                },
                "rev-1"
            ),
            HopProjectionAdmit::CountFallback
        );
        assert_eq!(
            admit_hop_projection_fence(&HopProjectionFence::default(), "rev-1"),
            HopProjectionAdmit::Reject
        );
    }
}
