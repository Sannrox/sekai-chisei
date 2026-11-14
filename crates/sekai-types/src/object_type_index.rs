//! Rebuildable object-type membership projection (#877).
//!
//! A registered dataset plus key mapping is the source of members. The index is
//! not object authority: deleting it and rematerializing from dataset rows and
//! Action deltas must restore visible membership. Hidden rows never contribute
//! to members, counts, order, errors, or continuation tokens.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use crate::object_schema::{ObjectType, PropertyValue, coerce_properties};

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
) -> Result<BTreeMap<String, PropertyValue>, String> {
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
                match object.get(key) {
                    Some(cell) if !cell.is_null() => {
                        properties.insert(key.clone(), PropertyValue::from_json(cell)?);
                    }
                    _ => {}
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
    filters: &[crate::dataset::RowFilter],
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
                eq_predicate(
                    dialect,
                    &extract,
                    &placeholder,
                    &filter.column,
                    &filter.value,
                )
            }
            "gt" | "lt" | "gte" | "lte" => {
                if filter
                    .value
                    .parse::<f64>()
                    .ok()
                    .filter(|float| float.is_finite())
                    .is_none()
                {
                    "1=0".into()
                } else {
                    let cmp = match filter.op.as_str() {
                        "gt" => ">",
                        "lt" => "<",
                        "gte" => ">=",
                        _ => "<=",
                    };
                    let integer_range = filter.value.parse::<i64>().is_ok();
                    values.push(filter.value.clone());
                    param += 1;
                    match dialect {
                        IndexSqlDialect::Sqlite => {
                            let typed = format!("json_extract(properties, '$.{}')", filter.column);
                            if integer_range {
                                format!(
                                    "({typed} IS NOT NULL AND ((typeof({typed}) = 'integer' AND {typed} {cmp} CAST({placeholder} AS INTEGER)) OR (typeof({typed}) = 'real' AND CAST({typed} AS REAL) {cmp} CAST({placeholder} AS REAL)) OR (typeof({typed}) = 'text' AND {typed} GLOB '*[0-9]*' AND {typed} NOT GLOB '*[A-Za-z]*' AND CAST({typed} AS REAL) {cmp} CAST({placeholder} AS REAL))))"
                                )
                            } else {
                                format!(
                                    "({typed} IS NOT NULL AND ((typeof({typed}) IN ('integer', 'real') AND {typed} {cmp} CAST({placeholder} AS REAL)) OR (typeof({typed}) = 'text' AND {typed} GLOB '*[0-9]*' AND {typed} NOT GLOB '*[A-Za-z]*' AND CAST({typed} AS REAL) {cmp} CAST({placeholder} AS REAL))))"
                                )
                            }
                        }
                        IndexSqlDialect::Postgres => {
                            let json_num = format!("(properties::json -> '{}')", filter.column);
                            format!(
                                "({json_num} IS NOT NULL AND ((jsonb_typeof({json_num}::jsonb) = 'number' AND ({json_num} #>> '{{}}')::numeric {cmp} ({placeholder})::numeric) OR (jsonb_typeof({json_num}::jsonb) = 'string' AND ({extract}) ~ '^[+-]?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$' AND ({extract})::numeric {cmp} ({placeholder})::numeric)))"
                            )
                        }
                    }
                }
            }
            _ => "1=0".into(),
        };
        clause.push_str(" AND ");
        clause.push_str(&pred);
    }
    Ok((clause, values))
}

fn eq_predicate(
    dialect: IndexSqlDialect,
    extract: &str,
    placeholder: &str,
    column: &str,
    value: &str,
) -> String {
    let integer_eq = value.parse::<i64>().is_ok();
    let float_eq = !integer_eq
        && value
            .parse::<f64>()
            .ok()
            .filter(|float| float.is_finite())
            .is_some();
    match dialect {
        IndexSqlDialect::Sqlite => {
            let json_type = format!("json_type(properties, '$.{column}')");
            let mut sql = format!(
                "({extract} = {placeholder} OR (typeof({extract}) IN ('integer', 'real') AND CAST({extract} AS TEXT) = {placeholder})"
            );
            if integer_eq {
                sql.push_str(&format!(
                    " OR (typeof({extract}) IN ('integer', 'real') AND {extract} = CAST({placeholder} AS INTEGER) AND {extract} = CAST({extract} AS INTEGER))"
                ));
            } else if float_eq {
                sql.push_str(&format!(
                    " OR (typeof({extract}) = 'real' AND CAST({extract} AS REAL) = CAST({placeholder} AS REAL))"
                ));
            }
            sql.push_str(&format!(
                " OR ({json_type} = 'true' AND {placeholder} IN ('true', '1')) OR ({json_type} = 'false' AND {placeholder} IN ('false', '0')))"
            ));
            sql
        }
        IndexSqlDialect::Postgres => {
            let json_num = format!("(properties::json -> '{column}')");
            let mut sql = format!("({extract} = {placeholder}");
            if integer_eq {
                sql.push_str(&format!(
                    " OR ({json_num} IS NOT NULL AND jsonb_typeof({json_num}::jsonb) = 'number' AND ({json_num} #>> '{{}}')::numeric = ({placeholder})::numeric)"
                ));
            } else if float_eq {
                sql.push_str(&format!(
                    " OR ({json_num} IS NOT NULL AND jsonb_typeof({json_num}::jsonb) = 'number' AND ({json_num} #>> '{{}}') ~ '[.eE]' AND ({json_num} #>> '{{}}')::float8 = ({placeholder})::float8)"
                ));
            }
            sql.push_str(&format!(
                " OR ({json_num} IS NOT NULL AND jsonb_typeof({json_num}::jsonb) = 'boolean' AND (({placeholder} IN ('true', '1') AND ({json_num} #>> '{{}}') = 'true') OR ({placeholder} IN ('false', '0') AND ({json_num} #>> '{{}}') = 'false'))))"
            ));
            sql
        }
    }
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
                .map(|key| {
                    format!(
                        "'{key}', CASE json_type(properties, '$.{key}') WHEN 'true' THEN json('true') WHEN 'false' THEN json('false') ELSE json_extract(properties, '$.{key}') END"
                    )
                })
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

impl From<ObjectTypeIndexError> for String {
    fn from(value: ObjectTypeIndexError) -> Self {
        value.message()
    }
}

/// How a later source value and a stored property edit share one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum EditConflictRule {
    /// The latest edit for a property keeps that property (default).
    #[default]
    EditWins,
    /// The later of the edit time and the source timestamp property wins.
    NewestWins,
}

impl EditConflictRule {
    pub const EDIT_WINS: &'static str = "edit_wins";
    pub const NEWEST_WINS: &'static str = "newest_wins";

    pub fn parse(value: &str) -> Result<Self, ObjectTypeIndexError> {
        match value.trim() {
            "" | Self::EDIT_WINS => Ok(Self::EditWins),
            Self::NEWEST_WINS => Ok(Self::NewestWins),
            other => Err(ObjectTypeIndexError::InvalidArgument(format!(
                "unsupported edit conflict rule {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EditWins => Self::EDIT_WINS,
            Self::NewestWins => Self::NEWEST_WINS,
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
    /// `edit_wins` (default) or `newest_wins`. Empty is `edit_wins`.
    #[serde(default)]
    pub conflict_rule: String,
    /// Source property compared to the edit time when `conflict_rule` is `newest_wins`.
    #[serde(default)]
    pub source_timestamp_property: String,
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
    pub properties: BTreeMap<String, PropertyValue>,
    pub content_hash: String,
    pub hidden: bool,
    pub from_edit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectTypeIndexEdit {
    pub namespace: String,
    pub kind: String,
    pub source_key: String,
    pub properties: BTreeMap<String, PropertyValue>,
    pub hidden: bool,
    /// Overlay retry key. Empty until an Action or `PutObjectTypeIndexEdit` names one.
    #[serde(default)]
    pub action_id: String,
    /// Clerk time of this overlay, milliseconds since Unix epoch.
    #[serde(default)]
    pub edited_at_ms: i64,
    /// Per-property overlay times. Empty keys fall back to `edited_at_ms`.
    #[serde(default)]
    pub property_edited_at_ms: BTreeMap<String, i64>,
}

/// Decode the SQL JSON sidecar of per-property overlay times.
pub fn parse_property_edit_times(raw: &str) -> Result<BTreeMap<String, i64>, String> {
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(raw).map_err(|error| error.to_string())
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
            || self.conflict_rule() != next.conflict_rule()
            || self.source_timestamp_property != next.source_timestamp_property
    }

    pub fn conflict_rule(&self) -> EditConflictRule {
        EditConflictRule::parse(&self.conflict_rule).unwrap_or(EditConflictRule::EditWins)
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
        let rule = EditConflictRule::parse(&self.conflict_rule)?;
        if rule == EditConflictRule::NewestWins {
            require_token("source_timestamp_property", &self.source_timestamp_property)?;
        }
        Ok(self)
    }
}

pub fn schema_drift(
    binding: &ObjectTypeDatasource,
    columns: &[crate::dataset::ColumnDef],
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
            properties.insert(property.clone(), PropertyValue::String(value.clone()));
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

/// Coerce index cells with the declared object type. Missing schema keeps
/// the inbound values.
pub fn coerce_index_properties(
    object_type: Option<&ObjectType>,
    properties: BTreeMap<String, PropertyValue>,
) -> Result<BTreeMap<String, PropertyValue>, ObjectTypeIndexError> {
    match object_type {
        Some(object_type) => coerce_properties(object_type, properties)
            .map_err(ObjectTypeIndexError::InvalidArgument),
        None => Ok(properties),
    }
}

pub fn coerce_index_member(
    mut member: ObjectTypeIndexMember,
    object_type: Option<&ObjectType>,
) -> Result<ObjectTypeIndexMember, ObjectTypeIndexError> {
    member.properties = coerce_index_properties(object_type, member.properties)?;
    member.content_hash = content_hash(&member.properties, member.hidden);
    Ok(member)
}

pub fn coerce_index_edit(
    object_type: Option<&ObjectType>,
    mut edit: ObjectTypeIndexEdit,
) -> Result<ObjectTypeIndexEdit, ObjectTypeIndexError> {
    edit.properties = coerce_index_properties(object_type, edit.properties)?;
    Ok(edit)
}

pub fn member_from_edit(
    binding: &ObjectTypeDatasource,
    edit: &ObjectTypeIndexEdit,
) -> ObjectTypeIndexMember {
    overlay_member(binding, None, edit).unwrap_or_else(|_| ObjectTypeIndexMember {
        namespace: binding.namespace.clone(),
        kind: binding.kind.clone(),
        object_id: sourced_object_id(&binding.kind, &edit.source_key),
        source_key: edit.source_key.clone(),
        content_hash: content_hash(&edit.properties, edit.hidden),
        properties: edit.properties.clone(),
        hidden: edit.hidden,
        from_edit: true,
    })
}

/// Overlay the latest edit per property onto a source member. Unedited
/// properties keep the source value. `newest_wins` keeps a later source
/// timestamp over an older edit.
pub fn overlay_member(
    binding: &ObjectTypeDatasource,
    source: Option<ObjectTypeIndexMember>,
    edit: &ObjectTypeIndexEdit,
) -> Result<ObjectTypeIndexMember, ObjectTypeIndexError> {
    let had_source = source.is_some();
    let mut member = match source {
        Some(member) => member,
        None => ObjectTypeIndexMember {
            namespace: binding.namespace.clone(),
            kind: binding.kind.clone(),
            object_id: sourced_object_id(&binding.kind, &edit.source_key),
            source_key: edit.source_key.clone(),
            content_hash: String::new(),
            properties: BTreeMap::new(),
            hidden: false,
            from_edit: false,
        },
    };
    let rule = binding.conflict_rule();
    let source_ts = member
        .properties
        .get(&binding.source_timestamp_property)
        .and_then(PropertyValue::timestamp_millis);
    let mut from_edit = member.from_edit;
    for (property, value) in &edit.properties {
        if property.starts_with("__sekai_index_") {
            continue;
        }
        let keep_edit = if !had_source {
            true
        } else {
            match rule {
                EditConflictRule::EditWins => true,
                EditConflictRule::NewestWins => {
                    let edit_ts = edit
                        .property_edited_at_ms
                        .get(property)
                        .copied()
                        .unwrap_or(edit.edited_at_ms);
                    edit_is_newer(edit_ts, source_ts)?
                }
            }
        };
        if keep_edit {
            member.properties.insert(property.clone(), value.clone());
            from_edit = true;
        }
    }
    let source_hidden = had_source && member.hidden;
    member.hidden = source_hidden || edit.hidden;
    if member.hidden != source_hidden {
        from_edit = true;
    }
    member.from_edit = from_edit;
    member.content_hash = content_hash(&member.properties, member.hidden);
    Ok(member)
}

/// Merge a later sparse overlay into the stored latest-per-property projection.
pub fn merge_index_edits(
    stored: Option<ObjectTypeIndexEdit>,
    incoming: ObjectTypeIndexEdit,
) -> ObjectTypeIndexEdit {
    let incoming = stamp_property_edit_times(incoming);
    let Some(stored) = stored else {
        return incoming;
    };
    let mut stored = stamp_property_edit_times(stored);
    if !incoming.action_id.is_empty() && incoming.action_id == stored.action_id {
        let retry = incoming
            .properties
            .iter()
            .all(|(key, value)| stored.properties.get(key) == Some(value))
            && stored.hidden == incoming.hidden;
        if retry {
            return stored;
        }
        return incoming;
    }
    for (key, value) in incoming.properties {
        stored.properties.insert(key.clone(), value);
        if let Some(at) = incoming.property_edited_at_ms.get(&key) {
            stored.property_edited_at_ms.insert(key, *at);
        }
    }
    stored.hidden = incoming.hidden;
    if !incoming.action_id.is_empty() {
        stored.action_id = incoming.action_id;
    }
    if incoming.edited_at_ms >= stored.edited_at_ms {
        stored.edited_at_ms = incoming.edited_at_ms;
    }
    stored
}

fn stamp_property_edit_times(mut edit: ObjectTypeIndexEdit) -> ObjectTypeIndexEdit {
    for key in edit.properties.keys() {
        edit.property_edited_at_ms
            .entry(key.clone())
            .or_insert(edit.edited_at_ms);
    }
    edit
}

/// One-to-one property-key remap between datasource mappings.
pub fn mapping_renames(
    previous: &BTreeMap<String, String>,
    next: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let removed: Vec<String> = previous
        .keys()
        .filter(|key| !next.contains_key(*key))
        .cloned()
        .collect();
    let added: Vec<String> = next
        .keys()
        .filter(|key| !previous.contains_key(*key))
        .cloned()
        .collect();
    if removed.len() == 1 && added.len() == 1 {
        let old = &removed[0];
        let new = &added[0];
        if previous.get(old) == next.get(new) {
            vec![(old.clone(), new.clone())]
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

/// Carry edits through a property rename. Type recasts that cannot parse
/// fail with the affected count.
pub fn carry_index_edits(
    edits: &mut [ObjectTypeIndexEdit],
    rename: &[(String, String)],
    recast: &[(String, crate::object_schema::PropertyType)],
) -> Result<(), ObjectTypeIndexError> {
    for (old, new) in rename {
        if old == new {
            continue;
        }
        for edit in edits.iter_mut() {
            if let Some(value) = edit.properties.remove(old) {
                edit.properties.entry(new.clone()).or_insert(value);
            }
            if let Some(at) = edit.property_edited_at_ms.remove(old) {
                edit.property_edited_at_ms.entry(new.clone()).or_insert(at);
            }
        }
    }
    for (property, prop_type) in recast {
        let mut failed = 0i32;
        for edit in edits.iter_mut() {
            let Some(value) = edit.properties.get(property).cloned() else {
                continue;
            };
            match recast_edit_value(value, prop_type.clone()) {
                Ok(canonical) => {
                    edit.properties.insert(property.clone(), canonical);
                }
                Err(()) => failed += 1,
            }
        }
        if failed > 0 {
            return Err(ObjectTypeIndexError::InvalidArgument(format!(
                "type revision cannot recast {failed} edits of property {property} to {}",
                prop_type.as_str()
            )));
        }
    }
    Ok(())
}

fn recast_edit_value(
    value: PropertyValue,
    prop_type: crate::object_schema::PropertyType,
) -> Result<PropertyValue, ()> {
    // Recast is given only a PropertyType, not the enum membership list.
    // Keep enum strings as cells; later schema validation owns allowed values.
    if prop_type == crate::object_schema::PropertyType::Enum {
        return Ok(match value {
            PropertyValue::String(text) => PropertyValue::String(text),
            other => PropertyValue::String(other.as_cell()),
        });
    }
    let declared = crate::object_schema::PropertyDef {
        name: String::new(),
        prop_type,
        required: false,
        description: String::new(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: crate::object_schema::default_property_classification(),
        struct_fields: Vec::new(),
    };
    crate::object_schema::coerce_property_value("", &declared, value).map_err(|_| ())
}

fn edit_is_newer(edited_at_ms: i64, source_ts: Option<i64>) -> Result<bool, ObjectTypeIndexError> {
    let Some(source_ms) = source_ts else {
        return Err(ObjectTypeIndexError::InvalidArgument(
            "newest conflict requires source timestamp".into(),
        ));
    };
    Ok(edited_at_ms >= source_ms)
}

pub fn sourced_object_id(kind: &str, source_key: &str) -> String {
    format!("{kind}:{source_key}")
}

pub fn content_hash(properties: &BTreeMap<String, PropertyValue>, hidden: bool) -> String {
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
    use crate::dataset::ColumnDef;

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
            conflict_rule: String::new(),
            source_timestamp_property: String::new(),
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
    fn overlay_keeps_unedited_source_properties() {
        let source = member_from_row(
            &binding(),
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let edit = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-1".into(),
            edited_at_ms: 20,
            property_edited_at_ms: Default::default(),
        };
        let overlaid = overlay_member(&binding(), Some(source), &edit).unwrap();
        assert_eq!(overlaid.properties.get("region").unwrap(), "edited");
        assert!(overlaid.from_edit);
    }

    #[test]
    fn newest_wins_keeps_later_source_value() {
        let mut binding = binding();
        binding
            .property_mapping
            .insert("updated_at".into(), "updated_at".into());
        binding.conflict_rule = EditConflictRule::NEWEST_WINS.into();
        binding.source_timestamp_property = "updated_at".into();
        let binding = binding.prepare().unwrap();
        let source = member_from_row(
            &binding,
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("updated_at".into(), "50".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let edit = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-1".into(),
            edited_at_ms: 20,
            property_edited_at_ms: Default::default(),
        };
        let overlaid = overlay_member(&binding, Some(source), &edit).unwrap();
        assert_eq!(overlaid.properties.get("region").unwrap(), "us");
    }

    #[test]
    fn newest_wins_uses_per_property_edit_times() {
        let mut binding = binding();
        binding
            .property_mapping
            .insert("name".into(), "name".into());
        binding
            .property_mapping
            .insert("updated_at".into(), "updated_at".into());
        binding.conflict_rule = EditConflictRule::NEWEST_WINS.into();
        binding.source_timestamp_property = "updated_at".into();
        let binding = binding.prepare().unwrap();
        let source = member_from_row(
            &binding,
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("name".into(), "Ada".into()),
                ("updated_at".into(), "20".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let edit = merge_index_edits(
            Some(ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 10,
                property_edited_at_ms: BTreeMap::new(),
            }),
            ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("name".into(), "Ada L.".into())]),
                hidden: false,
                action_id: "act-name".into(),
                edited_at_ms: 30,
                property_edited_at_ms: BTreeMap::new(),
            },
        );
        let overlaid = overlay_member(&binding, Some(source), &edit).unwrap();
        assert_eq!(overlaid.properties.get("region").unwrap(), "us");
        assert_eq!(overlaid.properties.get("name").unwrap(), "Ada L.");
    }

    #[test]
    fn merge_same_action_id_keeps_admission_time() {
        let first = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-1".into(),
            edited_at_ms: 20,
            property_edited_at_ms: BTreeMap::new(),
        };
        let retry = ObjectTypeIndexEdit {
            edited_at_ms: 40,
            ..first.clone()
        };
        let merged = merge_index_edits(Some(first.clone()), retry);
        assert_eq!(merged.edited_at_ms, 20);
        assert_eq!(merged.properties, first.properties);
    }

    #[test]
    fn merge_sparse_retry_keeps_accumulated_properties() {
        let region = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-region".into(),
            edited_at_ms: 10,
            property_edited_at_ms: BTreeMap::new(),
        };
        let name = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("name".into(), "Ada L.".into())]),
            hidden: false,
            action_id: "act-name".into(),
            edited_at_ms: 30,
            property_edited_at_ms: BTreeMap::new(),
        };
        let stored = merge_index_edits(Some(region), name.clone());
        let retried = merge_index_edits(Some(stored.clone()), name);
        assert_eq!(retried.properties.get("region").unwrap(), "edited");
        assert_eq!(retried.properties.get("name").unwrap(), "Ada L.");
        assert_eq!(retried.action_id, stored.action_id);
        assert_eq!(retried.edited_at_ms, stored.edited_at_ms);
    }

    #[test]
    fn mapping_rename_requires_the_same_source_column() {
        let previous = BTreeMap::from([("region".into(), "region".into())]);
        let renamed = BTreeMap::from([("area".into(), "region".into())]);
        assert_eq!(
            mapping_renames(&previous, &renamed),
            vec![("region".into(), "area".into())]
        );
        let replaced = BTreeMap::from([("age".into(), "age".into())]);
        assert!(mapping_renames(&previous, &replaced).is_empty());
    }

    #[test]
    fn overlay_hidden_follows_source_or_edit() {
        let source = member_from_row(
            &binding(),
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let hide = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::new(),
            hidden: true,
            action_id: "act-hide".into(),
            edited_at_ms: 20,
            property_edited_at_ms: BTreeMap::new(),
        };
        assert!(
            overlay_member(&binding(), Some(source.clone()), &hide)
                .unwrap()
                .hidden
        );
        let show = ObjectTypeIndexEdit {
            hidden: false,
            action_id: "act-show".into(),
            ..hide
        };
        assert!(
            !overlay_member(&binding(), Some(source), &show)
                .unwrap()
                .hidden
        );
    }

    #[test]
    fn newest_wins_pads_fractional_rfc3339_seconds() {
        let mut binding = binding();
        binding
            .property_mapping
            .insert("updated_at".into(), "updated_at".into());
        binding.conflict_rule = EditConflictRule::NEWEST_WINS.into();
        binding.source_timestamp_property = "updated_at".into();
        let binding = binding.prepare().unwrap();
        let source = member_from_row(
            &binding,
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("updated_at".into(), "1970-01-01T00:00:00.1Z".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let edit = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-1".into(),
            edited_at_ms: 50,
            property_edited_at_ms: BTreeMap::new(),
        };
        let overlaid = overlay_member(&binding, Some(source), &edit).unwrap();
        assert_eq!(overlaid.properties.get("region").unwrap(), "us");
    }

    #[test]
    fn newest_wins_accepts_rfc3339_timezone_offsets() {
        let mut binding = binding();
        binding
            .property_mapping
            .insert("updated_at".into(), "updated_at".into());
        binding.conflict_rule = EditConflictRule::NEWEST_WINS.into();
        binding.source_timestamp_property = "updated_at".into();
        let binding = binding.prepare().unwrap();
        let source = member_from_row(
            &binding,
            &HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("updated_at".into(), "1970-01-01T00:01:00+01:00".into()),
                ("hidden".into(), "0".into()),
            ]),
        )
        .unwrap();
        let edit = ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-offset".into(),
            edited_at_ms: 50,
            property_edited_at_ms: BTreeMap::new(),
        };
        let overlaid = overlay_member(&binding, Some(source), &edit).unwrap();
        assert_eq!(overlaid.properties.get("region").unwrap(), "edited");
    }

    #[test]
    fn property_rename_carries_edits_and_recast_names_the_count() {
        let mut edits = [ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "eu".into())]),
            hidden: false,
            action_id: "act-1".into(),
            edited_at_ms: 20,
            property_edited_at_ms: Default::default(),
        }];
        carry_index_edits(&mut edits, &[("region".into(), "area".into())], &[]).unwrap();
        assert_eq!(edits[0].properties.get("area").unwrap(), "eu");
        carry_index_edits(
            &mut edits,
            &[],
            &[("area".into(), crate::object_schema::PropertyType::Enum)],
        )
        .unwrap();
        assert_eq!(edits[0].properties.get("area").unwrap(), "eu");
        let mut bad = [ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("rank".into(), "north".into())]),
            hidden: false,
            action_id: "act-2".into(),
            edited_at_ms: 20,
            property_edited_at_ms: Default::default(),
        }];
        let error = carry_index_edits(
            &mut bad,
            &[],
            &[("rank".into(), crate::object_schema::PropertyType::Int)],
        )
        .unwrap_err();
        assert!(error.message().contains("1 edits of property rank"));
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
        let with_null = r#"{"region":"eu","amount":null}"#;
        assert_eq!(
            project_member_properties(with_null, Some(&needed)).unwrap(),
            BTreeMap::from([("region".into(), "eu".into())])
        );
    }

    #[test]
    fn member_filter_sql_pushes_eq_and_numeric_predicates() {
        let filters = [
            crate::dataset::RowFilter {
                column: "tier".into(),
                op: "gte".into(),
                value: "2".into(),
            },
            crate::dataset::RowFilter {
                column: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            },
        ];
        let (sqlite, values) = member_filter_sql(IndexSqlDialect::Sqlite, &filters).unwrap();
        assert!(sqlite.contains("json_extract(properties, '$.tier')"));
        assert!(sqlite.contains("CAST("));
        assert!(sqlite.contains("json_extract(properties, '$.region') = ?4"));
        assert!(sqlite.contains("CAST("));
        assert!(sqlite.contains("json_type(properties, '$.region')"));
        assert_eq!(values, ["2".to_string(), "eu".into()]);
        let (postgres, _) = member_filter_sql(IndexSqlDialect::Postgres, &filters).unwrap();
        assert!(postgres.contains("properties::json ->> 'tier'"));
        assert!(postgres.contains("::numeric"));
        assert!(!postgres.contains("::float8"));
    }

    #[test]
    fn member_filter_sql_eq_numeric_casts_follow_operand_shape() {
        let text = [crate::dataset::RowFilter {
            column: "region".into(),
            op: "eq".into(),
            value: "eu".into(),
        }];
        let (sqlite_text, _) = member_filter_sql(IndexSqlDialect::Sqlite, &text).unwrap();
        assert!(sqlite_text.contains("json_extract(properties, '$.region') = ?3"));
        assert!(!sqlite_text.contains("AS REAL"));
        assert!(!sqlite_text.contains("AS INTEGER"));
        let (postgres_text, _) = member_filter_sql(IndexSqlDialect::Postgres, &text).unwrap();
        assert!(!postgres_text.contains("::float8"));
        assert!(!postgres_text.contains("::numeric"));

        let integer = [crate::dataset::RowFilter {
            column: "count".into(),
            op: "eq".into(),
            value: "12".into(),
        }];
        let (sqlite_int, _) = member_filter_sql(IndexSqlDialect::Sqlite, &integer).unwrap();
        assert!(sqlite_int.contains("AS INTEGER"));
        assert!(!sqlite_int.contains("AS REAL"));
        let (postgres_int, _) = member_filter_sql(IndexSqlDialect::Postgres, &integer).unwrap();
        assert!(postgres_int.contains("::numeric"));
        assert!(!postgres_int.contains("::float8"));

        let float = [crate::dataset::RowFilter {
            column: "ratio".into(),
            op: "eq".into(),
            value: "12.5".into(),
        }];
        let (sqlite_float, _) = member_filter_sql(IndexSqlDialect::Sqlite, &float).unwrap();
        assert!(sqlite_float.contains("AS REAL"));
        assert!(sqlite_float.contains("typeof(json_extract(properties, '$.ratio')) = 'real'"));
        let (postgres_float, _) = member_filter_sql(IndexSqlDialect::Postgres, &float).unwrap();
        assert!(postgres_float.contains("::float8"));
        assert!(postgres_float.contains("[.eE]"));

        let nonsense = [crate::dataset::RowFilter {
            column: "count".into(),
            op: "gt".into(),
            value: "abc".into(),
        }];
        let (sqlite_gt, _) = member_filter_sql(IndexSqlDialect::Sqlite, &nonsense).unwrap();
        assert_eq!(sqlite_gt, " AND 1=0");
        let (postgres_gt, _) = member_filter_sql(IndexSqlDialect::Postgres, &nonsense).unwrap();
        assert_eq!(postgres_gt, " AND 1=0");

        let integer_range = [crate::dataset::RowFilter {
            column: "count".into(),
            op: "gt".into(),
            value: "12".into(),
        }];
        let (sqlite_int_gt, _) =
            member_filter_sql(IndexSqlDialect::Sqlite, &integer_range).unwrap();
        assert!(sqlite_int_gt.contains("AS INTEGER"));
        let (postgres_int_gt, _) =
            member_filter_sql(IndexSqlDialect::Postgres, &integer_range).unwrap();
        assert!(postgres_int_gt.contains("::numeric"));
        assert!(!postgres_int_gt.contains("::float8"));
    }

    #[test]
    fn member_properties_and_page_sql_are_exact() {
        let needed = ["region".into()];
        let sqlite_props = member_properties_sql(IndexSqlDialect::Sqlite, Some(&needed)).unwrap();
        assert_eq!(
            sqlite_props,
            "json_object('region', CASE json_type(properties, '$.region') WHEN 'true' THEN json('true') WHEN 'false' THEN json('false') ELSE json_extract(properties, '$.region') END)"
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
