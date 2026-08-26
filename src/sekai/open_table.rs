//! Digest-pinned Iceberg and Parquet projections (#682).
//!
//! Registered sources are local snapshot evidence, not a live catalog or a
//! second write plane. Query is the `projection` class of
//! `sekai.governed-transform-execution/v1`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::dataset::RowFilter;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::markings::{
    PRINCIPAL_PROFILE_KIND, PRINCIPAL_PROFILE_SEALED_PROPERTY, PrincipalAuthority,
    parse_classification, principal_authority_from_profile, principal_profile_external_id,
    trusted_service_authority,
};
use crate::sekai::security::Role;
use crate::shomei;

pub const OPEN_TABLE_CONTRACT: &str = "sekai.open-table-source/v1";
pub const TRANSFORM_PROFILE: &str = "sekai.governed-transform-execution/v1";
pub const TRANSFORM_CLASS: &str = "projection";
pub const SCHEMA_REVISION_V1: &str = "v1";
pub const FORMAT_ICEBERG: &str = "iceberg";
pub const FORMAT_PARQUET: &str = "parquet";
pub const MAX_COLUMNS: usize = 64;
pub const MAX_ROWS: usize = 500;
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
pub const QUERY_UNAVAILABLE: &str = "open table projection is not admitted";
pub const SNAPSHOT_UNAVAILABLE: &str = "open table snapshot is unavailable";
pub const SNAPSHOT_CORRUPT: &str = "open table snapshot is corrupt";
pub const REVISION_UNSUPPORTED: &str = "open table revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "open table projections are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTableColumn {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTableSource {
    pub contract_version: String,
    pub source_id: String,
    pub namespace: String,
    pub owner: String,
    pub format: String,
    pub schema_revision: String,
    pub schema_digest: String,
    pub snapshot_digest: String,
    pub columns: Vec<OpenTableColumn>,
    pub registered_by: String,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTableSnapshot {
    pub source_id: String,
    pub snapshot_digest: String,
    pub rows: Vec<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenTableQuery {
    pub source_id: String,
    pub columns: Vec<String>,
    pub filters: Vec<RowFilter>,
    pub snapshot_digest: Option<String>,
    pub classification_ceiling: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTableProjection {
    pub profile_version: String,
    pub class: String,
    pub namespace: String,
    pub source_id: String,
    pub format: String,
    pub schema_revision: String,
    pub definition_digest: String,
    pub input_digest: String,
    pub columns: Vec<String>,
    pub row_count: u32,
    pub projection_digest: String,
    pub rows: Vec<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct SchemaPin<'a> {
    format: &'a str,
    schema_revision: &'a str,
    columns: &'a [OpenTableColumn],
}

#[derive(Serialize)]
struct DefinitionPin<'a> {
    profile_version: &'a str,
    class: &'a str,
    namespace: &'a str,
    source_id: &'a str,
    owner: &'a str,
    format: &'a str,
    schema_revision: &'a str,
    schema_digest: &'a str,
    columns: &'a [OpenTableColumn],
}

#[derive(Serialize)]
struct SnapshotPin<'a> {
    source_id: &'a str,
    rows: &'a [BTreeMap<String, String>],
}

#[derive(Serialize)]
struct ProjectionPin<'a> {
    columns: &'a [String],
    rows: &'a [BTreeMap<String, String>],
}

pub fn schema_digest_for(source: &OpenTableSource) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&SchemaPin {
            format: &source.format,
            schema_revision: &source.schema_revision,
            columns: &source.columns,
        })?
    ))
}

pub fn snapshot_digest_for(snapshot: &OpenTableSnapshot) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&SnapshotPin {
            source_id: &snapshot.source_id,
            rows: &snapshot.rows,
        })?
    ))
}

pub fn register_open_table(
    db: &RuntimeDb,
    actor: &str,
    source: &OpenTableSource,
    now_ms: i64,
) -> Result<OpenTableSource, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("register timestamp must be non-negative".into());
    }
    let validated = validate_source(source, actor, now_ms)?;
    if let Some(existing) = db.get_open_table_source(&validated.source_id)?
        && existing.owner != actor
    {
        return Err(QUERY_UNAVAILABLE.into());
    }
    db.put_open_table_source(&validated)?;
    Ok(validated)
}

pub fn admit_open_table_snapshot(
    db: &RuntimeDb,
    actor: &str,
    snapshot: &OpenTableSnapshot,
) -> Result<OpenTableSnapshot, String> {
    required("actor", actor)?;
    required("source id", &snapshot.source_id)?;
    let source = db
        .get_open_table_source(&snapshot.source_id)?
        .ok_or(QUERY_UNAVAILABLE)?;
    if source.owner != actor {
        return Err(QUERY_UNAVAILABLE.into());
    }
    let validated = validate_snapshot(&source, snapshot)?;
    db.put_open_table_snapshot(&validated)?;
    Ok(validated)
}

pub fn query_open_table(
    db: &RuntimeDb,
    actor: &str,
    query: &OpenTableQuery,
    now_ms: i64,
) -> Result<OpenTableProjection, String> {
    required("actor", actor)?;
    required("source id", &query.source_id)?;
    if now_ms < 0 {
        return Err("query timestamp must be non-negative".into());
    }
    let source = db
        .get_open_table_source(&query.source_id)?
        .ok_or(QUERY_UNAVAILABLE)?;
    if source.owner != actor {
        return Err(QUERY_UNAVAILABLE.into());
    }
    if source.contract_version != OPEN_TABLE_CONTRACT
        || !supported_format(&source.format)
        || source.schema_revision != SCHEMA_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if schema_digest_for(&source)? != source.schema_digest {
        return Err(SNAPSHOT_CORRUPT.into());
    }
    let snapshot = db
        .get_open_table_snapshot(&query.source_id)?
        .ok_or(SNAPSHOT_UNAVAILABLE)?;
    if let Some(pinned) = query.snapshot_digest.as_deref()
        && pinned != snapshot.snapshot_digest
    {
        return Err(SNAPSHOT_UNAVAILABLE.into());
    }
    if snapshot.snapshot_digest != source.snapshot_digest
        || snapshot_digest_for(&snapshot)? != snapshot.snapshot_digest
    {
        return Err(SNAPSHOT_CORRUPT.into());
    }
    validate_rows(&source, &snapshot.rows).map_err(|_| SNAPSHOT_CORRUPT.to_string())?;

    let authority = query_authority(db, actor, query)?;
    let authorized_names = authorized_columns(&source, &authority);
    if query.columns.len() > MAX_COLUMNS {
        return Err("open table column list is invalid".into());
    }
    let mut requested = BTreeSet::new();
    for name in &query.columns {
        if !requested.insert(name) {
            return Err("open table column list is invalid".into());
        }
        if !source.columns.iter().any(|column| &column.name == name)
            || !authorized_names.contains(name)
        {
            return Err(QUERY_UNAVAILABLE.into());
        }
    }
    for filter in &query.filters {
        if !authorized_names.contains(&filter.column) {
            return Err(QUERY_UNAVAILABLE.into());
        }
        if !matches!(filter.op.as_str(), "eq" | "neq") {
            return Err("open table predicate is unsupported".into());
        }
    }

    let projected_names = if query.columns.is_empty() {
        authorized_names
    } else {
        query.columns.clone()
    };

    let mut rows = Vec::new();
    for row in &snapshot.rows {
        if !matches_filters(row, &query.filters)? {
            continue;
        }
        let mut projected = BTreeMap::new();
        for name in &projected_names {
            let value = row.get(name).ok_or(SNAPSHOT_CORRUPT)?;
            projected.insert(name.clone(), value.clone());
        }
        rows.push(projected);
    }

    let definition_digest = definition_digest(&source)?;
    let projection_digest = format!(
        "sha256:{}",
        shomei::digest_serializable(&ProjectionPin {
            columns: &projected_names,
            rows: &rows,
        })?
    );
    Ok(OpenTableProjection {
        profile_version: TRANSFORM_PROFILE.into(),
        class: TRANSFORM_CLASS.into(),
        namespace: source.namespace,
        source_id: source.source_id,
        format: source.format,
        schema_revision: source.schema_revision,
        definition_digest,
        input_digest: snapshot.snapshot_digest,
        columns: projected_names,
        row_count: u32::try_from(rows.len()).map_err(|error| error.to_string())?,
        projection_digest,
        rows,
    })
}

fn validate_source(
    source: &OpenTableSource,
    actor: &str,
    now_ms: i64,
) -> Result<OpenTableSource, String> {
    if source.contract_version != OPEN_TABLE_CONTRACT {
        return Err(REVISION_UNSUPPORTED.into());
    }
    required("source id", &source.source_id)?;
    required("namespace", &source.namespace)?;
    required("owner", &source.owner)?;
    if source.owner != actor {
        return Err(QUERY_UNAVAILABLE.into());
    }
    if !supported_format(&source.format) || source.schema_revision != SCHEMA_REVISION_V1 {
        return Err(REVISION_UNSUPPORTED.into());
    }
    required("snapshot digest", &source.snapshot_digest)?;
    if source.columns.is_empty() || source.columns.len() > MAX_COLUMNS {
        return Err("open table must declare between 1 and 64 columns".into());
    }
    let mut seen = BTreeSet::new();
    for column in &source.columns {
        required("column name", &column.name)?;
        if !seen.insert(column.name.clone()) {
            return Err(format!("duplicate open table column {}", column.name));
        }
        if !matches!(
            column.col_type.as_str(),
            "string" | "int" | "bool" | "float"
        ) {
            return Err(REVISION_UNSUPPORTED.into());
        }
        parse_classification(&column.classification)?;
    }
    let mut validated = source.clone();
    validated.registered_by = actor.into();
    validated.registered_at_ms = now_ms;
    let digest = schema_digest_for(&validated)?;
    if validated.schema_digest.is_empty() {
        validated.schema_digest = digest;
    } else if validated.schema_digest != digest {
        return Err(SNAPSHOT_CORRUPT.into());
    }
    Ok(validated)
}

fn validate_snapshot(
    source: &OpenTableSource,
    snapshot: &OpenTableSnapshot,
) -> Result<OpenTableSnapshot, String> {
    if snapshot.source_id != source.source_id {
        return Err(QUERY_UNAVAILABLE.into());
    }
    if snapshot.rows.len() > MAX_ROWS {
        return Err("open table snapshot is oversized".into());
    }
    let encoded = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_SNAPSHOT_BYTES {
        return Err("open table snapshot is oversized".into());
    }
    validate_rows(source, &snapshot.rows).map_err(|_| SNAPSHOT_CORRUPT.to_string())?;
    let digest = snapshot_digest_for(snapshot)?;
    if snapshot.snapshot_digest != digest || digest != source.snapshot_digest {
        return Err(SNAPSHOT_CORRUPT.into());
    }
    Ok(snapshot.clone())
}

fn validate_rows(
    source: &OpenTableSource,
    rows: &[BTreeMap<String, String>],
) -> Result<(), String> {
    let expected: BTreeSet<&str> = source
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    for row in rows {
        let keys: BTreeSet<&str> = row.keys().map(String::as_str).collect();
        if keys != expected {
            return Err(SNAPSHOT_CORRUPT.into());
        }
        for column in &source.columns {
            let value = row.get(&column.name).ok_or(SNAPSHOT_CORRUPT)?;
            if !typed_value(&column.col_type, value) {
                return Err(SNAPSHOT_CORRUPT.into());
            }
        }
    }
    Ok(())
}

fn typed_value(col_type: &str, value: &str) -> bool {
    match col_type {
        "string" => true,
        "int" => value.parse::<i64>().is_ok(),
        "bool" => matches!(value, "true" | "false"),
        "float" => value.parse::<f64>().is_ok_and(|number| number.is_finite()),
        _ => false,
    }
}

fn supported_format(format: &str) -> bool {
    matches!(format, FORMAT_ICEBERG | FORMAT_PARQUET)
}

fn query_authority(
    db: &RuntimeDb,
    actor: &str,
    query: &OpenTableQuery,
) -> Result<PrincipalAuthority, String> {
    let mut authority = if let Some(trusted) = trusted_service_authority(actor) {
        trusted
    } else {
        // Same sealed-profile + admin-grant rule as `resolve_principal_authority`.
        let candidates = db.find_all_by_external_id(&principal_profile_external_id(actor))?;
        let mut sealed = Vec::new();
        for object in &candidates {
            if object.kind != PRINCIPAL_PROFILE_KIND {
                continue;
            }
            if object
                .properties
                .get(PRINCIPAL_PROFILE_SEALED_PROPERTY)
                .is_none_or(|value| value != "true")
            {
                continue;
            }
            if db
                .list_grants(&object.id)?
                .iter()
                .any(|grant| matches!(grant.role, Role::Admin))
            {
                sealed.push(object);
            }
        }
        if sealed.len() > 1 {
            return Err(QUERY_UNAVAILABLE.into());
        }
        principal_authority_from_profile(actor, sealed.first().copied())?
    };
    if let Some(requested) = query.classification_ceiling.as_deref() {
        let requested = parse_classification(requested)?;
        if authority
            .classification_ceiling
            .is_some_and(|existing| requested < existing)
        {
            authority.classification_ceiling = Some(requested);
            authority.classification_token = Some(requested.as_str().into());
        }
    }
    Ok(authority)
}

fn authorized_columns(source: &OpenTableSource, authority: &PrincipalAuthority) -> Vec<String> {
    source
        .columns
        .iter()
        .filter(|column| column_visible(column, authority))
        .map(|column| column.name.clone())
        .collect()
}

fn column_visible(column: &OpenTableColumn, authority: &PrincipalAuthority) -> bool {
    let Ok(marking) = parse_classification(&column.classification) else {
        return false;
    };
    if marking == EvidenceClassification::Public {
        return true;
    }
    authority
        .classification_ceiling
        .is_some_and(|ceiling| ceiling >= marking)
}

fn matches_filters(row: &BTreeMap<String, String>, filters: &[RowFilter]) -> Result<bool, String> {
    for filter in filters {
        let value = row.get(&filter.column).ok_or(SNAPSHOT_CORRUPT)?;
        let matched = match filter.op.as_str() {
            "eq" => value == &filter.value,
            "neq" => value != &filter.value,
            _ => return Err("open table predicate is unsupported".into()),
        };
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

fn definition_digest(source: &OpenTableSource) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&DefinitionPin {
            profile_version: TRANSFORM_PROFILE,
            class: TRANSFORM_CLASS,
            namespace: &source.namespace,
            source_id: &source.source_id,
            owner: &source.owner,
            format: &source.format,
            schema_revision: &source.schema_revision,
            schema_digest: &source.schema_digest,
            columns: &source.columns,
        })?
    ))
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY;
    use crate::sekai::security::Grant;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn pin_ceiling(runtime: &RuntimeDb, principal: &str, ceiling: &str) {
        let profile_id = format!("profile:{principal}");
        runtime
            .create_object(&Object {
                id: profile_id.clone(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "analytics".into(),
                external_id: principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: format!("grant:{principal}"),
                object_id: profile_id,
                principal: "root".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();
    }

    fn columns() -> Vec<OpenTableColumn> {
        vec![
            OpenTableColumn {
                name: "id".into(),
                col_type: "int".into(),
                classification: "public".into(),
            },
            OpenTableColumn {
                name: "city".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
            OpenTableColumn {
                name: "ssn".into(),
                col_type: "string".into(),
                classification: "restricted".into(),
            },
        ]
    }

    fn rows() -> Vec<BTreeMap<String, String>> {
        vec![
            BTreeMap::from([
                ("id".into(), "1".into()),
                ("city".into(), "berlin".into()),
                ("ssn".into(), "111-11-1111".into()),
            ]),
            BTreeMap::from([
                ("id".into(), "2".into()),
                ("city".into(), "oslo".into()),
                ("ssn".into(), "222-22-2222".into()),
            ]),
        ]
    }

    fn source_for(format: &str, snapshot: &OpenTableSnapshot) -> OpenTableSource {
        let mut source = OpenTableSource {
            contract_version: OPEN_TABLE_CONTRACT.into(),
            source_id: snapshot.source_id.clone(),
            namespace: "analytics".into(),
            owner: "analyst".into(),
            format: format.into(),
            schema_revision: SCHEMA_REVISION_V1.into(),
            schema_digest: String::new(),
            snapshot_digest: snapshot_digest_for(snapshot).unwrap(),
            columns: columns(),
            registered_by: String::new(),
            registered_at_ms: 0,
        };
        source.schema_digest = schema_digest_for(&source).unwrap();
        source
    }

    fn snapshot() -> OpenTableSnapshot {
        let mut snapshot = OpenTableSnapshot {
            source_id: "iceberg:events".into(),
            snapshot_digest: String::new(),
            rows: rows(),
        };
        snapshot.snapshot_digest = snapshot_digest_for(&snapshot).unwrap();
        snapshot
    }

    fn register(runtime: &RuntimeDb, format: &str) -> (OpenTableSource, OpenTableSnapshot) {
        pin_ceiling(runtime, "analyst", "internal");
        let snap = snapshot();
        let source =
            register_open_table(runtime, "analyst", &source_for(format, &snap), 1_000).unwrap();
        let admitted = admit_open_table_snapshot(runtime, "analyst", &snap).unwrap();
        (source, admitted)
    }

    #[test]
    fn authorized_iceberg_and_parquet_projections_are_digest_stable() {
        for format in [FORMAT_ICEBERG, FORMAT_PARQUET] {
            let runtime = db();
            let (_source, snap) = register(&runtime, format);
            let query = OpenTableQuery {
                source_id: snap.source_id.clone(),
                columns: vec!["id".into(), "city".into()],
                classification_ceiling: Some("internal".into()),
                snapshot_digest: Some(snap.snapshot_digest.clone()),
                ..Default::default()
            };
            let first = query_open_table(&runtime, "analyst", &query, 2_000).unwrap();
            let second = query_open_table(&runtime, "analyst", &query, 3_000).unwrap();
            assert_eq!(first.format, format);
            assert_eq!(first.class, TRANSFORM_CLASS);
            assert_eq!(first.profile_version, TRANSFORM_PROFILE);
            assert_eq!(first.row_count, 2);
            assert_eq!(first.rows[0].get("city").unwrap(), "berlin");
            assert!(!first.rows[0].contains_key("ssn"));
            assert_eq!(first.projection_digest, second.projection_digest);
            assert_eq!(first.rows, second.rows);
            assert_eq!(first.input_digest, snap.snapshot_digest);
        }
    }

    #[test]
    fn default_projection_omits_hidden_fields_without_naming_them() {
        let runtime = db();
        let (_, snap) = register(&runtime, FORMAT_ICEBERG);
        let projection = query_open_table(
            &runtime,
            "analyst",
            &OpenTableQuery {
                source_id: snap.source_id,
                classification_ceiling: Some("internal".into()),
                ..Default::default()
            },
            2_000,
        )
        .unwrap();
        assert_eq!(
            projection.columns,
            vec!["id".to_string(), "city".to_string()]
        );
        assert!(projection.rows.iter().all(|row| !row.contains_key("ssn")));
    }

    #[test]
    fn hidden_field_sensitive_predicate_and_foreign_owner_fail_closed() {
        let runtime = db();
        let (_, snap) = register(&runtime, FORMAT_PARQUET);
        assert_eq!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id.clone(),
                    columns: vec!["ssn".into()],
                    classification_ceiling: Some("internal".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );
        assert_eq!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id.clone(),
                    filters: vec![RowFilter {
                        column: "ssn".into(),
                        op: "eq".into(),
                        value: "111-11-1111".into(),
                    }],
                    classification_ceiling: Some("internal".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );
        assert_eq!(
            query_open_table(
                &runtime,
                "intruder",
                &OpenTableQuery {
                    source_id: snap.source_id.clone(),
                    columns: vec!["id".into()],
                    classification_ceiling: Some("restricted".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );
        assert_eq!(
            query_open_table(
                &runtime,
                "intruder",
                &OpenTableQuery {
                    source_id: "missing".into(),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );
    }

    #[test]
    fn corrupt_metadata_and_unsupported_revision_fail_before_rows() {
        let runtime = db();
        let snap = snapshot();
        let mut source = source_for(FORMAT_ICEBERG, &snap);
        source.schema_digest = "sha256:deadbeef".into();
        assert_eq!(
            register_open_table(&runtime, "analyst", &source, 1_000).unwrap_err(),
            SNAPSHOT_CORRUPT
        );

        let mut bad_revision = source_for(FORMAT_ICEBERG, &snap);
        bad_revision.schema_digest.clear();
        bad_revision.schema_revision = "v2".into();
        assert_eq!(
            register_open_table(&runtime, "analyst", &bad_revision, 1_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );

        let mut bad_format = source_for("delta", &snap);
        bad_format.schema_digest.clear();
        assert_eq!(
            register_open_table(&runtime, "analyst", &bad_format, 1_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );

        register(&runtime, FORMAT_ICEBERG);
        let mut corrupt = snap;
        corrupt.rows[0].insert("city".into(), "tampered".into());
        assert_eq!(
            admit_open_table_snapshot(&runtime, "analyst", &corrupt).unwrap_err(),
            SNAPSHOT_CORRUPT
        );
    }

    #[test]
    fn missing_snapshot_is_an_explicit_gap() {
        let runtime = db();
        let snap = snapshot();
        register_open_table(
            &runtime,
            "analyst",
            &source_for(FORMAT_ICEBERG, &snap),
            1_000,
        )
        .unwrap();
        assert_eq!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id,
                    columns: vec!["id".into()],
                    classification_ceiling: Some("public".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            SNAPSHOT_UNAVAILABLE
        );
    }

    #[test]
    fn reregister_with_new_digest_invalidates_prior_snapshot() {
        let runtime = db();
        let (_, snap) = register(&runtime, FORMAT_ICEBERG);
        let mut next = snap.clone();
        next.rows[0].insert("city".into(), "paris".into());
        next.snapshot_digest = snapshot_digest_for(&next).unwrap();
        register_open_table(
            &runtime,
            "analyst",
            &source_for(FORMAT_ICEBERG, &next),
            2_000,
        )
        .unwrap();
        assert_eq!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id,
                    columns: vec!["id".into()],
                    ..Default::default()
                },
                3_000,
            )
            .unwrap_err(),
            SNAPSHOT_UNAVAILABLE
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "open table projections are unavailable on the PostgreSQL community runtime"
        );
    }

    #[test]
    fn caller_asserted_ceiling_cannot_elevate_and_foreign_register_cannot_take_over() {
        let runtime = db();
        let (_, snap) = register(&runtime, FORMAT_ICEBERG);
        assert_eq!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id.clone(),
                    columns: vec!["ssn".into()],
                    classification_ceiling: Some("restricted".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );

        let mut stolen = source_for(FORMAT_ICEBERG, &snap);
        stolen.owner = "intruder".into();
        stolen.schema_digest.clear();
        assert_eq!(
            register_open_table(&runtime, "intruder", &stolen, 3_000).unwrap_err(),
            QUERY_UNAVAILABLE
        );

        assert!(
            query_open_table(
                &runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: snap.source_id,
                    filters: vec![RowFilter {
                        column: "id".into(),
                        op: "gt".into(),
                        value: "0".into(),
                    }],
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err()
            .contains("unsupported")
        );

        let empty_runtime = db();
        pin_ceiling(&empty_runtime, "analyst", "internal");
        let mut empty_snap = OpenTableSnapshot {
            source_id: "iceberg:empty".into(),
            snapshot_digest: String::new(),
            rows: Vec::new(),
        };
        empty_snap.snapshot_digest = snapshot_digest_for(&empty_snap).unwrap();
        let empty_source = source_for(FORMAT_ICEBERG, &empty_snap);
        register_open_table(&empty_runtime, "analyst", &empty_source, 1_000).unwrap();
        admit_open_table_snapshot(&empty_runtime, "analyst", &empty_snap).unwrap();
        assert!(
            query_open_table(
                &empty_runtime,
                "analyst",
                &OpenTableQuery {
                    source_id: empty_snap.source_id,
                    filters: vec![RowFilter {
                        column: "id".into(),
                        op: "gt".into(),
                        value: "0".into(),
                    }],
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err()
            .contains("unsupported")
        );
    }

    #[test]
    fn unsealed_profile_and_trusted_query_ceiling_cannot_disclose_hidden_fields() {
        let runtime = db();
        runtime
            .create_object(&Object {
                id: "profile:forger".into(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: "forger".into(),
                namespace: "analytics".into(),
                external_id: principal_profile_external_id("forger"),
                properties: HashMap::from([(
                    PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "restricted".into(),
                )]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let snap = snapshot();
        let mut source = source_for(FORMAT_ICEBERG, &snap);
        source.owner = "forger".into();
        source.schema_digest.clear();
        register_open_table(&runtime, "forger", &source, 1_000).unwrap();
        admit_open_table_snapshot(&runtime, "forger", &snap).unwrap();
        assert_eq!(
            query_open_table(
                &runtime,
                "forger",
                &OpenTableQuery {
                    source_id: snap.source_id.clone(),
                    columns: vec!["ssn".into()],
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );

        let trusted = db();
        let mut local_source = source_for(FORMAT_PARQUET, &snap);
        local_source.owner = "local".into();
        local_source.schema_digest.clear();
        register_open_table(&trusted, "local", &local_source, 1_000).unwrap();
        admit_open_table_snapshot(&trusted, "local", &snap).unwrap();
        assert_eq!(
            query_open_table(
                &trusted,
                "local",
                &OpenTableQuery {
                    source_id: snap.source_id,
                    columns: vec!["city".into()],
                    classification_ceiling: Some("public".into()),
                    ..Default::default()
                },
                2_000,
            )
            .unwrap_err(),
            QUERY_UNAVAILABLE
        );
    }
}
