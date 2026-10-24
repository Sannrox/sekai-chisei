//! Authorized warehouse projections (#711).
//!
//! Export digest-bound snapshot and incremental pages with replay, deletion,
//! lineage, and security-metadata pins. Adapters do not receive grants.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::shomei;

pub const WAREHOUSE_CONTRACT: &str = "sekai.warehouse-projection/v1";
pub const SECURITY_CONTRACT: &str = "sekai.security-metadata/v1";
pub const PROFILE_ORDERS: &str = "adapter.warehouse.orders";
pub const PROFILE_INVENTORY: &str = "adapter.warehouse.inventory";
pub const PROFILE_VERSION: &str = "1.0.0";
pub const MODE_SNAPSHOT: &str = "snapshot";
pub const MODE_INCREMENTAL: &str = "incremental";
pub const STATUS_LIVE: &str = "live";
pub const STATUS_REVOKED: &str = "revoked";
pub const OUTCOME_EXPORTED: &str = "exported";
pub const OUTCOME_REPLAYED: &str = "replayed";
pub const WAREHOUSE_UNAVAILABLE: &str = "warehouse projection is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "warehouse projection revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "warehouse projections are unavailable on the PostgreSQL community runtime";
const MAX_COLUMNS: usize = 32;
const MAX_ROWS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseColumn {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseSecurity {
    pub contract_version: String,
    pub classification_ceiling: String,
    pub purpose: String,
    pub residency_class: String,
    pub trust_pin_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseCursor {
    pub generation: u64,
    pub offset: u64,
    pub last_page_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseRow {
    pub row_id: String,
    pub values: BTreeMap<String, String>,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseProjection {
    pub contract_version: String,
    pub projection_id: String,
    pub namespace: String,
    pub owner: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub columns: Vec<WarehouseColumn>,
    pub security: WarehouseSecurity,
    pub lineage_digest: String,
    pub cursor: WarehouseCursor,
    pub status: String,
    pub projection_digest: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehousePage {
    pub projection_id: String,
    pub namespace: String,
    pub mode: String,
    pub generation: u64,
    pub offset_start: u64,
    pub offset_end: u64,
    pub rows: Vec<WarehouseRow>,
    pub page_digest: String,
    pub lineage_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarehouseExport {
    pub outcome: String,
    pub projection: WarehouseProjection,
    pub page: WarehousePage,
}

#[derive(Serialize)]
struct ProjectionPin<'a> {
    contract_version: &'a str,
    projection_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    columns: &'a [WarehouseColumn],
    security: &'a WarehouseSecurity,
}

#[derive(Serialize)]
struct PagePin<'a> {
    projection_id: &'a str,
    namespace: &'a str,
    mode: &'a str,
    generation: u64,
    offset_start: u64,
    offset_end: u64,
    rows: &'a [WarehouseRow],
}

pub fn projection_digest_for(projection: &WarehouseProjection) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ProjectionPin {
            contract_version: &projection.contract_version,
            projection_id: &projection.projection_id,
            namespace: &projection.namespace,
            owner: &projection.owner,
            adapter_id: &projection.adapter_id,
            adapter_version: &projection.adapter_version,
            columns: &projection.columns,
            security: &projection.security,
        })?
    ))
}

pub fn page_digest_for(page: &WarehousePage) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&PagePin {
            projection_id: &page.projection_id,
            namespace: &page.namespace,
            mode: &page.mode,
            generation: page.generation,
            offset_start: page.offset_start,
            offset_end: page.offset_end,
            rows: &page.rows,
        })?
    ))
}

pub fn register_projection(
    db: &RuntimeDb,
    actor: &str,
    projection: &WarehouseProjection,
    now_ms: i64,
) -> Result<WarehouseProjection, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("register", now_ms)?;
    let validated = validate_projection(projection, actor, now_ms)?;
    if let Some(existing) =
        db.get_warehouse_projection(&validated.namespace, &validated.projection_id)?
    {
        return replay_projection(&existing, &validated);
    }
    match db.put_warehouse_projection(&validated) {
        Ok(()) => Ok(validated),
        Err(error) if error == WAREHOUSE_UNAVAILABLE => {
            let existing = db
                .get_warehouse_projection(&validated.namespace, &validated.projection_id)?
                .ok_or(WAREHOUSE_UNAVAILABLE)?;
            replay_projection(&existing, &validated)
        }
        Err(error) => Err(error),
    }
}

pub fn export_page(
    db: &RuntimeDb,
    actor: &str,
    page: &WarehousePage,
    now_ms: i64,
) -> Result<WarehouseExport, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("export", now_ms)?;
    // Recheck owner identity and security pins on every export. The cursor is
    // not a grant, and this surface does not resolve Chisei policy, budget, or
    // receipt authority.
    let current = owned_projection(db, &page.namespace, &page.projection_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    validate_security(&current.security)?;
    let incoming_digest = page_digest_for(page)?;
    if !page.page_digest.is_empty() && page.page_digest != incoming_digest {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if current.cursor.last_page_digest == incoming_digest
        && current.cursor.generation == page.generation
        && current.cursor.offset == page.offset_end
    {
        if page.projection_id != current.projection_id || page.namespace != current.namespace {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if !page.lineage_digest.is_empty() && page.lineage_digest != current.lineage_digest {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        let mut replayed = page.clone();
        replayed.page_digest = incoming_digest;
        if replayed.lineage_digest.is_empty() {
            replayed.lineage_digest = current.lineage_digest.clone();
        }
        return Ok(WarehouseExport {
            outcome: OUTCOME_REPLAYED.into(),
            projection: current,
            page: replayed,
        });
    }
    let validated = validate_page(&current, page)?;
    let mut next = current.clone();
    if validated.mode == MODE_SNAPSHOT {
        if current.cursor.offset != 0 && validated.generation != current.cursor.generation + 1 {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if current.cursor.offset == 0 && validated.generation != current.cursor.generation {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if validated.offset_start != 0 {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
    } else {
        if current.cursor.last_page_digest.is_empty() {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if validated.generation != current.cursor.generation
            || validated.offset_start != current.cursor.offset
        {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
    }
    next.cursor.generation = validated.generation;
    next.cursor.offset = validated.offset_end;
    next.cursor.last_page_digest = validated.page_digest.clone();
    next.lineage_digest = validated.lineage_digest.clone();
    db.commit_warehouse_export(&current, &next, Some(&validated))?;
    Ok(WarehouseExport {
        outcome: OUTCOME_EXPORTED.into(),
        projection: next,
        page: validated,
    })
}

pub fn get_projection(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    projection_id: &str,
) -> Result<WarehouseProjection, String> {
    owned_projection(db, namespace, projection_id, actor)
}

pub fn revoke_projection(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    projection_id: &str,
    now_ms: i64,
) -> Result<WarehouseProjection, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("revoke", now_ms)?;
    let current = owned_projection(db, namespace, projection_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_REVOKED.into();
    db.commit_warehouse_export(&current, &next, None)?;
    Ok(next)
}

fn validate_projection(
    projection: &WarehouseProjection,
    actor: &str,
    now_ms: i64,
) -> Result<WarehouseProjection, String> {
    if projection.contract_version != WAREHOUSE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if projection.adapter_version != PROFILE_VERSION
        || (projection.adapter_id != PROFILE_ORDERS && projection.adapter_id != PROFILE_INVENTORY)
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    required("projection id", &projection.projection_id)?;
    required("namespace", &projection.namespace)?;
    required("owner", &projection.owner)?;
    reject_secret(&projection.projection_id)?;
    reject_secret(&projection.namespace)?;
    reject_secret(&projection.owner)?;
    reject_secret(actor)?;
    if projection.owner != actor
        || has_whitespace(&projection.namespace)
        || has_whitespace(&projection.projection_id)
        || has_whitespace(&projection.owner)
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if projection.columns.is_empty() || projection.columns.len() > MAX_COLUMNS {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    let mut seen = BTreeSet::new();
    for column in &projection.columns {
        required("column name", &column.name)?;
        reject_secret(&column.name)?;
        if !seen.insert(column.name.as_str())
            || has_whitespace(&column.name)
            || !matches!(column.col_type.as_str(), "string" | "i64" | "bool")
            || !classification_ok(&column.classification)
            || rank(&column.classification) > rank(&projection.security.classification_ceiling)
        {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
    }
    validate_security(&projection.security)?;
    if projection.status != STATUS_LIVE
        || projection.cursor.generation != 0
        || projection.cursor.offset != 0
        || !projection.cursor.last_page_digest.is_empty()
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    let projection_digest = projection_digest_for(projection)?;
    if !projection.projection_digest.is_empty() && projection.projection_digest != projection_digest
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    Ok(WarehouseProjection {
        projection_digest: projection_digest.clone(),
        lineage_digest: projection_digest,
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        status: STATUS_LIVE.into(),
        ..projection.clone()
    })
}

fn validate_page(
    projection: &WarehouseProjection,
    page: &WarehousePage,
) -> Result<WarehousePage, String> {
    if page.projection_id != projection.projection_id || page.namespace != projection.namespace {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if page.mode != MODE_SNAPSHOT && page.mode != MODE_INCREMENTAL {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if page.rows.is_empty() || page.rows.len() > MAX_ROWS {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if page.offset_end <= page.offset_start
        || page.offset_end - page.offset_start != page.rows.len() as u64
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    let authorized: BTreeMap<&str, &WarehouseColumn> = projection
        .columns
        .iter()
        .map(|column| (column.name.as_str(), column))
        .collect();
    let mut seen_rows = BTreeSet::new();
    for row in &page.rows {
        required("row id", &row.row_id)?;
        reject_secret(&row.row_id)?;
        if !seen_rows.insert(row.row_id.as_str()) || has_whitespace(&row.row_id) {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if page.mode == MODE_SNAPSHOT && row.deleted {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        if row.deleted && !row.values.is_empty() {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
        for (key, value) in &row.values {
            reject_secret(key)?;
            reject_secret(value)?;
            let Some(column) = authorized.get(key.as_str()) else {
                return Err(WAREHOUSE_UNAVAILABLE.into());
            };
            if !typed_value(&column.col_type, value) {
                return Err(WAREHOUSE_UNAVAILABLE.into());
            }
        }
        if !row.deleted && row.values.len() != projection.columns.len() {
            return Err(WAREHOUSE_UNAVAILABLE.into());
        }
    }
    let page_digest = page_digest_for(page)?;
    if !page.page_digest.is_empty() && page.page_digest != page_digest {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    let lineage_digest = format!(
        "sha256:{}",
        shomei::digest_serializable(&(
            projection.projection_digest.as_str(),
            projection.cursor.last_page_digest.as_str(),
            page_digest.as_str()
        ))?
    );
    if !page.lineage_digest.is_empty() && page.lineage_digest != lineage_digest {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    Ok(WarehousePage {
        page_digest,
        lineage_digest,
        ..page.clone()
    })
}

fn validate_security(security: &WarehouseSecurity) -> Result<(), String> {
    if security.contract_version != SECURITY_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    required("purpose", &security.purpose)?;
    required("residency class", &security.residency_class)?;
    reject_secret(&security.purpose)?;
    reject_secret(&security.residency_class)?;
    if !classification_ok(&security.classification_ceiling)
        || !matches!(security.residency_class.as_str(), "eu" | "us" | "internal")
        || !digest_token(&security.trust_pin_digest)
        || has_whitespace(&security.purpose)
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    Ok(())
}

fn owned_projection(
    db: &RuntimeDb,
    namespace: &str,
    projection_id: &str,
    actor: &str,
) -> Result<WarehouseProjection, String> {
    required("namespace", namespace)?;
    required("projection id", projection_id)?;
    required("actor", actor)?;
    reject_secret(namespace)?;
    reject_secret(projection_id)?;
    reject_secret(actor)?;
    let projection = db
        .get_warehouse_projection(namespace, projection_id)?
        .ok_or(WAREHOUSE_UNAVAILABLE)?;
    if projection.owner != actor {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    if projection.contract_version != WAREHOUSE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(projection)
}

fn replay_projection(
    existing: &WarehouseProjection,
    incoming: &WarehouseProjection,
) -> Result<WarehouseProjection, String> {
    if existing.projection_digest != incoming.projection_digest
        || existing.owner != incoming.owner
        || existing.status == STATUS_REVOKED
        || existing.cursor.offset != 0
        || !existing.cursor.last_page_digest.is_empty()
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    Ok(existing.clone())
}

fn classification_ok(value: &str) -> bool {
    matches!(value, "public" | "internal" | "confidential" | "restricted")
}

fn rank(value: &str) -> u8 {
    match value {
        "public" => 0,
        "internal" => 1,
        "confidential" => 2,
        "restricted" => 3,
        _ => 4,
    }
}

fn reject_secret(value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("bearer ")
        || lower.contains("sk-")
        || lower.contains("ghp_")
        || lower.contains("gho_")
        || lower.contains("ghu_")
        || lower.contains("ghs_")
        || lower.contains("ghr_")
        || lower.contains("github_pat_")
        || lower.contains("-----begin")
        || crate::sekai::object_sync::contains_secret_like_text(value)
    {
        return Err(WAREHOUSE_UNAVAILABLE.into());
    }
    Ok(())
}

fn typed_value(col_type: &str, value: &str) -> bool {
    match col_type {
        "string" => true,
        "i64" => value.parse::<i64>().is_ok(),
        "bool" => matches!(value, "true" | "false"),
        _ => false,
    }
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn has_whitespace(value: &str) -> bool {
    value.chars().any(char::is_whitespace)
}

fn require_positive_timestamp(action: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{action} timestamp must be positive"))
    } else {
        Ok(())
    }
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

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn column(name: &str) -> WarehouseColumn {
        WarehouseColumn {
            name: name.into(),
            col_type: "string".into(),
            classification: "internal".into(),
        }
    }

    fn projection(adapter: &str, projection_id: &str) -> WarehouseProjection {
        let mut projection = WarehouseProjection {
            contract_version: WAREHOUSE_CONTRACT.into(),
            projection_id: projection_id.into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            adapter_id: adapter.into(),
            adapter_version: PROFILE_VERSION.into(),
            columns: vec![column("id"), column("sku")],
            security: WarehouseSecurity {
                contract_version: SECURITY_CONTRACT.into(),
                classification_ceiling: "internal".into(),
                purpose: "analytics".into(),
                residency_class: "eu".into(),
                trust_pin_digest: digest(1),
            },
            lineage_digest: String::new(),
            cursor: WarehouseCursor {
                generation: 0,
                offset: 0,
                last_page_digest: String::new(),
            },
            status: STATUS_LIVE.into(),
            projection_digest: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        projection.projection_digest = projection_digest_for(&projection).unwrap();
        projection
    }

    fn row(id: &str, sku: &str) -> WarehouseRow {
        WarehouseRow {
            row_id: id.into(),
            values: BTreeMap::from([("id".into(), id.into()), ("sku".into(), sku.into())]),
            deleted: false,
        }
    }

    fn page(projection_id: &str, mode: &str, start: u64, rows: Vec<WarehouseRow>) -> WarehousePage {
        let end = start + rows.len() as u64;
        let mut page = WarehousePage {
            projection_id: projection_id.into(),
            namespace: "ops".into(),
            mode: mode.into(),
            generation: 0,
            offset_start: start,
            offset_end: end,
            rows,
            page_digest: String::new(),
            lineage_digest: String::new(),
        };
        page.page_digest = page_digest_for(&page).unwrap();
        page
    }

    fn lifecycle(adapter: &str, projection_id: &str) {
        let runtime = RuntimeDb::memory();
        let registered = register_projection(
            &runtime,
            "integrator",
            &projection(adapter, projection_id),
            1_000,
        )
        .unwrap();
        assert_eq!(
            register_projection(
                &runtime,
                "integrator",
                &projection(adapter, projection_id),
                1_100
            )
            .unwrap(),
            registered
        );
        let snapshot = export_page(
            &runtime,
            "integrator",
            &page(projection_id, MODE_SNAPSHOT, 0, vec![row("1", "a")]),
            2_000,
        )
        .unwrap();
        assert_eq!(snapshot.outcome, OUTCOME_EXPORTED);
        assert_eq!(
            export_page(&runtime, "integrator", &snapshot.page, 2_100,)
                .unwrap()
                .outcome,
            OUTCOME_REPLAYED
        );
        let mut deleted = row("1", "a");
        deleted.values.clear();
        deleted.deleted = true;
        let incremental = export_page(
            &runtime,
            "integrator",
            &page(projection_id, MODE_INCREMENTAL, 1, vec![deleted]),
            3_000,
        )
        .unwrap();
        assert_eq!(incremental.outcome, OUTCOME_EXPORTED);
        assert_eq!(
            export_page(&runtime, "integrator", &incremental.page, 3_100)
                .unwrap()
                .outcome,
            OUTCOME_REPLAYED
        );
        let mut hidden = page(projection_id, MODE_INCREMENTAL, 2, vec![row("2", "b")]);
        hidden.rows[0].values.insert("secret".into(), "nope".into());
        hidden.page_digest.clear();
        assert_eq!(
            export_page(&runtime, "integrator", &hidden, 3_200).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        assert_eq!(
            get_projection(&runtime, "intruder", "ops", projection_id).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        let revoked =
            revoke_projection(&runtime, "integrator", "ops", projection_id, 4_000).unwrap();
        assert_eq!(revoked.status, STATUS_REVOKED);
        assert_eq!(
            export_page(&runtime, "integrator", &incremental.page, 4_100).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
    }

    #[test]
    fn two_adapters_pass_snapshot_incremental_replay_revocation_visibility_and_scope() {
        lifecycle(PROFILE_ORDERS, "wh:orders");
        lifecycle(PROFILE_INVENTORY, "wh:inventory");
    }

    #[test]
    fn hidden_fields_stale_cursors_and_unknown_versions_fail_closed() {
        let runtime = RuntimeDb::memory();
        register_projection(
            &runtime,
            "integrator",
            &projection(PROFILE_ORDERS, "wh:x"),
            1_000,
        )
        .unwrap();
        let mut hidden = serde_json::to_value(projection(PROFILE_ORDERS, "wh:x")).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("grant".into(), serde_json::json!("admin"));
        assert!(serde_json::from_value::<WarehouseProjection>(hidden).is_err());
        let mut unknown = projection(PROFILE_ORDERS, "wh:y");
        unknown.contract_version = "sekai.warehouse-projection/v0".into();
        assert_eq!(
            register_projection(&runtime, "integrator", &unknown, 1_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        let stale = page("wh:x", MODE_INCREMENTAL, 9, vec![row("9", "z")]);
        assert_eq!(
            export_page(&runtime, "integrator", &stale, 2_000).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        let mut secret_row = page("wh:x", MODE_SNAPSHOT, 0, vec![row("1", "a")]);
        secret_row.rows[0]
            .values
            .insert("sku".into(), "ghp_exampleleak".into());
        secret_row.page_digest.clear();
        assert_eq!(
            export_page(&runtime, "integrator", &secret_row, 2_100).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        let mut secret_owner = projection(PROFILE_ORDERS, "wh:leak");
        secret_owner.owner = "ghp_exampleleak".into();
        assert_eq!(
            register_projection(&runtime, "ghp_exampleleak", &secret_owner, 1_200).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "warehouse projections are unavailable on the PostgreSQL community runtime"
        );
        let snapshot = export_page(
            &runtime,
            "integrator",
            &page("wh:x", MODE_SNAPSHOT, 0, vec![row("1", "a")]),
            2_200,
        )
        .unwrap();
        assert_eq!(snapshot.outcome, OUTCOME_EXPORTED);
        let gap = page("wh:x", MODE_INCREMENTAL, 5, vec![row("2", "b")]);
        assert_eq!(
            export_page(&runtime, "integrator", &gap, 2_300).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        let mut bool_projection = projection(PROFILE_ORDERS, "wh:typed");
        bool_projection.columns[1].col_type = "bool".into();
        bool_projection.projection_digest.clear();
        register_projection(&runtime, "integrator", &bool_projection, 2_350).unwrap();
        let mut mistyped = page("wh:typed", MODE_SNAPSHOT, 0, vec![row("2", "b")]);
        mistyped.rows[0]
            .values
            .insert("sku".into(), "not-a-bool".into());
        mistyped.page_digest = page_digest_for(&mistyped).unwrap();
        assert_eq!(
            export_page(&runtime, "integrator", &mistyped, 2_360).unwrap_err(),
            WAREHOUSE_UNAVAILABLE
        );
        let mut later = page("wh:x", MODE_SNAPSHOT, 0, vec![row("3", "c")]);
        later.generation = 1;
        later.page_digest = page_digest_for(&later).unwrap();
        assert_eq!(
            export_page(&runtime, "integrator", &later, 2_400)
                .unwrap()
                .outcome,
            OUTCOME_EXPORTED
        );
    }
}
