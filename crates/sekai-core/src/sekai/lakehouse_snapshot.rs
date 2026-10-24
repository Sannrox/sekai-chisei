//! Authorized lakehouse snapshots (#712).
//!
//! Export partitioned versioned snapshots with schema evolution, redaction,
//! deletion, re-import, provenance, and security-metadata pins. Adapters do
//! not receive grants.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::shomei;

pub const LAKEHOUSE_CONTRACT: &str = "sekai.lakehouse-snapshot/v1";
pub const SECURITY_CONTRACT: &str = "sekai.security-metadata/v1";
pub const PROFILE_EVENTS: &str = "adapter.lakehouse.events";
pub const PROFILE_METRICS: &str = "adapter.lakehouse.metrics";
pub const PROFILE_VERSION: &str = "1.0.0";
pub const STATUS_LIVE: &str = "live";
pub const STATUS_REVOKED: &str = "revoked";
pub const OUTCOME_EXPORTED: &str = "exported";
pub const OUTCOME_REPLAYED: &str = "replayed";
pub const LAKEHOUSE_UNAVAILABLE: &str = "lakehouse snapshot is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "lakehouse snapshot revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "lakehouse snapshots are unavailable on the PostgreSQL community runtime";
const MAX_COLUMNS: usize = 32;
const MAX_PARTITIONS: usize = 32;
const MAX_ROWS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehouseColumn {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehouseSecurity {
    pub contract_version: String,
    pub classification_ceiling: String,
    pub purpose: String,
    pub residency_class: String,
    pub trust_pin_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehouseRow {
    pub row_id: String,
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehousePartition {
    pub partition_key: String,
    pub rows: Vec<LakehouseRow>,
    #[serde(default)]
    pub partition_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehouseSnapshot {
    pub contract_version: String,
    pub snapshot_id: String,
    pub namespace: String,
    pub owner: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub schema_version: u64,
    pub partition_keys: Vec<String>,
    pub columns: Vec<LakehouseColumn>,
    pub partitions: Vec<LakehousePartition>,
    pub security: LakehouseSecurity,
    #[serde(default)]
    pub redacted_columns: Vec<String>,
    #[serde(default)]
    pub deleted_partitions: Vec<String>,
    #[serde(default)]
    pub provenance_digest: String,
    #[serde(default)]
    pub snapshot_digest: String,
    pub status: String,
    #[serde(default)]
    pub admitted_by: String,
    #[serde(default)]
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakehouseExport {
    pub outcome: String,
    pub snapshot: LakehouseSnapshot,
}

#[derive(Serialize)]
struct SnapshotPin<'a> {
    contract_version: &'a str,
    snapshot_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    schema_version: u64,
    partition_keys: &'a [String],
    columns: &'a [LakehouseColumn],
    partitions: &'a [LakehousePartition],
    security: &'a LakehouseSecurity,
    redacted_columns: &'a [String],
    deleted_partitions: &'a [String],
    status: &'a str,
}

#[derive(Serialize)]
struct PartitionPin<'a> {
    partition_key: &'a str,
    rows: &'a [LakehouseRow],
}

pub fn snapshot_digest_for(snapshot: &LakehouseSnapshot) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&SnapshotPin {
            contract_version: &snapshot.contract_version,
            snapshot_id: &snapshot.snapshot_id,
            namespace: &snapshot.namespace,
            owner: &snapshot.owner,
            adapter_id: &snapshot.adapter_id,
            adapter_version: &snapshot.adapter_version,
            schema_version: snapshot.schema_version,
            partition_keys: &snapshot.partition_keys,
            columns: &snapshot.columns,
            partitions: &snapshot.partitions,
            security: &snapshot.security,
            redacted_columns: &snapshot.redacted_columns,
            deleted_partitions: &snapshot.deleted_partitions,
            status: &snapshot.status,
        })?
    ))
}

pub fn partition_digest_for(partition: &LakehousePartition) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&PartitionPin {
            partition_key: &partition.partition_key,
            rows: &partition.rows,
        })?
    ))
}

pub fn register_snapshot(
    db: &RuntimeDb,
    actor: &str,
    snapshot: &LakehouseSnapshot,
    now_ms: i64,
) -> Result<LakehouseExport, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("register", now_ms)?;
    required("snapshot id", &snapshot.snapshot_id)?;
    required("namespace", &snapshot.namespace)?;
    if let Some(existing) = db.get_lakehouse_snapshot(&snapshot.namespace, &snapshot.snapshot_id)? {
        return replay_existing(existing, snapshot, actor);
    }
    let validated = validate_snapshot(snapshot, actor, now_ms, None)?;
    match db.put_lakehouse_snapshot(&validated) {
        Ok(()) => Ok(LakehouseExport {
            outcome: OUTCOME_EXPORTED.into(),
            snapshot: validated,
        }),
        Err(error) if error == LAKEHOUSE_UNAVAILABLE => {
            let existing = db
                .get_lakehouse_snapshot(&validated.namespace, &validated.snapshot_id)?
                .ok_or(LAKEHOUSE_UNAVAILABLE)?;
            replay_existing(existing, snapshot, actor)
        }
        Err(error) => Err(error),
    }
}

pub fn reimport_snapshot(
    db: &RuntimeDb,
    actor: &str,
    snapshot: &LakehouseSnapshot,
    now_ms: i64,
) -> Result<LakehouseExport, String> {
    register_snapshot(db, actor, snapshot, now_ms)
}

pub fn upgrade_schema(
    db: &RuntimeDb,
    actor: &str,
    snapshot: &LakehouseSnapshot,
    now_ms: i64,
) -> Result<LakehouseExport, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("upgrade", now_ms)?;
    let current = owned_snapshot(db, &snapshot.namespace, &snapshot.snapshot_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    if snapshot.schema_version != current.schema_version + 1 {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let validated = validate_snapshot(snapshot, actor, now_ms, Some(&current))?;
    db.cas_lakehouse_snapshot(&current, &validated)?;
    Ok(LakehouseExport {
        outcome: OUTCOME_EXPORTED.into(),
        snapshot: validated,
    })
}

pub fn redact_columns(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    snapshot_id: &str,
    columns: &[String],
    now_ms: i64,
) -> Result<LakehouseSnapshot, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("redact", now_ms)?;
    if columns.is_empty() {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let current = owned_snapshot(db, namespace, snapshot_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let live: BTreeSet<&str> = current
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    let already: BTreeSet<&str> = current
        .redacted_columns
        .iter()
        .map(String::as_str)
        .collect();
    let mut next = current.clone();
    for column in columns {
        required("column", column)?;
        reject_secret(column)?;
        if !live.contains(column.as_str()) || already.contains(column.as_str()) {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        next.redacted_columns.push(column.clone());
        for partition in &mut next.partitions {
            for row in &mut partition.rows {
                row.values.remove(column);
            }
            partition.partition_digest = partition_digest_for(partition)?;
        }
    }
    next.redacted_columns.sort();
    next.redacted_columns.dedup();
    next.admitted_at_ms = now_ms;
    next.snapshot_digest = snapshot_digest_for(&next)?;
    next.provenance_digest =
        provenance_for(&current.snapshot_digest, "redact", &next.snapshot_digest)?;
    db.cas_lakehouse_snapshot(&current, &next)?;
    Ok(next)
}

pub fn delete_partitions(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    snapshot_id: &str,
    partitions: &[String],
    now_ms: i64,
) -> Result<LakehouseSnapshot, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("delete", now_ms)?;
    if partitions.is_empty() {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let current = owned_snapshot(db, namespace, snapshot_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let live: BTreeSet<&str> = current
        .partitions
        .iter()
        .map(|partition| partition.partition_key.as_str())
        .collect();
    let already: BTreeSet<&str> = current
        .deleted_partitions
        .iter()
        .map(String::as_str)
        .collect();
    let mut next = current.clone();
    for key in partitions {
        required("partition", key)?;
        reject_secret(key)?;
        if !live.contains(key.as_str()) || already.contains(key.as_str()) {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        next.deleted_partitions.push(key.clone());
        next.partitions
            .retain(|partition| partition.partition_key != *key);
    }
    next.deleted_partitions.sort();
    next.deleted_partitions.dedup();
    next.admitted_at_ms = now_ms;
    next.snapshot_digest = snapshot_digest_for(&next)?;
    next.provenance_digest =
        provenance_for(&current.snapshot_digest, "delete", &next.snapshot_digest)?;
    db.cas_lakehouse_snapshot(&current, &next)?;
    Ok(next)
}

pub fn get_snapshot(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    snapshot_id: &str,
) -> Result<LakehouseSnapshot, String> {
    let snapshot = owned_snapshot(db, namespace, snapshot_id, actor)?;
    if snapshot.status == STATUS_REVOKED {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    Ok(snapshot)
}

pub fn revoke_snapshot(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    snapshot_id: &str,
    now_ms: i64,
) -> Result<LakehouseSnapshot, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("revoke", now_ms)?;
    let current = owned_snapshot(db, namespace, snapshot_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_REVOKED.into();
    next.admitted_at_ms = now_ms;
    next.snapshot_digest = snapshot_digest_for(&next)?;
    next.provenance_digest =
        provenance_for(&current.snapshot_digest, "revoke", &next.snapshot_digest)?;
    db.cas_lakehouse_snapshot(&current, &next)?;
    Ok(next)
}

fn validate_snapshot(
    snapshot: &LakehouseSnapshot,
    actor: &str,
    now_ms: i64,
    predecessor: Option<&LakehouseSnapshot>,
) -> Result<LakehouseSnapshot, String> {
    if snapshot.contract_version != LAKEHOUSE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if snapshot.adapter_version != PROFILE_VERSION
        || (snapshot.adapter_id != PROFILE_EVENTS && snapshot.adapter_id != PROFILE_METRICS)
    {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    required("snapshot id", &snapshot.snapshot_id)?;
    required("namespace", &snapshot.namespace)?;
    required("owner", &snapshot.owner)?;
    reject_secret(&snapshot.snapshot_id)?;
    reject_secret(&snapshot.namespace)?;
    reject_secret(&snapshot.owner)?;
    if snapshot.owner != actor
        || has_whitespace(&snapshot.namespace)
        || has_whitespace(&snapshot.snapshot_id)
        || has_whitespace(&snapshot.owner)
    {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    if snapshot.partition_keys.is_empty() || snapshot.partition_keys.len() > 4 {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    for key in &snapshot.partition_keys {
        required("partition key", key)?;
        reject_secret(key)?;
        if has_whitespace(key) {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
    }
    if snapshot.columns.is_empty() || snapshot.columns.len() > MAX_COLUMNS {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let mut seen = BTreeSet::new();
    for column in &snapshot.columns {
        required("column name", &column.name)?;
        reject_secret(&column.name)?;
        if !seen.insert(column.name.as_str())
            || has_whitespace(&column.name)
            || !matches!(column.col_type.as_str(), "string" | "i64" | "bool")
            || !classification_ok(&column.classification)
            || rank(&column.classification) > rank(&snapshot.security.classification_ceiling)
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
    }
    validate_security(&snapshot.security)?;
    if snapshot.status != STATUS_LIVE {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    if let Some(previous) = predecessor {
        if previous.snapshot_id != snapshot.snapshot_id
            || previous.namespace != snapshot.namespace
            || previous.owner != snapshot.owner
            || previous.adapter_id != snapshot.adapter_id
            || previous.partition_keys != snapshot.partition_keys
            || previous.security != snapshot.security
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        if snapshot.columns.len() <= previous.columns.len()
            || previous
                .columns
                .iter()
                .zip(snapshot.columns.iter())
                .any(|(left, right)| left != right)
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        if snapshot.redacted_columns != previous.redacted_columns
            || snapshot.deleted_partitions != previous.deleted_partitions
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        let previous_partitions: BTreeMap<&str, &LakehousePartition> = previous
            .partitions
            .iter()
            .map(|partition| (partition.partition_key.as_str(), partition))
            .collect();
        let next_partitions: BTreeMap<&str, &LakehousePartition> = snapshot
            .partitions
            .iter()
            .map(|partition| (partition.partition_key.as_str(), partition))
            .collect();
        if previous_partitions.keys().copied().collect::<BTreeSet<_>>()
            != next_partitions.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        let old_columns: Vec<&str> = previous
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        for (key, previous_partition) in &previous_partitions {
            let next_partition = next_partitions.get(key).ok_or(LAKEHOUSE_UNAVAILABLE)?;
            if previous_partition.rows.len() != next_partition.rows.len() {
                return Err(LAKEHOUSE_UNAVAILABLE.into());
            }
            let next_rows: BTreeMap<&str, &LakehouseRow> = next_partition
                .rows
                .iter()
                .map(|row| (row.row_id.as_str(), row))
                .collect();
            for previous_row in &previous_partition.rows {
                let next_row = next_rows
                    .get(previous_row.row_id.as_str())
                    .ok_or(LAKEHOUSE_UNAVAILABLE)?;
                for column in &old_columns {
                    if previous_row.values.get(*column) != next_row.values.get(*column) {
                        return Err(LAKEHOUSE_UNAVAILABLE.into());
                    }
                }
            }
        }
    } else if snapshot.schema_version != 1
        || !snapshot.redacted_columns.is_empty()
        || !snapshot.deleted_partitions.is_empty()
    {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let redacted: BTreeSet<&str> = snapshot
        .redacted_columns
        .iter()
        .map(String::as_str)
        .collect();
    let deleted: BTreeSet<&str> = snapshot
        .deleted_partitions
        .iter()
        .map(String::as_str)
        .collect();
    if snapshot.partitions.is_empty() || snapshot.partitions.len() > MAX_PARTITIONS {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let authorized: BTreeMap<&str, &LakehouseColumn> = snapshot
        .columns
        .iter()
        .map(|column| (column.name.as_str(), column))
        .collect();
    let mut seen_partitions = BTreeSet::new();
    let mut partitions = Vec::with_capacity(snapshot.partitions.len());
    for partition in &snapshot.partitions {
        required("partition key", &partition.partition_key)?;
        reject_secret(&partition.partition_key)?;
        if !seen_partitions.insert(partition.partition_key.as_str())
            || deleted.contains(partition.partition_key.as_str())
            || partition.rows.is_empty()
            || partition.rows.len() > MAX_ROWS
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        let mut seen_rows = BTreeSet::new();
        for row in &partition.rows {
            required("row id", &row.row_id)?;
            reject_secret(&row.row_id)?;
            if !seen_rows.insert(row.row_id.as_str()) || has_whitespace(&row.row_id) {
                return Err(LAKEHOUSE_UNAVAILABLE.into());
            }
            for (key, value) in &row.values {
                reject_secret(key)?;
                reject_secret(value)?;
                if redacted.contains(key.as_str()) {
                    return Err(LAKEHOUSE_UNAVAILABLE.into());
                }
                let Some(column) = authorized.get(key.as_str()) else {
                    return Err(LAKEHOUSE_UNAVAILABLE.into());
                };
                if !typed_value(&column.col_type, value) {
                    return Err(LAKEHOUSE_UNAVAILABLE.into());
                }
            }
            let visible = snapshot
                .columns
                .iter()
                .filter(|column| !redacted.contains(column.name.as_str()))
                .count();
            if row.values.len() != visible {
                return Err(LAKEHOUSE_UNAVAILABLE.into());
            }
        }
        let mut next_partition = partition.clone();
        let digest = partition_digest_for(&next_partition)?;
        if !partition.partition_digest.is_empty() && partition.partition_digest != digest {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        next_partition.partition_digest = digest;
        partitions.push(next_partition);
    }
    let mut next = snapshot.clone();
    next.partitions = partitions;
    next.status = STATUS_LIVE.into();
    next.admitted_by = actor.into();
    next.admitted_at_ms = now_ms;
    let digest = snapshot_digest_for(&next)?;
    if !snapshot.snapshot_digest.is_empty() && snapshot.snapshot_digest != digest {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    next.snapshot_digest = digest.clone();
    let prior = predecessor
        .map(|value| value.snapshot_digest.as_str())
        .unwrap_or("");
    let action = if predecessor.is_some() {
        "upgrade"
    } else {
        "export"
    };
    next.provenance_digest = provenance_for(prior, action, &digest)?;
    Ok(next)
}

fn validate_security(security: &LakehouseSecurity) -> Result<(), String> {
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
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    Ok(())
}

fn owned_snapshot(
    db: &RuntimeDb,
    namespace: &str,
    snapshot_id: &str,
    actor: &str,
) -> Result<LakehouseSnapshot, String> {
    required("namespace", namespace)?;
    required("snapshot id", snapshot_id)?;
    required("actor", actor)?;
    reject_secret(namespace)?;
    reject_secret(snapshot_id)?;
    reject_secret(actor)?;
    let snapshot = db
        .get_lakehouse_snapshot(namespace, snapshot_id)?
        .ok_or(LAKEHOUSE_UNAVAILABLE)?;
    if snapshot.owner != actor {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    if snapshot.contract_version != LAKEHOUSE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    validate_security(&snapshot.security)?;
    Ok(snapshot)
}

fn replay_existing(
    existing: LakehouseSnapshot,
    incoming: &LakehouseSnapshot,
    actor: &str,
) -> Result<LakehouseExport, String> {
    if existing.status == STATUS_REVOKED || existing.owner != actor {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    let mut candidate = incoming.clone();
    for partition in &mut candidate.partitions {
        let digest = partition_digest_for(partition)?;
        if !partition.partition_digest.is_empty() && partition.partition_digest != digest {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        partition.partition_digest = digest;
    }
    let digest = snapshot_digest_for(&candidate)?;
    if (!incoming.snapshot_digest.is_empty() && incoming.snapshot_digest != digest)
        || digest != existing.snapshot_digest
    {
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    Ok(LakehouseExport {
        outcome: OUTCOME_REPLAYED.into(),
        snapshot: existing,
    })
}

fn provenance_for(prior: &str, action: &str, digest: &str) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&(prior, action, digest))?
    ))
}

fn typed_value(col_type: &str, value: &str) -> bool {
    match col_type {
        "string" => true,
        "i64" => value.parse::<i64>().is_ok(),
        "bool" => matches!(value, "true" | "false"),
        _ => false,
    }
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
        return Err(LAKEHOUSE_UNAVAILABLE.into());
    }
    Ok(())
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

    fn column(name: &str, col_type: &str) -> LakehouseColumn {
        LakehouseColumn {
            name: name.into(),
            col_type: col_type.into(),
            classification: "internal".into(),
        }
    }

    fn row(id: &str, field: &str, value: &str) -> LakehouseRow {
        LakehouseRow {
            row_id: id.into(),
            values: BTreeMap::from([("id".into(), id.into()), (field.into(), value.into())]),
        }
    }

    fn snapshot(adapter: &str, snapshot_id: &str, field: &str) -> LakehouseSnapshot {
        LakehouseSnapshot {
            contract_version: LAKEHOUSE_CONTRACT.into(),
            snapshot_id: snapshot_id.into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            adapter_id: adapter.into(),
            adapter_version: PROFILE_VERSION.into(),
            schema_version: 1,
            partition_keys: vec!["day".into()],
            columns: vec![column("id", "string"), column(field, "string")],
            partitions: vec![
                LakehousePartition {
                    partition_key: "2026-08-30".into(),
                    rows: vec![row("1", field, "a")],
                    partition_digest: String::new(),
                },
                LakehousePartition {
                    partition_key: "2026-08-31".into(),
                    rows: vec![row("2", field, "b")],
                    partition_digest: String::new(),
                },
            ],
            security: LakehouseSecurity {
                contract_version: SECURITY_CONTRACT.into(),
                classification_ceiling: "internal".into(),
                purpose: "analytics".into(),
                residency_class: "eu".into(),
                trust_pin_digest: digest(1),
            },
            redacted_columns: Vec::new(),
            deleted_partitions: Vec::new(),
            provenance_digest: String::new(),
            snapshot_digest: String::new(),
            status: STATUS_LIVE.into(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        }
    }

    fn lifecycle(adapter: &str, snapshot_id: &str, field: &str) {
        let runtime = RuntimeDb::memory();
        let registered = register_snapshot(
            &runtime,
            "integrator",
            &snapshot(adapter, snapshot_id, field),
            1_000,
        )
        .unwrap();
        assert_eq!(registered.outcome, OUTCOME_EXPORTED);
        assert_eq!(registered.snapshot.partitions.len(), 2);
        assert!(!registered.snapshot.provenance_digest.is_empty());
        assert_eq!(
            reimport_snapshot(&runtime, "integrator", &registered.snapshot, 1_100)
                .unwrap()
                .outcome,
            OUTCOME_REPLAYED
        );
        let mut rewritten = registered.snapshot.clone();
        rewritten.schema_version = 2;
        rewritten.columns.push(column("note", "string"));
        rewritten.partitions[0].rows[0]
            .values
            .insert(field.into(), "mutated".into());
        rewritten.snapshot_digest.clear();
        assert_eq!(
            upgrade_schema(&runtime, "integrator", &rewritten, 1_500).unwrap_err(),
            LAKEHOUSE_UNAVAILABLE
        );
        let mut upgraded = registered.snapshot.clone();
        upgraded.schema_version = 2;
        upgraded.columns.push(column("note", "string"));
        for partition in &mut upgraded.partitions {
            for row in &mut partition.rows {
                row.values.insert("note".into(), "ok".into());
            }
            partition.partition_digest.clear();
        }
        upgraded.snapshot_digest.clear();
        let upgraded = upgrade_schema(&runtime, "integrator", &upgraded, 2_000).unwrap();
        assert_eq!(upgraded.outcome, OUTCOME_EXPORTED);
        assert_eq!(upgraded.snapshot.schema_version, 2);
        let redacted = redact_columns(
            &runtime,
            "integrator",
            "ops",
            snapshot_id,
            &["note".into()],
            3_000,
        )
        .unwrap();
        assert!(redacted.redacted_columns.contains(&"note".into()));
        assert!(!redacted.partitions[0].rows[0].values.contains_key("note"));
        let deleted = delete_partitions(
            &runtime,
            "integrator",
            "ops",
            snapshot_id,
            &["2026-08-30".into()],
            4_000,
        )
        .unwrap();
        assert_eq!(deleted.partitions.len(), 1);
        assert!(deleted.deleted_partitions.contains(&"2026-08-30".into()));
        assert_eq!(
            get_snapshot(&runtime, "intruder", "ops", snapshot_id).unwrap_err(),
            LAKEHOUSE_UNAVAILABLE
        );
        let mut hidden = registered.snapshot.clone();
        hidden.partitions[0].rows[0]
            .values
            .insert("grant".into(), "admin".into());
        assert!(serde_json::to_value(&hidden).is_ok());
        let mut unknown = snapshot(adapter, "lh:x", field);
        unknown.contract_version = "sekai.lakehouse-snapshot/v0".into();
        assert_eq!(
            register_snapshot(&runtime, "integrator", &unknown, 5_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        let revoked = revoke_snapshot(&runtime, "integrator", "ops", snapshot_id, 6_000).unwrap();
        assert_eq!(revoked.status, STATUS_REVOKED);
        assert_eq!(
            get_snapshot(&runtime, "integrator", "ops", snapshot_id).unwrap_err(),
            LAKEHOUSE_UNAVAILABLE
        );
        assert_eq!(
            upgrade_schema(&runtime, "integrator", &upgraded.snapshot, 6_100).unwrap_err(),
            LAKEHOUSE_UNAVAILABLE
        );
    }

    #[test]
    fn two_adapters_pass_partition_upgrade_redaction_deletion_reimport_and_provenance() {
        lifecycle(PROFILE_EVENTS, "lh:events", "kind");
        lifecycle(PROFILE_METRICS, "lh:metrics", "value");
    }

    #[test]
    fn hidden_fields_foreign_scope_and_postgres_fail_closed() {
        let mut hidden = serde_json::to_value(snapshot(PROFILE_EVENTS, "lh:h", "kind")).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("token".into(), serde_json::json!("ghp_nope"));
        assert!(serde_json::from_value::<LakehouseSnapshot>(hidden).is_err());
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "lakehouse snapshots are unavailable on the PostgreSQL community runtime"
        );
    }
}
