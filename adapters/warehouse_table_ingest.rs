//! Warehouse table ingest profile (#1085).
//!
//! The connector runs outside the control plane. It reads one committed table
//! snapshot (Iceberg-style: a snapshot id, a schema revision, typed columns,
//! and rows) with its own credentials, and turns it into a registered-source
//! `ApplySourceBatch` batch. The plane never opens the warehouse: its
//! authority is the admitted batch, and the table snapshot id is only the
//! checkpoint cursor (ADR 0036 stays: a live table is never object identity).
//!
//! - One registered source-type descriptor per table schema revision
//!   (`warehouse.table`, record kind, schema revision). Declared schema drift
//!   (a new revision) is an explicit act: until an operator registers the new
//!   revision, the plane refuses its batches before any write.
//! - Each row's source version is the warehouse's row version. Undeclared
//!   drift (row contents changing under the same revision without a new row
//!   version, as in a table rewrite) is a source-version conflict, so the
//!   plane quarantines the batch and the last consistent objects stay.
//! - Columns marked `hidden` never leave the connector: they are not in record
//!   properties, payload digests, or display names.

use sekai_chisei::sekai::object_sync::{
    ADAPTER_REGISTERED_OBJECT_SYNC, ADAPTER_REGISTERED_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    SOURCE_BATCH_VERSION, SourceBatch, SourceRecord, object_id_for,
};
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, registered_source_id,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Registered source name for warehouse tables.
pub const SOURCE: &str = "warehouse.table";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableSnapshot {
    /// Table identity, used as the source instance (`catalog.schema.table`).
    pub table: String,
    /// The warehouse's committed snapshot id; becomes the checkpoint cursor.
    pub snapshot_id: String,
    pub schema_revision: String,
    /// Object kind the rows admit as.
    pub record_kind: String,
    pub key_column: String,
    pub display_column: String,
    /// The warehouse's per-row version; it changes whenever the row does.
    pub version_column: String,
    pub columns: Vec<TableColumn>,
    pub rows: Vec<BTreeMap<String, String>>,
    /// Keys the snapshot removed since its parent.
    #[serde(default)]
    pub deleted_keys: Vec<String>,
    pub committed_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableColumn {
    pub name: String,
    /// Restricted columns stay inside the connector.
    #[serde(default)]
    pub hidden: bool,
}

pub fn parse(bytes: &[u8]) -> Result<TableSnapshot, String> {
    let snapshot: TableSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| format!("table snapshot is invalid: {error}"))?;
    validate(&snapshot)?;
    Ok(snapshot)
}

pub fn validate(snapshot: &TableSnapshot) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for column in &snapshot.columns {
        if !names.insert(column.name.as_str()) {
            return Err(format!("column {:?} is declared twice", column.name));
        }
    }
    let visible = |name: &str| {
        snapshot
            .columns
            .iter()
            .any(|column| column.name == name && !column.hidden)
    };
    if !visible(&snapshot.key_column)
        || !visible(&snapshot.display_column)
        || !visible(&snapshot.version_column)
    {
        return Err("key, display, and version columns must be declared and visible".into());
    }
    let mut keys = BTreeSet::new();
    for row in &snapshot.rows {
        if let Some(extra) = row.keys().find(|name| !names.contains(name.as_str())) {
            return Err(format!("row carries undeclared column {extra:?}"));
        }
        let key = row
            .get(&snapshot.key_column)
            .filter(|key| !key.is_empty())
            .ok_or("every row needs a key")?;
        row.get(&snapshot.version_column)
            .filter(|version| !version.is_empty())
            .ok_or("every row needs a version")?;
        row.get(&snapshot.display_column)
            .filter(|display| !display.is_empty())
            .ok_or("every row needs a display value")?;
        if !keys.insert(key.as_str()) {
            return Err(format!("row key {key:?} appears twice"));
        }
    }
    if let Some(both) = snapshot
        .deleted_keys
        .iter()
        .find(|key| keys.contains(key.as_str()))
    {
        return Err(format!("row key {both:?} is both present and deleted"));
    }
    Ok(())
}

/// The descriptor this snapshot's schema revision admits under.
pub fn descriptor(snapshot: &TableSnapshot) -> Result<ProposedSourceTypeDescriptor, String> {
    ProposedSourceTypeDescriptor::prepare(SOURCE, &snapshot.record_kind, &snapshot.schema_revision)
}

/// The object-type definition (`definition_json`) for this schema revision:
/// the record kind with its visible columns as properties. Restricted
/// columns are never declared.
pub fn object_type_definition(snapshot: &TableSnapshot) -> String {
    let properties = snapshot
        .columns
        .iter()
        .filter(|column| !column.hidden)
        .map(|column| column.name.as_str())
        .collect::<Vec<_>>();
    serde_json::json!({ "name": snapshot.record_kind, "properties": properties }).to_string()
}

/// Checkpoint cursor for a committed snapshot.
pub fn checkpoint(snapshot: &TableSnapshot) -> String {
    format!("snapshot:{}", snapshot.snapshot_id)
}

/// The object a row key admits as under `descriptor`.
pub fn object_id(
    descriptor: &ProposedSourceTypeDescriptor,
    table: &str,
    key: &str,
) -> Result<String, String> {
    Ok(object_id_for(
        &descriptor.digest,
        &registered_source_id(descriptor, table, key)?,
    ))
}

fn visible_values(
    snapshot: &TableSnapshot,
    row: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    snapshot
        .columns
        .iter()
        .filter(|column| !column.hidden)
        .filter_map(|column| {
            row.get(&column.name)
                .map(|value| (column.name.clone(), value.clone()))
        })
        .collect()
}

fn digest_of(values: &BTreeMap<String, String>) -> String {
    let canonical = serde_json::to_vec(values).expect("string map serializes");
    format!("sha256:{:x}", Sha256::digest(canonical))
}

/// One record per row (upsert) and per deleted key (tombstone). The
/// snapshot is validated first, so a hand-built one fails instead of
/// panicking.
pub fn records(snapshot: &TableSnapshot) -> Result<Vec<SourceRecord>, String> {
    validate(snapshot)?;
    let upserts = snapshot.rows.iter().map(|row| {
        let properties = visible_values(snapshot, row);
        let digest = digest_of(&properties);
        SourceRecord {
            source: SOURCE.into(),
            source_instance: snapshot.table.clone(),
            external_id: row[&snapshot.key_column].clone(),
            source_version: row[&snapshot.version_column].clone(),
            type_name: snapshot.record_kind.clone(),
            display_name: properties[&snapshot.display_column].clone(),
            payload_digest: digest,
            properties,
            deleted: false,
            observed_at_ms: snapshot.committed_at_ms,
            source_sequence: None,
        }
    });
    let tombstones = snapshot.deleted_keys.iter().map(|key| {
        let digest = digest_of(&BTreeMap::from([(
            snapshot.key_column.clone(),
            key.clone(),
        )]));
        SourceRecord {
            source: SOURCE.into(),
            source_instance: snapshot.table.clone(),
            external_id: key.clone(),
            source_version: format!("deleted@{}", snapshot.snapshot_id),
            type_name: snapshot.record_kind.clone(),
            display_name: key.clone(),
            payload_digest: digest,
            properties: BTreeMap::new(),
            deleted: true,
            observed_at_ms: snapshot.committed_at_ms,
            source_sequence: None,
        }
    });
    Ok(upserts.chain(tombstones).collect())
}

/// The batch that advances the table's checkpoint from `current_cursor` to
/// this snapshot.
pub fn batch(
    snapshot: &TableSnapshot,
    namespace: &str,
    producer_identity: &str,
    current_cursor: &str,
) -> Result<SourceBatch, String> {
    let descriptor = descriptor(snapshot)?;
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: namespace.into(),
        producer_identity: producer_identity.into(),
        source: SOURCE.into(),
        source_instance: snapshot.table.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_REGISTERED_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_REGISTERED_OBJECT_SYNC_VERSION.into(),
        type_digest: descriptor.digest,
        current_cursor: current_cursor.into(),
        proposed_next_cursor: checkpoint(snapshot),
        idempotency_key: format!("{}@{}", snapshot.table, snapshot.snapshot_id),
        batch_digest: String::new(),
        collected_at_ms: snapshot.committed_at_ms,
        records: records(snapshot)?,
        delivery: None,
    };
    batch.batch_digest = batch
        .canonical_digest()
        .map_err(|error| format!("source batch is invalid: {error:?}"))?;
    Ok(batch)
}

/// The executor-side view of one table, holding the source credentials and
/// current rows. Writes are conditional on a row's version, and every write
/// commits a new snapshot the connector then ingests (#1085 writeback).
pub struct TableStore {
    snapshot: std::sync::Mutex<TableSnapshot>,
}

impl TableStore {
    pub fn new(snapshot: TableSnapshot) -> Result<Self, String> {
        validate(&snapshot)?;
        Ok(Self {
            snapshot: std::sync::Mutex::new(snapshot),
        })
    }

    /// The latest committed snapshot.
    pub fn snapshot(&self) -> TableSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Stable reference to one row, the same identity ingest admits.
    pub fn resource(&self, key: &str) -> Result<String, String> {
        let snapshot = self.snapshot();
        registered_source_id(&descriptor(&snapshot)?, &snapshot.table, key)
    }

    pub fn row_version(&self, key: &str) -> Result<String, String> {
        let snapshot = self.snapshot();
        snapshot
            .rows
            .iter()
            .find(|row| row.get(&snapshot.key_column).map(String::as_str) == Some(key))
            .and_then(|row| row.get(&snapshot.version_column).cloned())
            .ok_or_else(|| format!("row {key:?} does not exist"))
    }

    /// Applies `change` to row `key` while it is still at `expected_version`,
    /// then commits the next snapshot. Only visible, non-identity columns can
    /// change.
    pub fn apply(
        &self,
        key: &str,
        expected_version: &str,
        change: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let writable = |name: &str| {
            name != snapshot.key_column
                && name != snapshot.version_column
                && snapshot
                    .columns
                    .iter()
                    .any(|column| column.name == name && !column.hidden)
        };
        if change.is_empty() || !change.keys().all(|name| writable(name)) {
            return Err("the change names a column that cannot be written".into());
        }
        let key_column = snapshot.key_column.clone();
        let version_column = snapshot.version_column.clone();
        let row = snapshot
            .rows
            .iter_mut()
            .find(|row| row.get(&key_column).map(String::as_str) == Some(key))
            .ok_or_else(|| format!("row {key:?} does not exist"))?;
        if row.get(&version_column).map(String::as_str) != Some(expected_version) {
            return Err("record version changed since the writeback was decided".into());
        }
        let next = expected_version
            .parse::<u64>()
            .map(|version| (version + 1).to_string())
            .map_err(|_| "row versions must be integers".to_string())?;
        row.extend(change.clone());
        row.insert(version_column, next.clone());
        snapshot.snapshot_id = snapshot
            .snapshot_id
            .parse::<u64>()
            .map(|id| (id + 1).to_string())
            .map_err(|_| "snapshot ids must be integers".to_string())?;
        snapshot.deleted_keys.clear();
        snapshot.committed_at_ms += 1_000;
        Ok(next)
    }
}
