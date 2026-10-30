//! Governed export (#1627, ADR 0130).
//!
//! Data leaving the plane needs more than read. A namespace admin grants a
//! principal export on a namespace, and every grant and revocation is an
//! audit decision. An export streams an object set as CSV, JSON Lines, or
//! Parquet under the caller's read policy, so hidden rows and properties never
//! reach the file. Its receipt is written before the first byte and closed
//! with the row count and the digest of every byte sent; a stream that ends
//! early (a dropped client, an error) closes it as aborted.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use sekai_domain::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptArtifact,
    ReceiptEventKind,
};

pub const EXPORT_CONTRACT: &str = "sekai.governed-export/v1";
pub const EXPORT_DENIED: &str = "export_not_granted";
/// Another change to the same grant landed first; retry.
pub const GRANT_CHANGED: &str = "export_grant_changed";
/// An exporter renews its lease while it streams; another instance may
/// close an export whose lease ran out as aborted.
pub const EXPORT_LEASE_MS: i64 = 60_000;
const EXPORT_RENEW_MS: i64 = 10_000;
/// A send must end this long before the lease would run out.
const SEND_MARGIN_MS: i64 = 5_000;
/// Abandoned exports closed per sweep.
const RECOVERY_BATCH: usize = 32;
const MAX_REASON: usize = 1024;
/// Columns an export may select.
pub const MAX_EXPORT_COLUMNS: usize = 256;

/// One principal's export grant on one namespace. Revoking keeps the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportGrant {
    pub namespace: String,
    pub principal: String,
    pub granted_by: String,
    pub granted_at_ms: i64,
    pub reason: String,
    #[serde(default)]
    pub revoked_by: String,
    #[serde(default)]
    pub revoked_at_ms: i64,
    #[serde(default)]
    pub revocation_reason: String,
}

impl ExportGrant {
    pub fn active(&self) -> bool {
        self.revoked_by.is_empty()
    }
}

fn check_reason(reason: &str) -> Result<(), String> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON {
        return Err(format!("reason must be 1 to {MAX_REASON} bytes"));
    }
    Ok(())
}

/// Records the next state of a grant: the history row, which is the
/// durable record and fails when another change landed since, then the
/// audit decision mirroring it.
fn record_change(db: &RuntimeDb, seq: i64, grant: &ExportGrant) -> Result<(), String> {
    if !db.insert_export_grant(seq, grant)? {
        return Err(GRANT_CHANGED.into());
    }
    mirror(db, seq, grant)
}

/// Mirrors every entry of a grant's history, so an audit write lost before
/// any later change is repaired by the next call, not only the latest.
fn mirror_history(db: &RuntimeDb, namespace: &str, principal: &str) -> Result<(), String> {
    for (seq, grant) in db.export_grant_history(namespace, principal)? {
        mirror(db, seq, &grant)?;
    }
    Ok(())
}

/// The decision id of history entry `seq`: a digest of the length-prefixed
/// (namespace, principal, seq), so no two grants share one.
fn grant_decision_id(namespace: &str, principal: &str, seq: i64) -> String {
    let mut hasher = Sha256::new();
    for part in [namespace, principal] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(seq.to_be_bytes());
    format!("export-grant:{:x}", hasher.finalize())
}

/// Writes the audit decision of history entry `seq`. It is derived from the
/// entry alone and written idempotently, so a retry after a lost write
/// repairs it and never duplicates it.
fn mirror(db: &RuntimeDb, seq: i64, grant: &ExportGrant) -> Result<(), String> {
    let (outcome, actor, at_ms) = if grant.active() {
        ("granted", &grant.granted_by, grant.granted_at_ms)
    } else {
        ("revoked", &grant.revoked_by, grant.revoked_at_ms)
    };
    db.record_decisions_idempotently(&[Decision {
        id: grant_decision_id(&grant.namespace, &grant.principal, seq),
        timestamp: at_ms,
        actor: actor.clone(),
        action: "namespace_export_grant".into(),
        reason: format!("export grant {outcome} under {EXPORT_CONTRACT}"),
        evidence: HashMap::from([
            ("contract_version".into(), EXPORT_CONTRACT.into()),
            ("namespace".into(), grant.namespace.clone()),
            ("principal".into(), grant.principal.clone()),
            ("grant_seq".into(), seq.to_string()),
            (
                "grant_record".into(),
                serde_json::to_string(grant).map_err(|error| error.to_string())?,
            ),
        ]),
        target_id: format!("{}:{}", grant.namespace, grant.principal),
        outcome: outcome.into(),
    }])
}

/// Grants `principal` export on `namespace`. An active grant is returned as
/// it stands, so a retry records nothing twice; any audit decision lost
/// earlier is written first.
pub fn grant_export(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    reason: &str,
    actor: &str,
    now_ms: i64,
) -> Result<ExportGrant, String> {
    check_reason(reason)?;
    if principal.trim().is_empty() || principal.trim() != principal {
        return Err("principal must be canonical".into());
    }
    mirror_history(db, namespace, principal)?;
    let latest = db.latest_export_grant(namespace, principal)?;
    if let Some((_, existing)) = &latest
        && existing.active()
    {
        return Ok(existing.clone());
    }
    let grant = ExportGrant {
        namespace: namespace.into(),
        principal: principal.into(),
        granted_by: actor.into(),
        granted_at_ms: now_ms,
        reason: reason.trim().into(),
        revoked_by: String::new(),
        revoked_at_ms: 0,
        revocation_reason: String::new(),
    };
    let seq = latest.map_or(1, |(seq, _)| seq + 1);
    record_change(db, seq, &grant)?;
    Ok(grant)
}

/// Revokes `principal`'s export on `namespace`, keeping the grant and the
/// revocation's own reason; revoking a revoked or missing grant changes
/// nothing.
pub fn revoke_export(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    reason: &str,
    actor: &str,
    now_ms: i64,
) -> Result<Option<ExportGrant>, String> {
    check_reason(reason)?;
    mirror_history(db, namespace, principal)?;
    let Some((seq, existing)) = db.latest_export_grant(namespace, principal)? else {
        return Ok(None);
    };
    if !existing.active() {
        return Ok(Some(existing));
    }
    let revoked = ExportGrant {
        revoked_by: actor.into(),
        revoked_at_ms: now_ms,
        revocation_reason: reason.trim().into(),
        ..existing
    };
    record_change(db, seq + 1, &revoked)?;
    Ok(Some(revoked))
}

/// Writes the receipt of a saved export's run refused before it began
/// (#1628), closed as `refused` with `reason`; returns its id. A revoked
/// grant or a lost read therefore leaves a receipt, not only a refusal.
pub fn record_refused_run(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    definition_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<String, String> {
    let operation_id = format!("export-{}", uuid::Uuid::new_v4().simple());
    let receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.clone(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "governed_export".into(),
        initiating_actor: actor.into(),
        schema_version: EXPORT_CONTRACT.into(),
        policy_version: String::new(),
        started_at_ms: now_ms,
        completed_at_ms: Some(now_ms),
        events: vec![
            event(
                &operation_id,
                "intent",
                ReceiptEventKind::IntentRecorded,
                actor,
                now_ms,
                BTreeMap::from([
                    ("source_kind".into(), "export_definition".into()),
                    ("source_id".into(), definition_id.into()),
                ]),
            ),
            event(
                &operation_id,
                "outcome",
                ReceiptEventKind::OutcomeRecorded,
                actor,
                now_ms,
                BTreeMap::from([
                    ("outcome".into(), "refused".into()),
                    ("reason".into(), reason.into()),
                ]),
            ),
        ],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    };
    db.insert_closed_export_receipt(
        &operation_id,
        namespace,
        &serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
    )?;
    Ok(operation_id)
}

/// Removes expired export artifacts (#1628): any instance may sweep.
pub fn sweep_expired_artifacts(db: &RuntimeDb, now_ms: i64) -> Result<(), String> {
    db.sweep_export_artifacts(now_ms).map(|_| ())
}

/// A completed artifact the adapter may fetch and acknowledge.
pub struct DeliverableExportArtifact {
    pub receipt_id: String,
    pub namespace: String,
    pub definition_id: String,
    pub initiating_actor: String,
    pub content_digest: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

pub fn completed_digest(receipt: &OperationReceipt) -> Option<String> {
    receipt.events.iter().rev().find_map(|event| {
        (event.attributes.get("outcome").map(String::as_str) == Some("completed"))
            .then(|| event.attributes.get("content_digest").cloned())
            .flatten()
    })
}

/// Completed, unexpired, unacknowledged artifacts in `namespace`.
pub fn list_deliverable_export_artifacts(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
) -> Result<Vec<DeliverableExportArtifact>, String> {
    let mut deliverable = Vec::new();
    for artifact in db.list_unacked_export_artifacts(namespace, now_ms)? {
        let Some(receipt) = export_receipt(db, &artifact.receipt_id)? else {
            continue;
        };
        let Some(content_digest) = completed_digest(&receipt) else {
            continue;
        };
        deliverable.push(DeliverableExportArtifact {
            receipt_id: artifact.receipt_id,
            namespace: artifact.namespace,
            definition_id: artifact.definition_id,
            initiating_actor: receipt.initiating_actor,
            content_digest,
            created_at_ms: artifact.created_at_ms,
            expires_at_ms: artifact.expires_at_ms,
        });
    }
    Ok(deliverable)
}

/// Acknowledges delivery of a completed artifact whose digest the adapter
/// verified. Idempotent once acknowledged.
pub fn acknowledge_export_delivery(
    db: &RuntimeDb,
    receipt_id: &str,
    content_digest: &str,
    now_ms: i64,
) -> Result<bool, String> {
    let Some(receipt) = export_receipt(db, receipt_id)? else {
        return Ok(false);
    };
    let Some(digest) = completed_digest(&receipt) else {
        return Err("export artifact is not complete".into());
    };
    if digest != content_digest {
        return Err("export artifact digest mismatch".into());
    }
    db.acknowledge_export_artifact(receipt_id, now_ms)
}

/// Records an export refused for want of an export grant: a refusal, never
/// data.
pub fn record_refusal(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    source_kind: &str,
    source_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("export-refused:{}", uuid::Uuid::new_v4().simple()),
        timestamp: now_ms,
        actor: actor.into(),
        action: "governed_export".into(),
        reason: EXPORT_DENIED.into(),
        evidence: HashMap::from([
            ("contract_version".into(), EXPORT_CONTRACT.into()),
            ("namespace".into(), namespace.into()),
            ("source_kind".into(), source_kind.into()),
            ("source_id".into(), source_id.into()),
        ]),
        target_id: namespace.into(),
        outcome: "refused".into(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    JsonLines,
    Parquet,
}

impl ExportFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "csv" => Some(Self::Csv),
            "jsonl" => Some(Self::JsonLines),
            "parquet" => Some(Self::Parquet),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::JsonLines => "jsonl",
            Self::Parquet => "parquet",
        }
    }
}

/// Bytes of an export file, with how many rows they represent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPart {
    pub bytes: Vec<u8>,
    pub rows: u64,
}

impl AsRef<[u8]> for EncodedPart {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::borrow::Borrow<[u8]> for EncodedPart {
    fn borrow(&self) -> &[u8] {
        &self.bytes
    }
}

impl IntoIterator for EncodedPart {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

/// Encodes rows: the object id when exporting objects, then the selected
/// columns in order. A value the reader may not see is absent from what it
/// reads, so its cell is empty (CSV), its key absent (JSON Lines), or null
/// (Parquet).
pub struct RowEncoder {
    format: ExportFormat,
    columns: Vec<String>,
    id_column: bool,
    parquet: Option<sekai_parquet_export::Encoder>,
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) || value.trim() != value {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

impl RowEncoder {
    pub fn new(
        format: ExportFormat,
        columns: Vec<String>,
        id_column: bool,
    ) -> Result<Self, String> {
        if columns.len() > MAX_EXPORT_COLUMNS {
            return Err(format!(
                "at most {MAX_EXPORT_COLUMNS} properties may be exported"
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for column in &columns {
            if column.trim().is_empty() || (id_column && column == "id") || !seen.insert(column) {
                return Err(format!(
                    "property {column:?} cannot be exported twice or as id"
                ));
            }
        }
        let parquet = (format == ExportFormat::Parquet)
            .then(|| sekai_parquet_export::Encoder::new(columns.clone(), id_column));
        Ok(Self {
            format,
            columns,
            id_column,
            parquet,
        })
    }

    /// Selected columns, in export order.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Whether the encoder leads with an object id column.
    pub fn id_column(&self) -> bool {
        self.id_column
    }

    /// Bytes before the first row.
    pub fn header(&self) -> Vec<u8> {
        match self.format {
            ExportFormat::Csv => {
                let mut line = self
                    .id_column
                    .then_some("id")
                    .into_iter()
                    .chain(self.columns.iter().map(String::as_str))
                    .map(csv_field)
                    .collect::<Vec<_>>()
                    .join(",");
                line.push('\n');
                line.into_bytes()
            }
            ExportFormat::JsonLines => Vec::new(),
            ExportFormat::Parquet => sekai_parquet_export::Encoder::header(),
        }
    }

    /// One row: `id` leads when the encoder exports objects.
    pub fn row(&self, id: &str, values: &HashMap<String, String>) -> Vec<u8> {
        let lead = self.id_column.then_some(id);
        match self.format {
            ExportFormat::Csv => {
                let mut line = lead
                    .into_iter()
                    .chain(
                        self.columns
                            .iter()
                            .map(|column| values.get(column).map(String::as_str).unwrap_or("")),
                    )
                    .map(csv_field)
                    .collect::<Vec<_>>()
                    .join(",");
                line.push('\n');
                line.into_bytes()
            }
            ExportFormat::JsonLines => {
                let mut row = serde_json::Map::new();
                if let Some(id) = lead {
                    row.insert("id".into(), id.into());
                }
                for column in &self.columns {
                    if let Some(value) = values.get(column) {
                        row.insert(column.clone(), value.clone().into());
                    }
                }
                let mut line = serde_json::Value::Object(row).to_string().into_bytes();
                line.push(b'\n');
                line
            }
            ExportFormat::Parquet => Vec::new(),
        }
    }

    /// Encodes `id` and `values`. CSV and JSON Lines yield one row; Parquet
    /// yields a row group when the group fills.
    pub fn push(&mut self, id: &str, values: &HashMap<String, String>) -> Option<EncodedPart> {
        match self.format {
            ExportFormat::Csv | ExportFormat::JsonLines => Some(EncodedPart {
                bytes: self.row(id, values),
                rows: 1,
            }),
            ExportFormat::Parquet => {
                self.parquet
                    .as_mut()?
                    .push(id, values)
                    .map(|flush| EncodedPart {
                        bytes: flush.bytes,
                        rows: flush.rows,
                    })
            }
        }
    }

    /// Remaining Parquet bytes (last group and footer). Empty for CSV and
    /// JSON Lines.
    pub fn finish(&mut self) -> Option<EncodedPart> {
        let flush = self.parquet.as_mut()?.finish();
        (!flush.bytes.is_empty()).then_some(EncodedPart {
            bytes: flush.bytes,
            rows: flush.rows,
        })
    }
}

/// What an export reads, for its receipt.
pub struct ExportSource {
    pub namespace: String,
    /// `object_set` or `dataset_version`.
    pub source_kind: &'static str,
    /// The object kind, or the dataset id.
    pub source_id: String,
    /// The object set's query digest, or the dataset version id.
    pub source_version: String,
    /// The definition revision the set was read under; empty for datasets.
    pub definition_digest: String,
    pub format: ExportFormat,
    pub columns: Vec<String>,
    /// The principal whose export grant allowed the export.
    pub granted_via: String,
    /// Properties listed on a fingerprint policy for this namespace; empty
    /// when fingerprinting is off.
    pub fingerprint_properties: Vec<String>,
    /// Row-group size of a fingerprinted export; 0 when off.
    pub fingerprint_group_size: u32,
}

/// The receipt of one export. It is written when the export begins, before
/// any byte, with a lease on the export the exporter renews as it sends;
/// [`ExportReceipt::complete`] closes it, and dropping it without completing
/// closes it as aborted. An exporter whose process dies cannot drop it: the
/// next export sweeps leases that ran out and closes those receipts as
/// aborted. An outcome is decided once, on the lease row, before the receipt
/// carries it; an exporter whose lease ran out can neither renew nor
/// complete, and stops.
pub struct ExportReceipt {
    db: RuntimeDb,
    receipt: OperationReceipt,
    hasher: Sha256,
    rows: u64,
    renewed_at_ms: i64,
    lease_until_ms: i64,
    /// Set once a renewal fails; the export can then never complete.
    lost: bool,
    closed: bool,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// The decided outcome of an export, recorded on its lease row before the
/// receipt carries it.
#[derive(Serialize, Deserialize)]
struct Closing {
    attributes: BTreeMap<String, String>,
    artifact: Option<ReceiptArtifact>,
    at_ms: i64,
}

/// Decides the export's outcome under the lease condition; true when this
/// call decided it.
fn claim_close(
    db: &RuntimeDb,
    operation_id: &str,
    closing: &Closing,
    expired: bool,
    now_ms: i64,
) -> Result<bool, String> {
    let json = serde_json::to_string(closing).map_err(|error| error.to_string())?;
    db.claim_export_close(operation_id, &json, expired, now_ms)
}

/// Writes a decided outcome into the export's receipt, once. Safe to repeat
/// and to run from any instance.
fn finalize(db: &RuntimeDb, operation_id: &str) -> Result<(), String> {
    let Some((Some(json), receipt_json)) = db.open_export_row(operation_id)? else {
        return Ok(());
    };
    let closing: Closing = serde_json::from_str(&json).map_err(|error| error.to_string())?;
    let mut receipt: OperationReceipt =
        serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
    let actor = receipt.initiating_actor.clone();
    receipt.events.push(event(
        operation_id,
        "outcome",
        ReceiptEventKind::OutcomeRecorded,
        &actor,
        closing.at_ms,
        closing.attributes,
    ));
    receipt.artifact = closing.artifact;
    receipt.completed_at_ms = Some(closing.at_ms);
    db.finish_export_receipt(
        operation_id,
        &serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
    )
}

/// The receipt of an export, open or closed.
pub fn export_receipt(
    db: &RuntimeDb,
    operation_id: &str,
) -> Result<Option<OperationReceipt>, String> {
    db.get_export_receipt_json(operation_id)?
        .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        .transpose()
}

fn aborted(rows: u64, reason: &str, at_ms: i64) -> Closing {
    Closing {
        attributes: BTreeMap::from([
            ("outcome".to_string(), "aborted".to_string()),
            ("row_count".to_string(), rows.to_string()),
            ("reason".to_string(), reason.to_string()),
        ]),
        artifact: None,
        at_ms,
    }
}

/// Finishes exports whose outcome is decided, and closes as aborted those
/// whose exporter stopped renewing its lease. Each outcome is decided once
/// under its lease condition, so two instances never disagree.
pub fn recover_abandoned_exports(db: &RuntimeDb, now_ms: i64) -> Result<(), String> {
    for (operation_id, decided) in db.recoverable_exports(now_ms, RECOVERY_BATCH)? {
        if decided
            || claim_close(
                db,
                &operation_id,
                &aborted(0, "exporter_lost", now_ms),
                true,
                now_ms,
            )?
        {
            finalize(db, &operation_id)?;
        }
    }
    Ok(())
}

impl ExportReceipt {
    pub fn begin(
        db: RuntimeDb,
        actor: &str,
        source: &ExportSource,
        now_ms: i64,
    ) -> Result<Self, String> {
        recover_abandoned_exports(&db, now_ms)?;
        let operation_id = format!("export-{}", uuid::Uuid::new_v4().simple());
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.clone(),
            parent_operation_id: None,
            namespace: source.namespace.clone(),
            operation_class: "governed_export".into(),
            initiating_actor: actor.into(),
            schema_version: EXPORT_CONTRACT.into(),
            policy_version: source.definition_digest.clone(),
            started_at_ms: now_ms,
            completed_at_ms: None,
            events: vec![event(
                &operation_id,
                "intent",
                ReceiptEventKind::IntentRecorded,
                actor,
                now_ms,
                {
                    let mut attributes = BTreeMap::from([
                        ("source_kind".into(), source.source_kind.into()),
                        ("source_id".into(), source.source_id.clone()),
                        ("source_version".into(), source.source_version.clone()),
                        ("format".into(), source.format.as_str().into()),
                        ("properties".into(), source.columns.join(",")),
                        ("granted_via".into(), source.granted_via.clone()),
                    ]);
                    if !source.fingerprint_properties.is_empty() {
                        attributes.insert(
                            "fingerprint_properties".into(),
                            source.fingerprint_properties.join(","),
                        );
                        attributes.insert(
                            "fingerprint_group_size".into(),
                            source.fingerprint_group_size.to_string(),
                        );
                    }
                    attributes
                },
            )],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: (!source.definition_digest.is_empty())
                .then(|| source.definition_digest.clone()),
            artifact: None,
        };
        // One row holds the receipt and the lease, so whoever closes the
        // export closes it there.
        let lease_until_ms = now_ms + EXPORT_LEASE_MS;
        db.open_export(
            &operation_id,
            &source.namespace,
            lease_until_ms,
            &serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
        )?;
        Ok(Self {
            db,
            receipt,
            hasher: Sha256::new(),
            rows: 0,
            renewed_at_ms: now_ms,
            lease_until_ms,
            lost: false,
            closed: false,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.receipt.operation_id
    }

    /// Counts bytes about to be sent toward the digest, renewing the lease
    /// as time passes. False when the lease is gone: the export must stop.
    pub fn record(&mut self, bytes: &[u8], rows: u64) -> bool {
        self.hasher.update(bytes);
        self.rows += rows;
        let now = now_ms();
        if self.lost || now - self.renewed_at_ms < EXPORT_RENEW_MS {
            return !self.lost;
        }
        // An expired lease is never revived, swept or not; any failure to
        // renew ends the export for good.
        if self
            .db
            .renew_export(&self.receipt.operation_id, now, now + EXPORT_LEASE_MS)
            .unwrap_or(false)
        {
            self.renewed_at_ms = now;
            self.lease_until_ms = now + EXPORT_LEASE_MS;
        } else {
            self.lost = true;
        }
        !self.lost
    }

    /// False once a renewal failed: the export must stop and not complete.
    pub fn live(&self) -> bool {
        !self.lost
    }

    /// The time by which anything queued now must reach the client: before
    /// the lease could run out and another instance close the export.
    pub fn deadline_ms(&self) -> i64 {
        self.lease_until_ms - SEND_MARGIN_MS
    }

    /// How long a send may wait and still end before [`Self::deadline_ms`].
    pub fn send_budget(&self) -> Option<std::time::Duration> {
        let left = self.deadline_ms() - now_ms();
        (left > 0).then(|| std::time::Duration::from_millis(left as u64))
    }

    /// Closes the receipt as complete, only while the lease is live;
    /// returns the row count and digest.
    pub fn complete(mut self, now_ms: i64) -> Result<(u64, String), String> {
        if self.lost {
            // Left open: the sweep closes it as aborted once the lease ends.
            return Err("export lease lost".into());
        }
        self.closed = true;
        let digest = format!("sha256:{:x}", self.hasher.clone().finalize());
        let operation_id = self.receipt.operation_id.clone();
        let closing = Closing {
            attributes: BTreeMap::from([
                ("outcome".to_string(), "completed".to_string()),
                ("row_count".to_string(), self.rows.to_string()),
                ("content_digest".to_string(), digest.clone()),
            ]),
            artifact: Some(ReceiptArtifact {
                artifact_id: operation_id.clone(),
                digest: digest.clone(),
                tree_digest: String::new(),
                files: Vec::new(),
            }),
            at_ms: now_ms,
        };
        if !claim_close(&self.db, &operation_id, &closing, false, now_ms)? {
            return Err("export lease lost".into());
        }
        finalize(&self.db, &operation_id)?;
        Ok((self.rows, digest))
    }
}

impl Drop for ExportReceipt {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let now = now_ms();
        // An expired lease is left to the sweep, which decides it.
        if claim_close(
            &self.db,
            &self.receipt.operation_id,
            &aborted(self.rows, "export_ended", now),
            false,
            now,
        )
        .unwrap_or(false)
        {
            let _ = finalize(&self.db, &self.receipt.operation_id);
        }
    }
}

fn event(
    operation_id: &str,
    suffix: &str,
    kind: ReceiptEventKind,
    actor: &str,
    now_ms: i64,
    attributes: BTreeMap<String, String>,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{operation_id}:{suffix}"),
        operation_id: operation_id.into(),
        parent_event_id: (suffix != "intent").then(|| format!("{operation_id}:intent")),
        timestamp_ms: now_ms,
        surface: kind.surface(),
        kind,
        actor: actor.into(),
        references: Vec::new(),
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;

    fn object(id: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "Ticket".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn csv_quotes_what_needs_it_and_leaves_hidden_cells_empty() {
        let encoder = RowEncoder::new(
            ExportFormat::Csv,
            vec!["title".into(), "secret".into()],
            true,
        )
        .unwrap();
        assert_eq!(encoder.header(), b"id,title,secret\n");
        assert_eq!(
            {
                let object = object("t-1", &[("title", "a, \"b\"\nc")]);
                encoder.row(&object.id, &object.properties)
            },
            b"t-1,\"a, \"\"b\"\"\nc\",\n"
        );
    }

    #[test]
    fn json_lines_omit_hidden_properties() {
        let encoder = RowEncoder::new(
            ExportFormat::JsonLines,
            vec!["title".into(), "secret".into()],
            true,
        )
        .unwrap();
        assert!(encoder.header().is_empty());
        assert_eq!(
            {
                let object = object("t-1", &[("title", "x")]);
                encoder.row(&object.id, &object.properties)
            },
            b"{\"id\":\"t-1\",\"title\":\"x\"}\n"
        );
    }

    #[test]
    fn parquet_round_trips_and_hashes_the_file() {
        let mut encoder = RowEncoder::new(
            ExportFormat::Parquet,
            vec!["title".into(), "secret".into()],
            true,
        )
        .unwrap();
        let mut file = encoder.header();
        let mut rows = 0u64;
        if let Some(part) = encoder.push("t-1", &object("t-1", &[("title", "hello")]).properties) {
            rows += part.rows;
            file.extend(part.bytes);
        }
        if let Some(part) = encoder.finish() {
            rows += part.rows;
            file.extend(part.bytes);
        }
        assert_eq!(rows, 1);
        let table = sekai_parquet_export::decode(&file).unwrap();
        assert_eq!(table.rows[0].id, "t-1");
        assert_eq!(
            table.rows[0].values.get("title").map(String::as_str),
            Some("hello")
        );
        assert!(!table.rows[0].values.contains_key("secret"));
        let digest = format!("sha256:{:x}", Sha256::digest(&file));
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 7 + 64);
    }

    /// Grant, retry, revoke and re-grant on either backend.
    fn grant_contract(db: &RuntimeDb, ns: &str) {
        let granted = grant_export(db, ns, "alice", "audit", "admin", 1).unwrap();
        assert!(granted.active());
        assert_eq!(
            grant_export(db, ns, "alice", "again", "admin", 2).unwrap(),
            granted
        );
        assert!(grant_export(db, ns, "alice", " ", "admin", 2).is_err());
        let revoked = revoke_export(db, ns, "alice", "done", "admin", 3)
            .unwrap()
            .unwrap();
        assert!(!revoked.active());
        assert_eq!(revoked.revocation_reason, "done");
        assert_eq!(revoked.reason, "audit");
        assert_eq!(db.get_export_grant(ns, "alice").unwrap(), Some(revoked));
        assert_eq!(
            revoke_export(db, ns, "bob", "done", "admin", 3).unwrap(),
            None
        );
        assert!(
            grant_export(db, ns, "alice", "new audit", "admin", 4)
                .unwrap()
                .active()
        );
    }

    #[test]
    fn grant_decision_ids_never_collide_across_delimiters() {
        assert_ne!(
            grant_decision_id("a:b", "c", 1),
            grant_decision_id("a", "b:c", 1)
        );
    }

    /// A dataset version reads back whole, in order, a page at a time.
    fn version_pages(db: &RuntimeDb, ns: &str) {
        let dataset_id = format!("{ns}-rows");
        db.create_dataset(&crate::sekai::dataset::Dataset {
            id: dataset_id.clone(),
            name: dataset_id.clone(),
            columns: vec![crate::sekai::dataset::ColumnDef {
                name: "n".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        })
        .unwrap();
        let rows: Vec<HashMap<String, String>> = (0..5)
            .map(|n| HashMap::from([("n".to_string(), n.to_string())]))
            .collect();
        db.append_rows(&dataset_id, &rows).unwrap();
        let version = db.latest_dataset_version_id(&dataset_id).unwrap();
        let mut after = i64::MIN;
        let mut read = Vec::new();
        loop {
            let page = db
                .dataset_version_rows_after(&dataset_id, &version, after, 2)
                .unwrap();
            let Some((last, _)) = page.last() else { break };
            after = *last;
            read.extend(page.into_iter().map(|(_, row)| row["n"].clone()));
        }
        assert_eq!(read, ["0", "1", "2", "3", "4"]);
    }

    /// Definitions store once per id; artifacts fill in order, complete,
    /// and expire.
    fn artifact_contract(db: &RuntimeDb, ns: &str) {
        let (owner, record) = db
            .put_export_definition(ns, "nightly", "alice", "{\"v\":1}")
            .unwrap();
        assert_eq!((owner.as_str(), record.as_str()), ("alice", "{\"v\":1}"));
        assert_eq!(
            db.put_export_definition(ns, "nightly", "bob", "{\"v\":2}")
                .unwrap()
                .1,
            "{\"v\":1}"
        );
        let receipt_id = format!("{ns}-run");
        db.open_export_artifact(&receipt_id, ns, "nightly", 1_000)
            .unwrap();
        for (seq, part) in [b"ab".as_slice(), b"cd".as_slice()].into_iter().enumerate() {
            db.put_export_artifact_chunk(&receipt_id, seq as i64, part)
                .unwrap();
        }
        assert_eq!(
            db.export_artifact_chunks_after(&receipt_id, -1, 1, 2_000)
                .unwrap(),
            vec![(0, b"ab".to_vec())]
        );
        assert_eq!(
            db.export_artifact_chunks_after(&receipt_id, 0, 8, 2_000)
                .unwrap(),
            vec![(1, b"cd".to_vec())]
        );
        assert!(
            db.export_artifact_chunks_after(&receipt_id, 1, 8, 2_000)
                .unwrap()
                .is_empty()
        );
        assert!(
            db.export_artifact_is_deliverable(&receipt_id, 2_000)
                .unwrap()
        );
        let artifact = db.get_export_artifact(&receipt_id, 2_000).unwrap().unwrap();
        assert_eq!(artifact.bytes, b"abcd");
        let listed = db.list_unacked_export_artifacts(ns, 2_000).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].receipt_id, receipt_id);
        let acked = format!("{ns}-acked");
        db.open_export_artifact(&acked, ns, "nightly", 1_000)
            .unwrap();
        db.put_export_artifact_chunk(&acked, 0, b"ef").unwrap();
        assert!(db.acknowledge_export_artifact(&acked, 2_000).unwrap());
        assert!(db.get_export_artifact(&acked, 2_000).unwrap().is_none());
        assert!(!db.export_artifact_is_deliverable(&acked, 2_000).unwrap());
        assert!(
            db.export_artifact_chunks_after(&acked, -1, 8, 2_000)
                .unwrap()
                .is_empty()
        );
        assert!(db.acknowledge_export_artifact(&acked, 2_000).unwrap());
        db.put_export_definition(ns, "hourly", "alice", r#"{"everyMs":1000}"#)
            .unwrap();
        let due = db.claim_due_export_schedules(1_500).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].definition_id, "hourly");
        assert!(db.claim_due_export_schedules(1_500).unwrap().is_empty());
        db.put_export_definition(ns, "also", "alice", r#"{"everyMs":1000}"#)
            .unwrap();
        assert_eq!(db.claim_due_export_schedules(2_000).unwrap().len(), 1);
        assert_eq!(db.claim_due_export_schedules(2_000).unwrap().len(), 1);
        assert!(db.claim_due_export_schedules(2_000).unwrap().is_empty());
        let hourly = r#"{"everyMs":1000}"#;
        assert!(db.delete_export_definition(ns, "hourly", hourly).unwrap());
        db.put_export_definition(ns, "hourly", "alice", hourly)
            .unwrap();
        assert_eq!(db.claim_due_export_schedules(1_500).unwrap().len(), 1);
        // Unreadable once expired, kept until then, and swept after.
        let expired = 1_000 + crate::sekai::data_export_artifact_store::ARTIFACT_RETENTION_MS + 1;
        assert!(
            db.get_export_artifact(&receipt_id, expired)
                .unwrap()
                .is_none()
        );
        db.sweep_export_artifacts(2_000).unwrap();
        assert!(
            db.get_export_artifact(&receipt_id, 2_000)
                .unwrap()
                .is_some()
        );
        db.sweep_export_artifacts(expired).unwrap();
        assert!(
            db.get_export_artifact(&receipt_id, 2_000)
                .unwrap()
                .is_none()
        );
        // Deleted only as the record it is.
        assert!(
            !db.delete_export_definition(ns, "nightly", "{\"v\":2}")
                .unwrap()
        );
        assert!(
            db.delete_export_definition(ns, "nightly", "{\"v\":1}")
                .unwrap()
        );
        assert!(db.get_export_definition(ns, "nightly").unwrap().is_none());
    }

    #[test]
    fn sqlite_export_artifacts_follow_the_contract() {
        artifact_contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    fn sqlite_export_artifact_ack_column_is_added_on_existing_tables() {
        let path = std::env::temp_dir().join(format!(
            "export-ack-upgrade-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sekai_export_artifacts (
                    receipt_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    definition_id TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL
                );
                CREATE TABLE sekai_export_artifact_chunks (
                    receipt_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    data BLOB NOT NULL,
                    PRIMARY KEY (receipt_id, seq)
                );
                INSERT INTO sekai_export_artifacts
                    (receipt_id, namespace, definition_id, created_at_ms, expires_at_ms)
                VALUES ('old-run', 'acme', 'nightly', 1000, 2000000000000);
                INSERT INTO sekai_export_artifact_chunks (receipt_id, seq, data)
                VALUES ('old-run', 0, x'6162');",
            )
            .unwrap();
        }
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            crate::db::sekai::SekaiDb::new_for_plane(
                path.to_str().unwrap(),
                crate::db::schema_plane::SchemaPlane::Sekai,
            )
            .unwrap(),
        ));
        let listed = db.list_unacked_export_artifacts("acme", 2_000).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].receipt_id, "old-run");
        assert!(db.acknowledge_export_artifact("old-run", 2_000).unwrap());
        assert!(db.get_export_artifact("old-run", 2_000).unwrap().is_none());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sqlite_dataset_versions_read_in_pages() {
        version_pages(&RuntimeDb::memory(), "acme");
    }

    #[test]
    fn sqlite_export_grants_follow_the_contract() {
        grant_contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    fn a_sekai_only_plane_holds_grants_and_receipts() {
        let path = std::env::temp_dir().join(format!(
            "export-plane-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            crate::db::sekai::SekaiDb::new_for_plane(
                path.to_str().unwrap(),
                crate::db::schema_plane::SchemaPlane::Sekai,
            )
            .unwrap(),
        ));
        grant_contract(&db, "acme");
        let source = ExportSource {
            namespace: "acme".into(),
            source_kind: "object_set",
            source_id: "Ticket".into(),
            source_version: "sha256:q".into(),
            definition_digest: "sha256:d".into(),
            format: ExportFormat::Csv,
            columns: Vec::new(),
            granted_via: "alice".into(),
            fingerprint_properties: Vec::new(),
            fingerprint_group_size: 0,
        };
        let receipt = ExportReceipt::begin(db.clone(), "alice", &source, now_ms()).unwrap();
        let id = receipt.operation_id().to_string();
        receipt.complete(now_ms()).unwrap();
        assert!(
            export_receipt(&db, &id)
                .unwrap()
                .unwrap()
                .completed_at_ms
                .is_some()
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_export_grants_follow_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        // A namespace of its own, so concurrent or repeated runs never share
        // a record.
        let ns = format!("export-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        grant_contract(&db, &ns);
        // Receipts: one completes; one is abandoned past its lease and swept.
        let source = ExportSource {
            namespace: ns.clone(),
            source_kind: "object_set",
            source_id: "Ticket".into(),
            source_version: "sha256:q".into(),
            definition_digest: "sha256:d".into(),
            format: ExportFormat::JsonLines,
            columns: Vec::new(),
            granted_via: "alice".into(),
            fingerprint_properties: Vec::new(),
            fingerprint_group_size: 0,
        };
        let now = now_ms();
        let done = ExportReceipt::begin(db.clone(), "alice", &source, now).unwrap();
        let done_id = done.operation_id().to_string();
        done.complete(now).unwrap();
        let lost = ExportReceipt::begin(db.clone(), "alice", &source, now).unwrap();
        let lost_id = lost.operation_id().to_string();
        std::mem::forget(lost);
        recover_abandoned_exports(&db, now + EXPORT_LEASE_MS + 1).unwrap();
        let outcome = |id: &str| {
            export_receipt(&db, id)
                .unwrap()
                .unwrap()
                .events
                .last()
                .unwrap()
                .attributes["outcome"]
                .clone()
        };
        assert_eq!(outcome(&done_id), "completed");
        assert_eq!(outcome(&lost_id), "aborted");
        version_pages(&db, &ns);
        artifact_contract(&db, &ns);
    }

    #[test]
    fn an_abandoned_export_is_closed_once_as_aborted_and_fences_its_exporter() {
        let db = RuntimeDb::memory();
        let source = ExportSource {
            namespace: "acme".into(),
            source_kind: "object_set",
            source_id: "Ticket".into(),
            source_version: "sha256:q".into(),
            definition_digest: "sha256:d".into(),
            format: ExportFormat::Csv,
            columns: vec!["title".into()],
            granted_via: "alice".into(),
            fingerprint_properties: Vec::new(),
            fingerprint_group_size: 0,
        };
        let mut lost = ExportReceipt::begin(db.clone(), "alice", &source, 1_000).unwrap();
        let id = lost.operation_id().to_string();
        // The exporter stalls past its lease; another export sweeps it.
        let later = 1_000 + EXPORT_LEASE_MS + 1;
        recover_abandoned_exports(&db, later).unwrap();
        let receipt = export_receipt(&db, &id).unwrap().unwrap();
        assert!(receipt.completed_at_ms.is_some());
        assert_eq!(
            receipt.events.last().unwrap().attributes["outcome"],
            "aborted"
        );
        // A second sweep finds nothing, and the stalled exporter is fenced.
        recover_abandoned_exports(&db, later + 1).unwrap();
        assert_eq!(export_receipt(&db, &id).unwrap().unwrap().events.len(), 2);
        lost.renewed_at_ms = 0;
        assert!(!lost.record(b"late", 1));
        assert!(lost.complete(later + 2).is_err());
        assert_eq!(export_receipt(&db, &id).unwrap().unwrap().events.len(), 2);

        // A crash after the outcome is decided, before the receipt carries
        // it: the next sweep finishes it with that outcome.
        let crashed = ExportReceipt::begin(db.clone(), "alice", &source, later).unwrap();
        let crashed_id = crashed.operation_id().to_string();
        assert!(
            claim_close(
                &db,
                &crashed_id,
                &aborted(7, "export_ended", later + 1),
                false,
                later + 1
            )
            .unwrap()
        );
        std::mem::forget(crashed);
        assert!(
            export_receipt(&db, &crashed_id)
                .unwrap()
                .unwrap()
                .completed_at_ms
                .is_none()
        );
        recover_abandoned_exports(&db, later + 2).unwrap();
        let finished = export_receipt(&db, &crashed_id).unwrap().unwrap();
        assert_eq!(finished.events.last().unwrap().attributes["row_count"], "7");
        assert!(db.recoverable_exports(i64::MAX, 10).unwrap().is_empty());
    }

    #[test]
    fn columns_are_distinct_and_never_the_id() {
        for columns in [vec!["id"], vec!["a", "a"], vec![" "]] {
            let columns = columns.into_iter().map(String::from).collect();
            assert!(RowEncoder::new(ExportFormat::Csv, columns, true).is_err());
        }
    }
}
