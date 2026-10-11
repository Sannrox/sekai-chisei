//! Source-batch contract types and validation shared by adapters and the plane.
//!
//! This module is the semver surface for `sekai.source-batch/v1` and `v2`.
//! Control-plane apply logic stays in `sekai_chisei::sekai::object_sync`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const SOURCE_BATCH_VERSION: &str = "sekai.source-batch/v1";
pub const SOURCE_BATCH_V2_VERSION: &str = "sekai.source-batch/v2";
pub const SOURCE_TYPE_REVISION_VERSION: &str = "sekai.source-type-revision/v1";
pub const SOURCE_GITHUB: &str = "github";
pub const FAMILY_OBJECT_SYNC: &str = "source_control.object_sync";
pub const ADAPTER_GITHUB_OBJECT_SYNC: &str = "adapter.github.object_sync";
pub const ADAPTER_GITHUB_OBJECT_SYNC_VERSION: &str = "1.0.0";
pub const ADAPTER_REGISTERED_OBJECT_SYNC: &str = "adapter.registered.object_sync";
pub const ADAPTER_REGISTERED_OBJECT_SYNC_VERSION: &str = "1.0.0";
pub const GITHUB_OBJECT_SYNC_TYPE_DIGEST: &str =
    "sha256:97a329c80d00af0525c6076aef9f8162471eee9c108cefae42f68a8309fb708a";
pub const GITHUB_OBJECT_SYNC_RECORD_TYPES: &[&str] = &["Issue", "PullRequest"];

/// The code-owned GitHub Issue/PullRequest type revision.
///
/// The digest is SHA-256 over the newline-delimited contract version, family,
/// source, and ordered record types, including the final newline. Live
/// registered descriptors use a separate digest and identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTypeRevisionDescriptor {
    pub contract_version: &'static str,
    pub family: &'static str,
    pub source: &'static str,
    pub record_types: &'static [&'static str],
    pub digest: &'static str,
}

pub const GITHUB_OBJECT_SYNC_TYPE_REVISION: SourceTypeRevisionDescriptor =
    SourceTypeRevisionDescriptor {
        contract_version: SOURCE_TYPE_REVISION_VERSION,
        family: FAMILY_OBJECT_SYNC,
        source: SOURCE_GITHUB,
        record_types: GITHUB_OBJECT_SYNC_RECORD_TYPES,
        digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST,
    };

pub const MAX_SOURCE_BATCH_RECORDS: usize = 500;
pub const MAX_SOURCE_RECORD_PROPERTIES: usize = 64;
pub const MAX_SOURCE_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_SOURCE_IDENTIFIER_BYTES: usize = 512;
pub const MAX_SOURCE_DISPLAY_NAME_BYTES: usize = 1024;
pub const MAX_SOURCE_PROPERTY_KEY_BYTES: usize = 128;
pub const MAX_SOURCE_PROPERTY_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_SOURCE_FEED_EPOCH_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDeliveryMode {
    Snapshot,
    ChangeFeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceSyncGenerationStatus {
    Snapshotting,
    Active,
    RecoveryRequired,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSyncGeneration {
    pub binding_id: String,
    pub sync_generation: u64,
    pub status: SourceSyncGenerationStatus,
    pub delivery_mode: SourceDeliveryMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_feed_epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_offset: Option<u64>,
    pub reason: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Replay-relevant delivery metadata for the v2 source-batch contract.
///
/// Change-feed offsets describe the half-open-to-closed range
/// `(offset_start, offset_end]`. A completed snapshot uses only `offset_end`
/// for its source-provided change-feed handoff barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeliveryWindow {
    pub mode: SourceDeliveryMode,
    pub sync_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_feed_epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_end: Option<u64>,
    pub snapshot_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub source: String,
    pub source_instance: String,
    pub external_id: String,
    /// Immutable source-owned revision, ETag, node revision, or equivalent.
    #[serde(default)]
    pub source_version: String,
    pub type_name: String,
    pub display_name: String,
    pub payload_digest: String,
    /// Stable, adapter-normalized scalar properties used by object projection.
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    pub deleted: bool,
    pub observed_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
}

impl SourceRecord {
    pub fn source_id(&self) -> String {
        source_id(&self.source, &self.source_instance, &self.external_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatch {
    pub contract_version: String,
    pub namespace: String,
    /// Producer identity authenticated by the transport and rebound server-side.
    pub producer_identity: String,
    pub source: String,
    pub source_instance: String,
    pub family: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub type_digest: String,
    /// Empty only when no checkpoint has been committed for this binding.
    pub current_cursor: String,
    /// Adapter proposal. Only the plane may make it the durable checkpoint.
    pub proposed_next_cursor: String,
    pub idempotency_key: String,
    pub batch_digest: String,
    pub collected_at_ms: i64,
    pub records: Vec<SourceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<SourceDeliveryWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CanonicalSourceBatch<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    producer_identity: &'a str,
    source: &'a str,
    source_instance: &'a str,
    family: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    type_digest: &'a str,
    current_cursor: &'a str,
    proposed_next_cursor: &'a str,
    idempotency_key: &'a str,
    records: &'a [SourceRecord],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CanonicalSourceBatchV2<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    producer_identity: &'a str,
    source: &'a str,
    source_instance: &'a str,
    family: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    type_digest: &'a str,
    current_cursor: &'a str,
    proposed_next_cursor: &'a str,
    idempotency_key: &'a str,
    delivery: &'a SourceDeliveryWindow,
    records: &'a [SourceRecord],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatchReplayMaterial {
    pub namespace: String,
    pub producer_identity: String,
    pub idempotency_key: String,
    pub batch_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDisposition {
    NewBatch,
    ExactReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatchValidationError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SourceBatchValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SourceBatchValidationError {}

impl SourceBatchValidationError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl SourceBatch {
    /// Digest of all replay-relevant input. Collection time and the digest
    /// field itself are deliberately excluded.
    pub fn canonical_digest(&self) -> Result<String, SourceBatchValidationError> {
        let bytes = match self.contract_version.as_str() {
            SOURCE_BATCH_VERSION => {
                if self.delivery.is_some()
                    || self
                        .records
                        .iter()
                        .any(|record| record.source_sequence.is_some())
                {
                    return Err(SourceBatchValidationError::new(
                        "unexpected_delivery_metadata",
                        "v1 source batches cannot contain delivery metadata or source sequences",
                    ));
                }
                serde_json::to_vec(&CanonicalSourceBatch {
                    contract_version: &self.contract_version,
                    namespace: &self.namespace,
                    producer_identity: &self.producer_identity,
                    source: &self.source,
                    source_instance: &self.source_instance,
                    family: &self.family,
                    adapter_id: &self.adapter_id,
                    adapter_version: &self.adapter_version,
                    type_digest: &self.type_digest,
                    current_cursor: &self.current_cursor,
                    proposed_next_cursor: &self.proposed_next_cursor,
                    idempotency_key: &self.idempotency_key,
                    records: &self.records,
                })
            }
            SOURCE_BATCH_V2_VERSION => {
                let delivery = self.delivery.as_ref().ok_or_else(|| {
                    SourceBatchValidationError::new(
                        "missing_delivery_metadata",
                        "v2 source batches require a delivery envelope",
                    )
                })?;
                serde_json::to_vec(&CanonicalSourceBatchV2 {
                    contract_version: &self.contract_version,
                    namespace: &self.namespace,
                    producer_identity: &self.producer_identity,
                    source: &self.source,
                    source_instance: &self.source_instance,
                    family: &self.family,
                    adapter_id: &self.adapter_id,
                    adapter_version: &self.adapter_version,
                    type_digest: &self.type_digest,
                    current_cursor: &self.current_cursor,
                    proposed_next_cursor: &self.proposed_next_cursor,
                    idempotency_key: &self.idempotency_key,
                    delivery,
                    records: &self.records,
                })
            }
            _ => {
                return Err(SourceBatchValidationError::new(
                    "unsupported_version",
                    "source batch contract version is not supported",
                ));
            }
        }
        .map_err(|error| {
            SourceBatchValidationError::new(
                "canonicalization_failed",
                format!("source batch cannot be canonicalized: {error}"),
            )
        })?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    pub fn replay_material(&self) -> Result<SourceBatchReplayMaterial, SourceBatchValidationError> {
        self.validate()?;
        Ok(SourceBatchReplayMaterial {
            namespace: self.namespace.clone(),
            producer_identity: self.producer_identity.clone(),
            idempotency_key: self.idempotency_key.clone(),
            batch_digest: self.batch_digest.clone(),
        })
    }

    pub fn compare_replay(
        &self,
        existing: &SourceBatchReplayMaterial,
    ) -> Result<ReplayDisposition, SourceBatchValidationError> {
        let incoming = self.replay_material()?;
        if incoming.namespace == existing.namespace
            && incoming.producer_identity == existing.producer_identity
            && incoming.idempotency_key == existing.idempotency_key
        {
            if incoming.batch_digest == existing.batch_digest {
                return Ok(ReplayDisposition::ExactReplay);
            }
            return Err(SourceBatchValidationError::new(
                "idempotency_conflict",
                "idempotency key is already bound to different canonical batch input",
            ));
        }
        Ok(ReplayDisposition::NewBatch)
    }

    pub fn validate(&self) -> Result<(), SourceBatchValidationError> {
        validate_delivery_envelope(self)?;
        require_bounded_identifier("namespace", &self.namespace)?;
        require_bounded_identifier("producer_identity", &self.producer_identity)?;
        require_bounded_identifier("source_instance", &self.source_instance)?;
        require_bounded_identifier("idempotency_key", &self.idempotency_key)?;
        if self.family != FAMILY_OBJECT_SYNC {
            return Err(SourceBatchValidationError::new(
                "foreign_family",
                "family must be source_control.object_sync",
            ));
        }
        if self.source == SOURCE_GITHUB || self.type_digest == GITHUB_OBJECT_SYNC_TYPE_DIGEST {
            if self.source != SOURCE_GITHUB {
                return Err(SourceBatchValidationError::new(
                    "foreign_source",
                    "source must be github",
                ));
            }
            validate_github_repository(&self.source_instance)?;
            if self.adapter_id != ADAPTER_GITHUB_OBJECT_SYNC
                || self.adapter_version != ADAPTER_GITHUB_OBJECT_SYNC_VERSION
            {
                return Err(SourceBatchValidationError::new(
                    "unsupported_adapter",
                    "adapter must be adapter.github.object_sync at version 1.0.0",
                ));
            }
            if self.type_digest != GITHUB_OBJECT_SYNC_TYPE_DIGEST {
                return Err(SourceBatchValidationError::new(
                    "unbound_type_revision",
                    "type_digest is not bound to the code-owned GitHub object-sync revision",
                ));
            }
        } else {
            validate_registered_batch_envelope(self)?;
        }
        require_cursor("current_cursor", &self.current_cursor, true)?;
        require_cursor("proposed_next_cursor", &self.proposed_next_cursor, false)?;
        if self.collected_at_ms <= 0 {
            return Err(SourceBatchValidationError::new(
                "invalid_timestamp",
                "collected_at_ms must be positive",
            ));
        }
        if self.records.is_empty() || self.records.len() > MAX_SOURCE_BATCH_RECORDS {
            return Err(SourceBatchValidationError::new(
                "record_bounds",
                format!("records must contain between 1 and {MAX_SOURCE_BATCH_RECORDS} entries"),
            ));
        }

        let mut source_ids = HashSet::with_capacity(self.records.len());
        for (index, record) in self.records.iter().enumerate() {
            validate_record(record, index, self)?;
            if !source_ids.insert(record.external_id.as_str()) {
                let repeated = if self.type_digest == GITHUB_OBJECT_SYNC_TYPE_DIGEST {
                    "a GitHub number"
                } else {
                    "an identity"
                };
                return Err(SourceBatchValidationError::new(
                    "ambiguous_record_identity",
                    format!("records[{index}] repeats {repeated} already present in the batch"),
                ));
            }
        }
        validate_ordered_delivery(self)?;

        require_digest("batch_digest", &self.batch_digest)?;
        if self.batch_digest != self.canonical_digest()? {
            return Err(SourceBatchValidationError::new(
                "batch_digest_mismatch",
                "batch_digest does not match the canonical source batch",
            ));
        }
        Ok(())
    }

    pub fn validate_for_producer(
        &self,
        authenticated_producer: &str,
    ) -> Result<(), SourceBatchValidationError> {
        require_bounded_identifier("authenticated_producer", authenticated_producer)?;
        if self.producer_identity != authenticated_producer {
            return Err(SourceBatchValidationError::new(
                "producer_identity_mismatch",
                "source batch producer does not match the authenticated producer",
            ));
        }
        self.validate()
    }

    /// Server validation has only authoritative success or denial outcomes.
    /// Partial is reserved for post-validation execution; unknown is reserved
    /// for externally observed ambiguous progress.
    pub fn server_validation_outcome(&self, authenticated_producer: &str) -> OperationOutcome {
        match self.validate_for_producer(authenticated_producer) {
            Ok(()) => OperationOutcome::Success,
            Err(_) => OperationOutcome::Denial,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceBatchStatus {
    Open,
    Committed,
    Aborted,
    Quarantined,
}

impl SourceBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Committed => "COMMITTED",
            Self::Aborted => "ABORTED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Success,
    Denial,
    Unavailable,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub binding_id: String,
    pub namespace: String,
    pub producer_identity: String,
    pub source: String,
    pub source_instance: String,
    pub family: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub type_digest: String,
    pub created_at_ms: i64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatchTransaction {
    pub transaction_id: String,
    pub binding_id: String,
    pub namespace: String,
    pub producer_identity: String,
    pub idempotency_key: String,
    pub batch_digest: String,
    pub current_cursor: String,
    pub proposed_next_cursor: String,
    pub status: SourceBatchStatus,
    pub outcome: OperationOutcome,
    pub opened_at_ms: i64,
    pub closed_at_ms: Option<i64>,
    pub reason: String,
    #[serde(default = "default_source_batch_version")]
    pub contract_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_mode: Option<SourceDeliveryMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_feed_epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_end: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCheckpoint {
    pub binding_id: String,
    pub namespace: String,
    pub cursor: String,
    pub committed_batch_digest: String,
    pub advanced_at_ms: i64,
    #[serde(default = "default_source_batch_version")]
    pub contract_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_mode: Option<SourceDeliveryMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_feed_epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecordResult {
    pub transaction_id: String,
    pub source_id: String,
    pub source_version: String,
    pub decision: SyncDecision,
    pub outcome: OperationOutcome,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatchResult {
    pub transaction: SourceBatchTransaction,
    pub records: Vec<SourceRecordResult>,
    /// True only when the plane committed proposed_next_cursor.
    pub checkpoint_advanced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSyncState {
    pub binding: SourceBinding,
    pub checkpoint: Option<SourceCheckpoint>,
    pub open_transaction: Option<SourceBatchTransaction>,
    pub last_result: Option<SourceBatchResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_generation: Option<SourceSyncGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_transaction: Option<SourceBatchTransaction>,
    pub updated_at_ms: i64,
}

fn default_source_batch_version() -> String {
    SOURCE_BATCH_VERSION.into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncedObject {
    pub object_id: String,
    pub type_name: String,
    pub source_id: String,
    #[serde(default)]
    pub source_version: String,
    pub payload_digest: String,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    pub tombstoned: bool,
    pub type_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDecision {
    Upsert(SyncedObject),
    Tombstone(SyncedObject),
    Conflict { source_id: String, reason: String },
    Reject { reason: String },
}

pub fn source_id(source: &str, instance: &str, external_id: &str) -> String {
    format!("{source}:{instance}#{external_id}")
}

pub fn object_id_for(type_digest: &str, source_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(type_digest.as_bytes());
    hasher.update(b"\n");
    hasher.update(source_id.as_bytes());
    format!("sync-{:x}", hasher.finalize())
}

/// Map one GitHub issue or pull-request observation onto a sync decision.
///
/// Transport (webhook, document, or poll) is out of scope. Callers feed one
/// `SourceRecord`. GitHub Issues and pull requests share a number space, so
/// `source_id` omits `type_name`. Other GitHub kinds and other hosts stay
/// rejected until a later identity decision.
pub fn sync_github_record(record: SourceRecord, type_digest: &str) -> SyncDecision {
    if record.source != SOURCE_GITHUB {
        return SyncDecision::Reject {
            reason: "source is not the GitHub dogfood system of record".into(),
        };
    }
    if type_digest != GITHUB_OBJECT_SYNC_TYPE_DIGEST {
        return SyncDecision::Reject {
            reason: "type revision is not bound to the GitHub object-sync profile".into(),
        };
    }
    if validate_github_repository(&record.source_instance).is_err()
        || validate_github_number(&record.external_id).is_err()
    {
        return SyncDecision::Reject {
            reason: "GitHub source instance or external id is invalid".into(),
        };
    }
    if record.type_name != "Issue" && record.type_name != "PullRequest" {
        return SyncDecision::Reject {
            reason: "GitHub sync admits Issue and PullRequest only".into(),
        };
    }
    let source = record.source_id();
    let object = SyncedObject {
        object_id: object_id_for(type_digest, &source),
        type_name: record.type_name,
        source_id: source,
        source_version: record.source_version,
        payload_digest: record.payload_digest,
        properties: record.properties,
        tombstoned: record.deleted,
        type_digest: type_digest.to_string(),
    };
    if record.deleted {
        SyncDecision::Tombstone(object)
    } else {
        SyncDecision::Upsert(object)
    }
}

/// Detect a conflicting refresh when the same source identity would change
/// object id for a type revision.
pub fn detect_identity_conflict(
    existing: &SyncedObject,
    incoming: &SyncedObject,
) -> Option<String> {
    if existing.source_id != incoming.source_id {
        return None;
    }
    if existing.type_digest != incoming.type_digest {
        return Some("source identity moved across type revisions".into());
    }
    if existing.object_id != incoming.object_id {
        return Some("source identity mapped to a different object id".into());
    }
    None
}

/// Schema-drift denials are retained as quarantine evidence. Cursor, authority,
/// and ambiguous lifecycle denials still fail closed before a stored result.
pub fn is_schema_drift_denial(code: Option<&str>) -> bool {
    matches!(
        code,
        Some("type_identity_conflict")
            | Some("source_revision_conflict")
            | Some("binding_type_conflict")
    )
}

fn validate_delivery_envelope(batch: &SourceBatch) -> Result<(), SourceBatchValidationError> {
    match batch.contract_version.as_str() {
        SOURCE_BATCH_VERSION => {
            if batch.delivery.is_some()
                || batch
                    .records
                    .iter()
                    .any(|record| record.source_sequence.is_some())
            {
                return Err(SourceBatchValidationError::new(
                    "unexpected_delivery_metadata",
                    "v1 source batches cannot contain delivery metadata or source sequences",
                ));
            }
            Ok(())
        }
        SOURCE_BATCH_V2_VERSION => {
            let delivery = batch.delivery.as_ref().ok_or_else(|| {
                SourceBatchValidationError::new(
                    "missing_delivery_metadata",
                    "v2 source batches require a delivery envelope",
                )
            })?;
            if delivery.sync_generation == 0 {
                return Err(SourceBatchValidationError::new(
                    "invalid_sync_generation",
                    "delivery sync_generation must be positive",
                ));
            }
            require_db_u64("delivery.sync_generation", delivery.sync_generation)?;
            if let Some(epoch) = &delivery.source_feed_epoch {
                validate_source_feed_epoch(epoch)?;
            }
            for (label, value) in [
                ("delivery.offset_start", delivery.offset_start),
                ("delivery.offset_end", delivery.offset_end),
            ] {
                if let Some(value) = value {
                    require_db_u64(label, value)?;
                }
            }
            match delivery.mode {
                SourceDeliveryMode::Snapshot => {
                    if delivery.offset_start.is_some()
                        || (delivery.snapshot_complete && delivery.offset_end.is_none())
                        || (!delivery.snapshot_complete && delivery.offset_end.is_some())
                    {
                        return Err(SourceBatchValidationError::new(
                            "invalid_snapshot_metadata",
                            "snapshot delivery offsets do not match completion state",
                        ));
                    }
                    if delivery.snapshot_complete && delivery.source_feed_epoch.is_none() {
                        return Err(SourceBatchValidationError::new(
                            "missing_feed_epoch",
                            "completed snapshot delivery requires a source feed epoch",
                        ));
                    }
                }
                SourceDeliveryMode::ChangeFeed => {
                    if delivery.source_feed_epoch.is_none() {
                        return Err(SourceBatchValidationError::new(
                            "missing_feed_epoch",
                            "change-feed delivery requires a source feed epoch",
                        ));
                    }
                    if delivery.snapshot_complete {
                        return Err(SourceBatchValidationError::new(
                            "invalid_change_feed_metadata",
                            "change-feed delivery cannot complete a snapshot",
                        ));
                    }
                    let (Some(offset_start), Some(offset_end)) =
                        (delivery.offset_start, delivery.offset_end)
                    else {
                        return Err(SourceBatchValidationError::new(
                            "missing_delivery_range",
                            "change-feed delivery requires both range offsets",
                        ));
                    };
                    if offset_end <= offset_start {
                        return Err(SourceBatchValidationError::new(
                            "invalid_delivery_range",
                            "change-feed offset_end must be greater than offset_start",
                        ));
                    }
                }
            }
            Ok(())
        }
        _ => Err(SourceBatchValidationError::new(
            "unsupported_version",
            "source batch contract version is not supported",
        )),
    }
}

fn validate_ordered_delivery(batch: &SourceBatch) -> Result<(), SourceBatchValidationError> {
    if batch.contract_version == SOURCE_BATCH_VERSION {
        return Ok(());
    }
    let delivery = batch.delivery.as_ref().ok_or_else(|| {
        SourceBatchValidationError::new(
            "missing_delivery_metadata",
            "v2 source batches require a delivery envelope",
        )
    })?;
    match delivery.mode {
        SourceDeliveryMode::Snapshot => {
            if batch
                .records
                .iter()
                .any(|record| record.source_sequence.is_some())
            {
                return Err(SourceBatchValidationError::new(
                    "unexpected_source_sequence",
                    "snapshot records cannot contain source_sequence",
                ));
            }
        }
        SourceDeliveryMode::ChangeFeed => {
            let (Some(offset_start), Some(offset_end)) =
                (delivery.offset_start, delivery.offset_end)
            else {
                return Err(SourceBatchValidationError::new(
                    "missing_delivery_range",
                    "change-feed delivery requires both range offsets",
                ));
            };
            let sequences = batch
                .records
                .iter()
                .map(|record| {
                    record.source_sequence.ok_or_else(|| {
                        SourceBatchValidationError::new(
                            "missing_source_sequence",
                            "every change-feed record requires source_sequence",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mut seen = HashSet::with_capacity(sequences.len());
            for sequence in &sequences {
                if !seen.insert(*sequence) {
                    return Err(SourceBatchValidationError::new(
                        "duplicate_source_sequence",
                        "change-feed source_sequence values must be unique",
                    ));
                }
            }
            if sequences.windows(2).any(|pair| pair[0] > pair[1]) {
                return Err(SourceBatchValidationError::new(
                    "reordered_source_sequence",
                    "change-feed source_sequence values must be strictly increasing",
                ));
            }

            // This is contract-shape validation, not a stateful gap signal.
            // Stateful gaps are batches whose offset_start is ahead of the
            // plane-owned committed offset; persistence durably aborts those
            // after OPEN and marks the generation RECOVERY_REQUIRED.
            let expected_len = offset_end.checked_sub(offset_start).ok_or_else(|| {
                SourceBatchValidationError::new(
                    "invalid_delivery_range",
                    "change-feed delivery range is invalid",
                )
            })?;
            if expected_len != sequences.len() as u64
                || sequences.iter().enumerate().any(|(index, sequence)| {
                    offset_start
                        .checked_add(index as u64 + 1)
                        .is_none_or(|expected| expected != *sequence)
                })
            {
                return Err(SourceBatchValidationError::new(
                    "noncontiguous_source_sequence",
                    "change-feed source_sequence values must exactly cover the delivery range",
                ));
            }
        }
    }
    Ok(())
}

fn validate_source_feed_epoch(value: &str) -> Result<(), SourceBatchValidationError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_FEED_EPOCH_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SourceBatchValidationError::new(
            "invalid_feed_epoch",
            format!(
                "source feed epoch must be canonical and at most {MAX_SOURCE_FEED_EPOCH_BYTES} bytes"
            ),
        ));
    }
    if contains_secret_like_text(value) {
        return Err(SourceBatchValidationError::new(
            "secret_like_text",
            "source feed epoch contains credential-like text",
        ));
    }
    Ok(())
}

fn validate_record(
    record: &SourceRecord,
    index: usize,
    batch: &SourceBatch,
) -> Result<(), SourceBatchValidationError> {
    if let Some(source_sequence) = record.source_sequence {
        require_db_u64(
            &format!("records[{index}].source_sequence"),
            source_sequence,
        )?;
    }
    if record.source != batch.source || record.source_instance != batch.source_instance {
        return Err(SourceBatchValidationError::new(
            "mixed_source_identity",
            format!("records[{index}] does not match the batch source identity"),
        ));
    }
    require_bounded_identifier(
        &format!("records[{index}].external_id"),
        &record.external_id,
    )?;
    if batch.type_digest == GITHUB_OBJECT_SYNC_TYPE_DIGEST {
        validate_github_number(&record.external_id)?;
        if !matches!(record.type_name.as_str(), "Issue" | "PullRequest") {
            return Err(SourceBatchValidationError::new(
                "unsupported_record_type",
                format!("records[{index}] must be an Issue or PullRequest"),
            ));
        }
    } else {
        require_registered_record_token(
            &format!("records[{index}].external_id"),
            &record.external_id,
            false,
        )?;
        require_registered_record_token(
            &format!("records[{index}].type_name"),
            &record.type_name,
            false,
        )?;
        if record.type_name == "Issue" || record.type_name == "PullRequest" {
            return Err(SourceBatchValidationError::new(
                "unsupported_record_type",
                format!("records[{index}] cannot reuse GitHub Issue or PullRequest"),
            ));
        }
        if let Some(expected) = batch.records.first()
            && record.type_name != expected.type_name
        {
            return Err(SourceBatchValidationError::new(
                "mixed_record_type",
                format!("records[{index}] does not match the registered record kind"),
            ));
        }
    }
    require_bounded_identifier(
        &format!("records[{index}].source_version"),
        &record.source_version,
    )?;
    require_bounded_text(
        &format!("records[{index}].display_name"),
        &record.display_name,
        MAX_SOURCE_DISPLAY_NAME_BYTES,
        false,
    )?;
    require_digest(
        &format!("records[{index}].payload_digest"),
        &record.payload_digest,
    )?;
    if record.observed_at_ms <= 0 {
        return Err(SourceBatchValidationError::new(
            "invalid_timestamp",
            format!("records[{index}].observed_at_ms must be positive"),
        ));
    }
    if record.properties.len() > MAX_SOURCE_RECORD_PROPERTIES {
        return Err(SourceBatchValidationError::new(
            "property_bounds",
            format!("records[{index}].properties exceeds {MAX_SOURCE_RECORD_PROPERTIES} entries"),
        ));
    }
    for (key, value) in &record.properties {
        if key.is_empty()
            || key.len() > MAX_SOURCE_PROPERTY_KEY_BYTES
            || key.trim() != key
            || key.chars().any(|character| {
                !(character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '_' | '-' | '.'))
            })
        {
            return Err(SourceBatchValidationError::new(
                "invalid_property_key",
                format!("records[{index}].properties contains a non-normalized key"),
            ));
        }
        if is_secret_key(key) {
            return Err(SourceBatchValidationError::new(
                "secret_like_text",
                format!("records[{index}].properties contains a credential-like key"),
            ));
        }
        require_bounded_text(
            &format!("records[{index}].properties[{key}]"),
            value,
            MAX_SOURCE_PROPERTY_VALUE_BYTES,
            true,
        )?;
    }
    Ok(())
}

fn require_db_u64(label: &str, value: u64) -> Result<(), SourceBatchValidationError> {
    if value > i64::MAX as u64 {
        return Err(SourceBatchValidationError::new(
            "delivery_position_out_of_range",
            format!("{label} exceeds the supported delivery position range"),
        ));
    }
    Ok(())
}

fn validate_registered_batch_envelope(
    batch: &SourceBatch,
) -> Result<(), SourceBatchValidationError> {
    require_digest("type_digest", &batch.type_digest)?;
    if batch.source == SOURCE_GITHUB {
        return Err(SourceBatchValidationError::new(
            "foreign_source",
            "registered source batches cannot reuse github",
        ));
    }
    require_registered_record_token("source", &batch.source, false)?;
    require_registered_record_token("source_instance", &batch.source_instance, true)?;
    if batch.adapter_id != ADAPTER_REGISTERED_OBJECT_SYNC
        || batch.adapter_version != ADAPTER_REGISTERED_OBJECT_SYNC_VERSION
    {
        return Err(SourceBatchValidationError::new(
            "unsupported_adapter",
            "adapter must be adapter.registered.object_sync at version 1.0.0",
        ));
    }
    Ok(())
}

fn require_registered_record_token(
    label: &str,
    value: &str,
    allow_slash: bool,
) -> Result<(), SourceBatchValidationError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('#')
        || value.contains(':')
        || (value.contains('/') && !allow_slash)
    {
        return Err(SourceBatchValidationError::new(
            "invalid_source_instance",
            format!("{label} is not a canonical registered token"),
        ));
    }
    Ok(())
}

fn validate_github_repository(value: &str) -> Result<(), SourceBatchValidationError> {
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !valid_github_repository_part(owner)
        || !valid_github_repository_part(repository)
    {
        return Err(SourceBatchValidationError::new(
            "invalid_source_instance",
            "GitHub source_instance must be canonical owner/repository",
        ));
    }
    Ok(())
}

fn valid_github_repository_part(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn validate_github_number(value: &str) -> Result<(), SourceBatchValidationError> {
    let number = value.parse::<u64>().map_err(|_| {
        SourceBatchValidationError::new(
            "invalid_external_id",
            "GitHub external_id must be a canonical positive number",
        )
    })?;
    if number == 0 || number.to_string() != value {
        return Err(SourceBatchValidationError::new(
            "invalid_external_id",
            "GitHub external_id must be a canonical positive number",
        ));
    }
    Ok(())
}

fn require_bounded_identifier(label: &str, value: &str) -> Result<(), SourceBatchValidationError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SourceBatchValidationError::new(
            "invalid_identifier",
            format!(
                "{label} must be nonempty, canonical, and at most {MAX_SOURCE_IDENTIFIER_BYTES} bytes"
            ),
        ));
    }
    if contains_secret_like_text(value) {
        return Err(SourceBatchValidationError::new(
            "secret_like_text",
            format!("{label} contains credential-like text"),
        ));
    }
    Ok(())
}

fn require_cursor(
    label: &str,
    value: &str,
    allow_empty: bool,
) -> Result<(), SourceBatchValidationError> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAX_SOURCE_CURSOR_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(SourceBatchValidationError::new(
            "cursor_bounds",
            format!("{label} is not a bounded opaque cursor"),
        ));
    }
    if contains_secret_like_text(value) {
        return Err(SourceBatchValidationError::new(
            "secret_like_text",
            format!("{label} contains credential-like text"),
        ));
    }
    Ok(())
}

fn require_bounded_text(
    label: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), SourceBatchValidationError> {
    if (!allow_empty && value.trim().is_empty())
        || value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(SourceBatchValidationError::new(
            "text_bounds",
            format!("{label} is not bounded normalized text"),
        ));
    }
    if contains_secret_like_text(value) {
        return Err(SourceBatchValidationError::new(
            "secret_like_text",
            format!("{label} contains credential-like text"),
        ));
    }
    Ok(())
}

fn require_digest(label: &str, value: &str) -> Result<(), SourceBatchValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SourceBatchValidationError::new(
            "invalid_digest",
            format!("{label} must use sha256:<64 lowercase hex>"),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceBatchValidationError::new(
            "invalid_digest",
            format!("{label} must use sha256:<64 lowercase hex>"),
        ));
    }
    Ok(())
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.replace('-', "_");
    normalized
        .split(['.', '_'])
        .any(|part| matches!(part, "secret" | "password" | "token" | "credential"))
        || normalized.contains("api_key")
        || normalized.contains("private_key")
        || normalized.contains("authorization")
}

pub fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin private key-----")
        || lower.contains("-----begin rsa private key-----")
        || lower.contains("authorization: bearer ")
        || lower.contains("x-api-key:")
        || lower.contains("api_key=")
        || lower.contains("api-key=")
        || lower.contains("access_token=")
        || lower.contains("client_secret=")
        || lower.contains("password=")
        || lower.contains("private_key=")
        || lower.contains("github_pat_")
        || lower.contains("ghp_")
        || lower.contains("gho_")
        || lower.contains("ghs_")
        || lower.contains("ghu_")
        || (value.starts_with("AKIA")
            && value.len() >= 20
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}
