//! Bounded inbound object sync from one system of record.
//!
//! Adapters collect records and propose a next opaque cursor. The control plane
//! validates and commits the complete batch before it advances its checkpoint.
//! This is not a pipeline product.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const SOURCE_BATCH_VERSION: &str = "sekai.source-batch/v1";
pub const SOURCE_TYPE_REVISION_VERSION: &str = "sekai.source-type-revision/v1";
pub const SOURCE_GITHUB: &str = "github";
pub const FAMILY_OBJECT_SYNC: &str = "source_control.object_sync";
pub const ADAPTER_GITHUB_OBJECT_SYNC: &str = "adapter.github.object_sync";
pub const ADAPTER_GITHUB_OBJECT_SYNC_VERSION: &str = "1.0.0";
pub const GITHUB_OBJECT_SYNC_TYPE_DIGEST: &str =
    "sha256:97a329c80d00af0525c6076aef9f8162471eee9c108cefae42f68a8309fb708a";
pub const GITHUB_OBJECT_SYNC_RECORD_TYPES: &[&str] = &["Issue", "PullRequest"];

/// The only source type revision admitted by the v1 object-sync contract.
///
/// The digest is SHA-256 over the newline-delimited contract version, family,
/// source, and ordered record types, including the final newline.
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
        let canonical = CanonicalSourceBatch {
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
        };
        let bytes = serde_json::to_vec(&canonical).map_err(|error| {
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
        if self.contract_version != SOURCE_BATCH_VERSION {
            return Err(SourceBatchValidationError::new(
                "unsupported_version",
                "source batch contract version is not supported",
            ));
        }
        require_bounded_identifier("namespace", &self.namespace)?;
        require_bounded_identifier("producer_identity", &self.producer_identity)?;
        require_bounded_identifier("source_instance", &self.source_instance)?;
        require_bounded_identifier("idempotency_key", &self.idempotency_key)?;
        if self.source != SOURCE_GITHUB {
            return Err(SourceBatchValidationError::new(
                "foreign_source",
                "source must be github",
            ));
        }
        validate_github_repository(&self.source_instance)?;
        if self.family != FAMILY_OBJECT_SYNC {
            return Err(SourceBatchValidationError::new(
                "foreign_family",
                "family must be source_control.object_sync",
            ));
        }
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
                return Err(SourceBatchValidationError::new(
                    "ambiguous_record_identity",
                    format!(
                        "records[{index}] repeats a GitHub number already present in the batch"
                    ),
                ));
            }
        }

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCheckpoint {
    pub binding_id: String,
    pub namespace: String,
    pub cursor: String,
    pub committed_batch_digest: String,
    pub advanced_at_ms: i64,
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
    pub updated_at_ms: i64,
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

fn validate_record(
    record: &SourceRecord,
    index: usize,
    batch: &SourceBatch,
) -> Result<(), SourceBatchValidationError> {
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
    validate_github_number(&record.external_id)?;
    require_bounded_identifier(
        &format!("records[{index}].source_version"),
        &record.source_version,
    )?;
    if !matches!(record.type_name.as_str(), "Issue" | "PullRequest") {
        return Err(SourceBatchValidationError::new(
            "unsupported_record_type",
            format!("records[{index}] must be an Issue or PullRequest"),
        ));
    }
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

fn contains_secret_like_text(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
    const PAYLOAD_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn issue() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            source_version: "issue-node-v7".into(),
            type_name: "Issue".into(),
            display_name: "Broken deploy".into(),
            payload_digest: PAYLOAD_DIGEST.into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Broken deploy".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
        }
    }

    fn valid_batch() -> SourceBatch {
        let mut batch = SourceBatch {
            contract_version: SOURCE_BATCH_VERSION.into(),
            namespace: "acme".into(),
            producer_identity: "connector/github-primary".into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: TYPE_DIGEST.into(),
            current_cursor: "cursor:41".into(),
            proposed_next_cursor: "cursor:42".into(),
            idempotency_key: "batch-42".into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![issue()],
        };
        batch.batch_digest = batch.canonical_digest().unwrap();
        batch
    }

    #[test]
    fn valid_source_batch_is_admitted() {
        let batch = valid_batch();
        batch
            .validate_for_producer("connector/github-primary")
            .unwrap();
        assert_eq!(
            batch.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success
        );
        assert_eq!(
            batch
                .validate_for_producer("connector/foreign")
                .unwrap_err()
                .code,
            "producer_identity_mismatch"
        );
        assert_eq!(
            batch.server_validation_outcome("connector/foreign"),
            OperationOutcome::Denial
        );
    }

    #[test]
    fn github_type_revision_descriptor_and_digest_are_fixed() {
        let material = "sekai.source-type-revision/v1\nsource_control.object_sync\ngithub\nIssue\nPullRequest\n";
        assert_eq!(
            GITHUB_OBJECT_SYNC_TYPE_REVISION,
            SourceTypeRevisionDescriptor {
                contract_version: SOURCE_TYPE_REVISION_VERSION,
                family: FAMILY_OBJECT_SYNC,
                source: SOURCE_GITHUB,
                record_types: &["Issue", "PullRequest"],
                digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST,
            }
        );
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(material)),
            GITHUB_OBJECT_SYNC_TYPE_DIGEST
        );
    }

    #[test]
    fn unbound_type_revision_fails_closed() {
        let mut batch = valid_batch();
        batch.type_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        batch.batch_digest = batch.canonical_digest().unwrap();
        assert_eq!(batch.validate().unwrap_err().code, "unbound_type_revision");
    }

    #[test]
    fn canonical_digest_is_stable_across_collection_time() {
        let first = valid_batch();
        let mut second = first.clone();
        second.collected_at_ms += 9_000;
        assert_eq!(
            first.canonical_digest().unwrap(),
            second.canonical_digest().unwrap()
        );
        assert!(second.validate().is_ok());
    }

    #[test]
    fn unknown_contract_version_fails_closed() {
        let mut batch = valid_batch();
        batch.contract_version = "sekai.source-batch/v2".into();
        batch.batch_digest = batch.canonical_digest().unwrap();
        let error = batch.validate().unwrap_err();
        assert_eq!(error.code, "unsupported_version");
    }

    #[test]
    fn foreign_contract_values_and_malformed_digests_fail_closed() {
        let mut family = valid_batch();
        family.family = "source_control.other".into();
        family.batch_digest = family.canonical_digest().unwrap();
        assert_eq!(family.validate().unwrap_err().code, "foreign_family");

        let mut adapter = valid_batch();
        adapter.adapter_version = "2.0.0".into();
        adapter.batch_digest = adapter.canonical_digest().unwrap();
        assert_eq!(adapter.validate().unwrap_err().code, "unsupported_adapter");

        let mut digest = valid_batch();
        digest.records[0].payload_digest = "sha256:abc".into();
        digest.batch_digest = digest.canonical_digest().unwrap();
        assert_eq!(digest.validate().unwrap_err().code, "invalid_digest");
    }

    #[test]
    fn mixed_and_unsupported_records_fail_closed() {
        let mut mixed = valid_batch();
        mixed.records[0].source_instance = "other/repository".into();
        mixed.batch_digest = mixed.canonical_digest().unwrap();
        assert_eq!(mixed.validate().unwrap_err().code, "mixed_source_identity");

        let mut unsupported = valid_batch();
        unsupported.records[0].type_name = "Discussion".into();
        unsupported.batch_digest = unsupported.canonical_digest().unwrap();
        assert_eq!(
            unsupported.validate().unwrap_err().code,
            "unsupported_record_type"
        );

        let mut ambiguous = valid_batch();
        let mut pull = issue();
        pull.type_name = "PullRequest".into();
        ambiguous.records.push(pull);
        ambiguous.batch_digest = ambiguous.canonical_digest().unwrap();
        assert_eq!(
            ambiguous.validate().unwrap_err().code,
            "ambiguous_record_identity"
        );
    }

    #[test]
    fn github_repository_and_number_identity_are_canonical() {
        for source_instance in ["not-a-repository", "Owner/repository"] {
            let mut repository = valid_batch();
            repository.source_instance = source_instance.into();
            repository.records[0].source_instance = repository.source_instance.clone();
            repository.batch_digest = repository.canonical_digest().unwrap();
            assert_eq!(
                repository.validate().unwrap_err().code,
                "invalid_source_instance"
            );
        }

        for external_id in ["0", "01", "not-a-number"] {
            let mut number = valid_batch();
            number.records[0].external_id = external_id.into();
            number.batch_digest = number.canonical_digest().unwrap();
            assert_eq!(number.validate().unwrap_err().code, "invalid_external_id");
            assert!(matches!(
                sync_github_record(number.records.remove(0), GITHUB_OBJECT_SYNC_TYPE_DIGEST),
                SyncDecision::Reject { .. }
            ));
        }
    }

    #[test]
    fn record_property_and_cursor_bounds_fail_closed() {
        let mut too_many = valid_batch();
        too_many.records = (0..=MAX_SOURCE_BATCH_RECORDS)
            .map(|index| {
                let mut record = issue();
                record.external_id = index.to_string();
                record
            })
            .collect();
        too_many.batch_digest = too_many.canonical_digest().unwrap();
        assert_eq!(too_many.validate().unwrap_err().code, "record_bounds");

        let mut properties = valid_batch();
        properties.records[0].properties = (0..=MAX_SOURCE_RECORD_PROPERTIES)
            .map(|index| (format!("property_{index}"), "value".into()))
            .collect();
        properties.batch_digest = properties.canonical_digest().unwrap();
        assert_eq!(properties.validate().unwrap_err().code, "property_bounds");

        let mut cursor = valid_batch();
        cursor.proposed_next_cursor = "x".repeat(MAX_SOURCE_CURSOR_BYTES + 1);
        cursor.batch_digest = cursor.canonical_digest().unwrap();
        assert_eq!(cursor.validate().unwrap_err().code, "cursor_bounds");
    }

    #[test]
    fn secret_like_text_is_rejected() {
        let mut property = valid_batch();
        property.records[0]
            .properties
            .insert("access_token".into(), "redacted".into());
        property.batch_digest = property.canonical_digest().unwrap();
        assert_eq!(property.validate().unwrap_err().code, "secret_like_text");

        let mut cursor = valid_batch();
        cursor.proposed_next_cursor = "ghp_not-a-checkpoint".into();
        cursor.batch_digest = cursor.canonical_digest().unwrap();
        assert_eq!(cursor.validate().unwrap_err().code, "secret_like_text");
    }

    #[test]
    fn replay_material_requires_exact_canonical_input() {
        let first = valid_batch();
        let material = first.replay_material().unwrap();

        let mut replay = first.clone();
        replay.collected_at_ms += 1;
        assert_eq!(
            replay.compare_replay(&material).unwrap(),
            ReplayDisposition::ExactReplay
        );
        assert_eq!(replay.replay_material().unwrap(), material);

        let mut conflict = first;
        conflict.proposed_next_cursor = "cursor:43".into();
        conflict.batch_digest = conflict.canonical_digest().unwrap();
        assert_eq!(
            conflict.compare_replay(&material).unwrap_err().code,
            "idempotency_conflict"
        );
    }

    #[test]
    fn server_validation_never_emits_partial_or_unknown() {
        let valid = valid_batch();
        assert!(matches!(
            valid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success | OperationOutcome::Denial
        ));

        let mut invalid = valid;
        invalid.batch_digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            invalid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success | OperationOutcome::Denial
        ));
        assert_eq!(
            invalid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Denial
        );
    }

    #[test]
    fn github_issue_upserts_stable_object_id() {
        let first = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let second = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        assert_eq!(first.object_id, second.object_id);
        assert_eq!(first.source_id, "github:acme/ops#12");
        assert_eq!(first.source_version, "issue-node-v7");
        assert_eq!(first.properties["state"], "open");
        assert!(!first.tombstoned);
    }

    #[test]
    fn deleted_github_record_tombstones() {
        let mut record = issue();
        record.deleted = true;
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Tombstone(object) => assert!(object.tombstoned),
            other => panic!("expected tombstone, got {other:?}"),
        }
    }

    #[test]
    fn foreign_source_is_rejected() {
        let mut record = issue();
        record.source = "jira".into();
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => assert!(reason.contains("GitHub")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn issue_and_pull_request_share_github_number_identity() {
        let issue_object = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let mut pull = issue();
        pull.type_name = "PullRequest".into();
        let pull_object = match sync_github_record(pull, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        assert_eq!(issue_object.object_id, pull_object.object_id);
        assert_eq!(issue_object.source_id, pull_object.source_id);
        assert_eq!(issue_object.source_id, "github:acme/ops#12");
    }

    #[test]
    fn additional_github_kinds_are_rejected() {
        let mut record = issue();
        record.type_name = "Discussion".into();
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("Issue and PullRequest only"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn type_revision_change_is_a_conflict() {
        let upserted = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("{other:?}"),
        };
        let mut moved = upserted.clone();
        moved.type_digest = "unbound-revision".into();
        moved.object_id = object_id_for(&moved.type_digest, &moved.source_id);
        assert!(detect_identity_conflict(&upserted, &moved).is_some());
    }
}
