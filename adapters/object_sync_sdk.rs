//! Dependency-light helper for out-of-process source-sync adapters.
//!
//! This module deliberately does not reuse the evidence `SubmitEvidence`
//! helper. It builds `sekai.source-batch/v1`, persists the exact normalized
//! batch before delivery, and leaves authentication to the RPC transport.

use fs2::FileExt;
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, MAX_SOURCE_BATCH_RECORDS, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch, SourceRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const OUTBOX_FORMAT_VERSION: &str = "sekai.source-outbox/v1";
pub const DEFAULT_MAX_PENDING_FILES: usize = 256;
pub const DEFAULT_MAX_ENTRY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_QUARANTINE_REASON_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAdapterConfig {
    pub namespace: String,
    pub producer_identity: String,
    /// Canonical GitHub `owner/repository`.
    pub source_instance: String,
    pub type_digest: String,
}

#[derive(Debug, Serialize)]
struct StableBatchIdentity<'a> {
    contract_version: &'static str,
    namespace: &'a str,
    producer_identity: &'a str,
    source: &'static str,
    source_instance: &'a str,
    family: &'static str,
    adapter_id: &'static str,
    adapter_version: &'static str,
    type_digest: &'a str,
    current_cursor: &'a str,
    proposed_next_cursor: &'a str,
    records: &'a [SourceRecord],
}

/// Builds one deterministic, bounded source batch from normalized records.
pub fn build_source_batch(
    config: &SourceAdapterConfig,
    current_cursor: &str,
    proposed_next_cursor: &str,
    collected_at_ms: i64,
    mut records: Vec<SourceRecord>,
) -> Result<SourceBatch, String> {
    if config.type_digest != GITHUB_OBJECT_SYNC_TYPE_DIGEST {
        return Err("source adapter rejected: unbound_type_revision".into());
    }
    if records.len() > MAX_SOURCE_BATCH_RECORDS {
        return Err("source adapter record count exceeds the batch limit".into());
    }
    records.sort_by(|left, right| {
        (
            left.external_id.as_str(),
            left.type_name.as_str(),
            left.source_version.as_str(),
        )
            .cmp(&(
                right.external_id.as_str(),
                right.type_name.as_str(),
                right.source_version.as_str(),
            ))
    });
    let identity = StableBatchIdentity {
        contract_version: SOURCE_BATCH_VERSION,
        namespace: &config.namespace,
        producer_identity: &config.producer_identity,
        source: SOURCE_GITHUB,
        source_instance: &config.source_instance,
        family: FAMILY_OBJECT_SYNC,
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC,
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION,
        type_digest: &config.type_digest,
        current_cursor,
        proposed_next_cursor,
        records: &records,
    };
    let identity_bytes = serde_json::to_vec(&identity)
        .map_err(|_| "source batch identity cannot be serialized".to_string())?;
    let idempotency_key = format!("sync-{:x}", Sha256::digest(identity_bytes));
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: config.namespace.clone(),
        producer_identity: config.producer_identity.clone(),
        source: SOURCE_GITHUB.into(),
        source_instance: config.source_instance.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: config.type_digest.clone(),
        current_cursor: current_cursor.into(),
        proposed_next_cursor: proposed_next_cursor.into(),
        idempotency_key,
        batch_digest: String::new(),
        collected_at_ms,
        records,
    };
    batch.batch_digest = batch
        .canonical_digest()
        .map_err(|error| format!("source batch canonicalization failed: {}", error.code))?;
    batch
        .validate()
        .map_err(|error| format!("source batch rejected: {}", error.code))?;
    Ok(batch)
}

/// Serialize the public source-batch contract without transport metadata.
pub fn serialize_source_batch(batch: &SourceBatch) -> Result<Vec<u8>, String> {
    batch
        .validate()
        .map_err(|error| format!("source batch rejected: {}", error.code))?;
    serde_json::to_vec(batch).map_err(|_| "source batch cannot be serialized".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLimits {
    pub max_pending_files: usize,
    pub max_entry_bytes: usize,
}

impl Default for OutboxLimits {
    fn default() -> Self {
        Self {
            max_pending_files: DEFAULT_MAX_PENDING_FILES,
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceOutbox {
    root: PathBuf,
    limits: OutboxLimits,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBatch {
    format_version: String,
    batch: SourceBatch,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantinedBatch {
    format_version: String,
    reason_code: String,
    batch: SourceBatch,
}

impl SourceOutbox {
    pub fn open(root: impl Into<PathBuf>, limits: OutboxLimits) -> Result<Self, String> {
        if limits.max_pending_files == 0 || limits.max_entry_bytes == 0 {
            return Err("source outbox limits must be positive".into());
        }
        let outbox = Self {
            root: root.into(),
            limits,
        };
        fs::create_dir_all(&outbox.root)
            .map_err(|_| "failed to create source outbox".to_string())?;
        restrict_directory(&outbox.root)?;
        let _lock = outbox.lock_exclusive()?;
        outbox.remove_stale_temps()?;
        outbox.pending()?;
        Ok(outbox)
    }

    /// Persist the exact normalized batch before any transport callback runs.
    pub fn enqueue(&self, batch: &SourceBatch) -> Result<SourceBatch, String> {
        batch
            .validate()
            .map_err(|error| format!("source batch rejected: {}", error.code))?;
        validate_outbox_key(&batch.idempotency_key)?;
        let _lock = self.lock_exclusive()?;
        let path = self.pending_path(&batch.idempotency_key);
        if path.exists() {
            let stored = self.read_pending(&path)?;
            if stored.batch_digest == batch.batch_digest {
                return Ok(stored);
            }
            return Err("source outbox idempotency key is bound to another batch".into());
        }
        for pending in self.pending()? {
            if same_binding(&pending, batch) {
                if pending.batch_digest == batch.batch_digest {
                    return Ok(pending);
                }
                return Err("source outbox binding already has a distinct unresolved batch".into());
            }
        }
        self.ensure_pending_capacity()?;
        let stored = StoredBatch {
            format_version: OUTBOX_FORMAT_VERSION.into(),
            batch: batch.clone(),
        };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| "source outbox entry cannot be serialized".to_string())?;
        self.check_entry_size(bytes.len())?;
        match atomic_write(&self.root, &path, &bytes)? {
            PublishDisposition::Published => Ok(batch.clone()),
            PublishDisposition::Existing => {
                let stored = self.read_pending(&path)?;
                if stored.batch_digest == batch.batch_digest {
                    Ok(stored)
                } else {
                    Err("source outbox idempotency key is bound to another batch".into())
                }
            }
        }
    }

    /// Return pending batches in deterministic idempotency-key order.
    pub fn pending(&self) -> Result<Vec<SourceBatch>, String> {
        self.ensure_pending_bounds()?;
        let mut paths = pending_paths(&self.root)?;
        paths.sort();
        let batches = paths
            .iter()
            .map(|path| self.read_pending(path))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, batch) in batches.iter().enumerate() {
            if batches[..index]
                .iter()
                .any(|existing| same_binding(existing, batch))
            {
                return Err(
                    "source outbox contains multiple unresolved batches for one binding".into(),
                );
            }
        }
        Ok(batches)
    }

    pub fn quarantine_count(&self) -> Result<usize, String> {
        let path = self.root.join("quarantine");
        if !path.exists() {
            return Ok(0);
        }
        Ok(pending_paths(&path)?.len())
    }

    /// Deliver every pending entry in deterministic order.
    ///
    /// Transport failures, ambiguous replies, and mismatched committed replies
    /// retain the entry. Only an exact committed reply removes it.
    pub fn flush<T: SourceSyncTransport>(
        &self,
        transport: &mut T,
        quarantine_rejections: bool,
    ) -> Result<FlushReport, String> {
        let _lock = self.lock_exclusive()?;
        let mut report = FlushReport::default();
        for batch in self.pending()? {
            report.entries.push(self.flush_batch_locked(
                &batch,
                transport,
                quarantine_rejections,
            )?);
        }
        Ok(report)
    }

    /// Deliver one exact pending entry without touching other source bindings.
    pub fn flush_idempotency_key<T: SourceSyncTransport>(
        &self,
        idempotency_key: &str,
        transport: &mut T,
        quarantine_rejections: bool,
    ) -> Result<FlushEntry, String> {
        validate_outbox_key(idempotency_key)?;
        let _lock = self.lock_exclusive()?;
        let path = self.pending_path(idempotency_key);
        if !path.exists() {
            return Err("source outbox entry does not exist".into());
        }
        let batch = self.read_pending(&path)?;
        self.flush_batch_locked(&batch, transport, quarantine_rejections)
    }

    fn flush_batch_locked<T: SourceSyncTransport>(
        &self,
        batch: &SourceBatch,
        transport: &mut T,
        quarantine_rejections: bool,
    ) -> Result<FlushEntry, String> {
        let idempotency_key = batch.idempotency_key.clone();
        let disposition = match transport.apply_source_batch(batch) {
            Ok(ApplySourceBatchReply::Committed {
                idempotency_key,
                batch_digest,
                committed_cursor,
            }) if idempotency_key == batch.idempotency_key
                && batch_digest == batch.batch_digest
                && committed_cursor == batch.proposed_next_cursor =>
            {
                self.remove_pending(&batch.idempotency_key)?;
                FlushDisposition::Committed
            }
            Ok(ApplySourceBatchReply::Rejected { reason_code }) if quarantine_rejections => {
                self.quarantine(batch, normalize_reason_code(&reason_code))?;
                FlushDisposition::Quarantined
            }
            Ok(ApplySourceBatchReply::Rejected { .. })
            | Ok(ApplySourceBatchReply::Committed { .. })
            | Err(_) => FlushDisposition::Pending,
        };
        Ok(FlushEntry {
            idempotency_key,
            disposition,
        })
    }

    fn lock_exclusive(&self) -> Result<OutboxLock, String> {
        let path = self.root.join(".source-outbox.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        let file = match options.create_new(true).open(&path) {
            Ok(file) => {
                sync_directory(&self.root)?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let expected = fs::symlink_metadata(&path)
                    .map_err(|_| "failed to inspect source outbox lock".to_string())?;
                if !expected.file_type().is_file() {
                    return Err("source outbox lock is not a regular file".into());
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| "failed to open source outbox lock".to_string())?;
                let actual = file
                    .metadata()
                    .map_err(|_| "failed to inspect opened source outbox lock".to_string())?;
                if !actual.is_file() {
                    return Err("source outbox lock is not a regular file".into());
                }
                #[cfg(unix)]
                if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                    return Err("source outbox lock changed while opening".into());
                }
                file
            }
            Err(_) => return Err("failed to create source outbox lock".into()),
        };
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "failed to protect source outbox lock".to_string())?;
        FileExt::lock_exclusive(&file)
            .map_err(|_| "failed to acquire source outbox lock".to_string())?;
        Ok(OutboxLock(file))
    }

    fn pending_path(&self, idempotency_key: &str) -> PathBuf {
        self.root.join(format!("{idempotency_key}.json"))
    }

    fn read_pending(&self, path: &Path) -> Result<SourceBatch, String> {
        let bytes = read_bounded_regular_file(path, self.limits.max_entry_bytes)?;
        let stored: StoredBatch = serde_json::from_slice(&bytes)
            .map_err(|_| "source outbox entry is corrupt".to_string())?;
        if stored.format_version != OUTBOX_FORMAT_VERSION {
            return Err("source outbox entry version is unsupported".into());
        }
        stored
            .batch
            .validate()
            .map_err(|_| "source outbox entry contains an invalid batch".to_string())?;
        validate_outbox_key(&stored.batch.idempotency_key)?;
        if path.file_name().and_then(|name| name.to_str())
            != Some(&format!("{}.json", stored.batch.idempotency_key))
        {
            return Err("source outbox entry filename does not match its identity".into());
        }
        Ok(stored.batch)
    }

    fn remove_pending(&self, idempotency_key: &str) -> Result<(), String> {
        fs::remove_file(self.pending_path(idempotency_key))
            .map_err(|_| "failed to remove committed source outbox entry".to_string())?;
        sync_directory(&self.root)
    }

    fn quarantine(&self, batch: &SourceBatch, reason_code: &str) -> Result<(), String> {
        let directory = self.root.join("quarantine");
        fs::create_dir_all(&directory)
            .map_err(|_| "failed to create source outbox quarantine".to_string())?;
        restrict_directory(&directory)?;
        if pending_paths(&directory)?.len() >= self.limits.max_pending_files {
            return Err("source outbox quarantine reached its file limit".into());
        }
        let quarantined = QuarantinedBatch {
            format_version: OUTBOX_FORMAT_VERSION.into(),
            reason_code: reason_code.into(),
            batch: batch.clone(),
        };
        let bytes = serde_json::to_vec(&quarantined)
            .map_err(|_| "source quarantine entry cannot be serialized".to_string())?;
        self.check_entry_size(bytes.len())?;
        let destination = directory.join(format!("{}.json", batch.idempotency_key));
        if atomic_write(&directory, &destination, &bytes)? == PublishDisposition::Existing {
            let existing = read_bounded_regular_file(&destination, self.limits.max_entry_bytes)?;
            if existing != bytes {
                return Err("source quarantine identity is bound to another entry".into());
            }
        }
        self.remove_pending(&batch.idempotency_key)
    }

    fn remove_stale_temps(&self) -> Result<(), String> {
        let mut removed = false;
        for entry in
            fs::read_dir(&self.root).map_err(|_| "failed to inspect source outbox".to_string())?
        {
            let entry = entry.map_err(|_| "failed to inspect source outbox".to_string())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') && name.ends_with(".tmp") {
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| "failed to inspect source outbox temporary file".to_string())?;
                if !metadata.file_type().is_file() {
                    return Err("source outbox temporary entry is not a regular file".into());
                }
                fs::remove_file(entry.path())
                    .map_err(|_| "failed to remove source outbox temporary file".to_string())?;
                removed = true;
            }
        }
        if removed {
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    fn ensure_pending_capacity(&self) -> Result<(), String> {
        if pending_paths(&self.root)?.len() >= self.limits.max_pending_files {
            Err("source outbox reached its pending file limit".into())
        } else {
            Ok(())
        }
    }

    fn ensure_pending_bounds(&self) -> Result<(), String> {
        if pending_paths(&self.root)?.len() > self.limits.max_pending_files {
            Err("source outbox exceeds its pending file limit".into())
        } else {
            Ok(())
        }
    }

    fn check_entry_size(&self, bytes: usize) -> Result<(), String> {
        if bytes > self.limits.max_entry_bytes {
            Err("source outbox entry exceeds its byte limit".into())
        } else {
            Ok(())
        }
    }
}

struct OutboxLock(File);

impl Drop for OutboxLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn same_binding(left: &SourceBatch, right: &SourceBatch) -> bool {
    left.namespace == right.namespace
        && left.source_instance == right.source_instance
        && left.type_digest == right.type_digest
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplySourceBatchReply {
    Committed {
        idempotency_key: String,
        batch_digest: String,
        committed_cursor: String,
    },
    /// A bounded code such as `invalid_record`; never a remote response body.
    Rejected { reason_code: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    Unavailable,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSourceSyncStateInput {
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSyncStateView {
    pub found: bool,
    pub current_cursor: Option<String>,
    pub open_transaction: bool,
    pub last_committed_batch_digest: Option<String>,
}

/// RPC seam implemented by an out-of-process client.
///
/// Implementations map these calls to `ApplySourceBatch` and
/// `GetSourceSyncState`. They own credentials in memory; this SDK never accepts
/// or persists bearer metadata.
pub trait SourceSyncTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure>;

    fn get_source_sync_state(
        &mut self,
        input: &GetSourceSyncStateInput,
    ) -> Result<SourceSyncStateView, TransportFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushDisposition {
    Committed,
    Pending,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushEntry {
    pub idempotency_key: String,
    pub disposition: FlushDisposition,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub entries: Vec<FlushEntry>,
}

fn validate_outbox_key(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sync-") else {
        return Err("source outbox idempotency key is not SDK-generated".into());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source outbox idempotency key is not SDK-generated".into());
    }
    Ok(())
}

fn normalize_reason_code(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= MAX_QUARANTINE_REASON_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        value
    } else {
        "remote_rejected"
    }
}

fn pending_paths(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|_| "failed to inspect source outbox".to_string())?
    {
        let entry = entry.map_err(|_| "failed to inspect source outbox".to_string())?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| "failed to inspect source outbox entry".to_string())?;
            if !metadata.file_type().is_file() {
                return Err("source outbox entry is not a regular file".into());
            }
            paths.push(path);
        }
    }
    Ok(paths)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishDisposition {
    Published,
    Existing,
}

fn atomic_write(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<PublishDisposition, String> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "source outbox destination is invalid".to_string())?;
    let temporary = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|_| "failed to create source outbox temporary file".to_string())?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temporary);
        return Err("failed to persist source outbox temporary file".into());
    }
    match fs::hard_link(&temporary, destination) {
        Ok(()) => {
            sync_directory(directory)?;
            fs::remove_file(&temporary)
                .map_err(|_| "failed to finalize source outbox entry".to_string())?;
            sync_directory(directory)?;
            Ok(PublishDisposition::Published)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            sync_directory(directory)?;
            Ok(PublishDisposition::Existing)
        }
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            Err("failed to atomically publish source outbox entry".into())
        }
    }
}

fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let expected = fs::symlink_metadata(path)
        .map_err(|_| "failed to inspect source outbox entry".to_string())?;
    if !expected.file_type().is_file() || expected.len() as usize > max_bytes {
        return Err("source outbox entry is not a bounded regular file".into());
    }
    let mut file =
        File::open(path).map_err(|_| "failed to open source outbox entry".to_string())?;
    let actual = file
        .metadata()
        .map_err(|_| "failed to inspect opened source outbox entry".to_string())?;
    if !actual.is_file() || actual.len() as usize > max_bytes {
        return Err("source outbox entry is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err("source outbox entry changed while opening".into());
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "failed to protect source outbox entry".to_string())?;
    }
    let mut bytes = Vec::with_capacity(actual.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| "failed to read source outbox entry".to_string())?;
    if bytes.len() > max_bytes {
        return Err("source outbox entry exceeds its byte limit".into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    let expected = fs::symlink_metadata(path)
        .map_err(|_| "failed to inspect source outbox directory".to_string())?;
    if !expected.file_type().is_dir() {
        return Err("source outbox path is not a real directory".into());
    }
    let directory =
        File::open(path).map_err(|_| "failed to open source outbox directory".to_string())?;
    let actual = directory
        .metadata()
        .map_err(|_| "failed to inspect opened source outbox directory".to_string())?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err("source outbox directory changed while opening".into());
    }
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|_| "failed to protect source outbox directory".to_string())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "failed to sync source outbox directory".to_string())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}
