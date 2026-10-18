//! Signed per-namespace hash chain for Action, transform-run, and agent-turn
//! receipts.
//!
//! The rusqlite/PostgreSQL host that inserts chained rows stays in the plane.
//! Hash, signature, checkpoint, and offline verify live here so an isolated
//! runner can emit the same `transform_run` body (ADR 0097 / ADR 0102) and an
//! auditor can verify an exported bundle without store access.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BUNDLE_VERSION: &str = "sekai.receipt-chain/v1";
pub const DIGEST_ALGORITHM: &str = "sha-256";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const GENESIS_HEAD_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const CHECKPOINT_INTERVAL: i64 = 32;
const ENTRY_DOMAIN: &[u8] = b"SEKAI-RECEIPT-CHAIN-ENTRY-V1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"SEKAI-RECEIPT-CHAIN-CHECKPOINT-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Action,
    TransformRun,
    AgentTurn,
}

impl ReceiptKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::TransformRun => "transform_run",
            Self::AgentTurn => "agent_turn",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "action" => Ok(Self::Action),
            "transform_run" => Ok(Self::TransformRun),
            "agent_turn" => Ok(Self::AgentTurn),
            other => Err(format!("unknown receipt kind {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    Genesis,
    Periodic,
    Latest,
}

impl CheckpointKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Periodic => "periodic",
            Self::Latest => "latest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    pub seq: i64,
    pub namespace: String,
    pub kind: ReceiptKind,
    pub receipt_id: String,
    pub receipt_json: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub key_id: String,
    pub signature: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub namespace: String,
    pub kind: CheckpointKind,
    pub head_seq: i64,
    pub head_hash: String,
    pub entry_count: i64,
    pub key_id: String,
    pub signature: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKey {
    pub key_id: String,
    pub public_key_hex: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChainBundle {
    pub bundle_version: String,
    pub namespace: String,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub keys: Vec<PublishedKey>,
    pub checkpoints: Vec<Checkpoint>,
    pub entries: Vec<ChainEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub position: usize,
    pub seq: i64,
    pub message: String,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "position {} (seq {}): {}",
            self.position, self.seq, self.message
        )
    }
}

impl std::error::Error for VerifyError {}

#[derive(Clone)]
pub struct SigningKeySet {
    current: SigningKey,
    verifying: BTreeMap<String, VerifyingKey>,
    published: BTreeMap<String, PublishedKey>,
}

impl SigningKeySet {
    pub fn from_seed_hex(seed_hex: &str, created_at_ms: i64) -> Result<Self, String> {
        let current = signing_key_from_hex(seed_hex)?;
        let mut set = Self {
            current,
            verifying: BTreeMap::new(),
            published: BTreeMap::new(),
        };
        set.record_current(created_at_ms);
        Ok(set)
    }

    /// Trust a historical public key so a latest checkpoint signed before
    /// rotation still authenticates after the active seed changes.
    pub fn trust_public_key(
        &mut self,
        public_key_hex: &str,
        created_at_ms: i64,
    ) -> Result<String, String> {
        let bytes = decode_hex32(
            public_key_hex,
            "trusted public key must be a 32-byte hexadecimal Ed25519 key",
        )?;
        let verifying = VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())?;
        let id = key_id(&bytes);
        self.verifying.insert(id.clone(), verifying);
        self.published.entry(id.clone()).or_insert(PublishedKey {
            key_id: id.clone(),
            public_key_hex: to_hex(&bytes),
            created_at_ms,
            retired_at_ms: Some(created_at_ms),
        });
        Ok(id)
    }

    pub fn rotate(&mut self, seed_hex: &str, created_at_ms: i64) -> Result<String, String> {
        let previous_id = key_id(self.current.verifying_key().as_bytes());
        if let Some(published) = self.published.get_mut(&previous_id) {
            published.retired_at_ms = Some(created_at_ms);
        }
        self.current = signing_key_from_hex(seed_hex)?;
        let next_id = self.record_current(created_at_ms);
        Ok(next_id)
    }

    pub fn current_key_id(&self) -> String {
        key_id(self.current.verifying_key().as_bytes())
    }

    pub fn current_public_key_hex(&self) -> String {
        to_hex(self.current.verifying_key().as_bytes())
    }

    pub fn published_keys(&self) -> Vec<PublishedKey> {
        self.published.values().cloned().collect()
    }

    pub fn verifying_key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.verifying.get(key_id)
    }

    pub fn sign_entry(&self, entry_hash: &str) -> String {
        self.sign_entry_hash(entry_hash)
    }

    pub fn issued_checkpoint(
        &self,
        namespace: &str,
        kind: CheckpointKind,
        head_seq: i64,
        head_hash: &str,
        entry_count: i64,
        created_at_ms: i64,
    ) -> Result<Checkpoint, String> {
        let mut checkpoint = Checkpoint {
            namespace: namespace.to_string(),
            kind,
            head_seq,
            head_hash: head_hash.to_string(),
            entry_count,
            key_id: self.current_key_id(),
            signature: String::new(),
            created_at_ms,
        };
        checkpoint.signature = self.sign_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    fn record_current(&mut self, created_at_ms: i64) -> String {
        let public = *self.current.verifying_key().as_bytes();
        let id = key_id(&public);
        self.verifying
            .insert(id.clone(), self.current.verifying_key());
        self.published.insert(
            id.clone(),
            PublishedKey {
                key_id: id.clone(),
                public_key_hex: to_hex(&public),
                created_at_ms,
                retired_at_ms: None,
            },
        );
        id
    }

    fn sign_entry_hash(&self, entry_hash: &str) -> String {
        to_hex(
            &self
                .current
                .sign(&entry_signed_bytes(entry_hash))
                .to_bytes(),
        )
    }

    fn sign_checkpoint(&self, checkpoint: &Checkpoint) -> Result<String, String> {
        Ok(to_hex(
            &self
                .current
                .sign(&checkpoint_signed_bytes(checkpoint)?)
                .to_bytes(),
        ))
    }
}

/// In-memory chain used by the offline library and by tests of the contract.
pub struct ReceiptChain {
    namespace: String,
    keys: SigningKeySet,
    entries: Vec<ChainEntry>,
    checkpoints: Vec<Checkpoint>,
}

impl ReceiptChain {
    pub fn genesis(
        namespace: impl Into<String>,
        keys: SigningKeySet,
        created_at_ms: i64,
    ) -> Result<Self, String> {
        let namespace = namespace.into();
        if namespace.is_empty() {
            return Err("receipt chain namespace must be non-empty".into());
        }
        let mut chain = Self {
            namespace,
            keys,
            entries: Vec::new(),
            checkpoints: Vec::new(),
        };
        let genesis = chain.sign_checkpoint(
            CheckpointKind::Genesis,
            0,
            GENESIS_HEAD_HASH,
            0,
            created_at_ms,
        )?;
        chain.checkpoints.push(genesis);
        chain.upsert_latest(created_at_ms)?;
        Ok(chain)
    }

    pub fn append(
        &mut self,
        kind: ReceiptKind,
        receipt_id: impl Into<String>,
        receipt_json: impl Into<String>,
        created_at_ms: i64,
    ) -> Result<&ChainEntry, String> {
        let receipt_id = receipt_id.into();
        let receipt_json = receipt_json.into();
        if receipt_id.is_empty() {
            return Err("receipt_id must be non-empty".into());
        }
        if receipt_json.is_empty() {
            return Err("receipt_json must be non-empty".into());
        }
        let seq = i64::try_from(self.entries.len())
            .map_err(|_| "receipt chain seq overflow".to_string())?
            + 1;
        let prev_hash = self
            .entries
            .last()
            .map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HEAD_HASH.to_string());
        let entry_hash = entry_hash(
            seq,
            &prev_hash,
            &self.namespace,
            kind,
            &receipt_id,
            &receipt_json,
            created_at_ms,
        );
        let key_id = self.keys.current_key_id();
        let signature = self.keys.sign_entry_hash(&entry_hash);
        self.entries.push(ChainEntry {
            seq,
            namespace: self.namespace.clone(),
            kind,
            receipt_id,
            receipt_json,
            prev_hash,
            entry_hash: entry_hash.clone(),
            key_id,
            signature,
            created_at_ms,
        });
        self.upsert_latest(created_at_ms)?;
        if seq % CHECKPOINT_INTERVAL == 0 {
            let periodic = self.sign_checkpoint(
                CheckpointKind::Periodic,
                seq,
                &entry_hash,
                seq,
                created_at_ms,
            )?;
            self.checkpoints.push(periodic);
        }
        self.entries
            .last()
            .ok_or_else(|| "receipt chain append lost the new entry".to_string())
    }

    pub fn rotate(&mut self, seed_hex: &str, created_at_ms: i64) -> Result<String, String> {
        self.keys.rotate(seed_hex, created_at_ms)
    }

    pub fn bundle(&self) -> ReceiptChainBundle {
        ReceiptChainBundle {
            bundle_version: BUNDLE_VERSION.into(),
            namespace: self.namespace.clone(),
            digest_algorithm: DIGEST_ALGORITHM.into(),
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
            keys: self.keys.published_keys(),
            checkpoints: self.checkpoints.clone(),
            entries: self.entries.clone(),
        }
    }

    fn upsert_latest(&mut self, created_at_ms: i64) -> Result<(), String> {
        let (head_seq, head_hash, count) = match self.entries.last() {
            Some(entry) => (entry.seq, entry.entry_hash.as_str(), entry.seq),
            None => (0, GENESIS_HEAD_HASH, 0),
        };
        let latest = self.sign_checkpoint(
            CheckpointKind::Latest,
            head_seq,
            head_hash,
            count,
            created_at_ms,
        )?;
        self.checkpoints
            .retain(|checkpoint| checkpoint.kind != CheckpointKind::Latest);
        self.checkpoints.push(latest);
        Ok(())
    }

    fn sign_checkpoint(
        &self,
        kind: CheckpointKind,
        head_seq: i64,
        head_hash: &str,
        entry_count: i64,
        created_at_ms: i64,
    ) -> Result<Checkpoint, String> {
        let mut checkpoint = Checkpoint {
            namespace: self.namespace.clone(),
            kind,
            head_seq,
            head_hash: head_hash.to_string(),
            entry_count,
            key_id: self.keys.current_key_id(),
            signature: String::new(),
            created_at_ms,
        };
        checkpoint.signature = self.keys.sign_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }
}

/// Canonical content hash of a chained receipt. `receipt_json` is hashed as the
/// exact stored string so a parsed representation cannot verify garbage.
/// `created_at_ms` is authenticated so exported timestamps cannot be rewritten.
pub fn entry_hash(
    seq: i64,
    prev_hash: &str,
    namespace: &str,
    kind: ReceiptKind,
    receipt_id: &str,
    receipt_json: &str,
    created_at_ms: i64,
) -> String {
    let canonical = serde_json::to_vec(&(
        seq,
        prev_hash,
        namespace,
        kind.as_str(),
        receipt_id,
        receipt_json,
        created_at_ms,
    ))
    .unwrap_or_default();
    format!("sha256:{}", to_hex(&Sha256::digest(canonical)))
}

pub fn signing_key_from_hex(value: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&decode_hex32(
        value,
        "receipt-chain signing key must be a 32-byte hexadecimal Ed25519 seed",
    )?))
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{}", to_hex(&Sha256::digest(public_key)))
}

/// Classify opaque receipt JSON. Transform-run bodies match the ADR 0097
/// field set (including isolated-process receipts). Operation receipts with a
/// `model_called` event are agent turns; other operation receipts are actions.
pub fn classify_receipt_json(receipt_json: &str) -> Result<ReceiptKind, String> {
    let value: serde_json::Value =
        serde_json::from_str(receipt_json).map_err(|error| error.to_string())?;
    if value.get("run_id").is_some()
        && value.get("transform_id").is_some()
        && value.get("definition_digest").is_some()
    {
        return Ok(ReceiptKind::TransformRun);
    }
    let events = value
        .get("events")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if events.iter().any(|event| {
        event
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind == "model_called")
    }) {
        return Ok(ReceiptKind::AgentTurn);
    }
    if value.get("operation_id").is_some() {
        return Ok(ReceiptKind::Action);
    }
    Err("receipt JSON is not an operation receipt or transform run".into())
}

/// Verify a bundle against independently trusted public keys or key-id
/// fingerprints (`sha256:` + hex). Keys published in the bundle are not a
/// trust anchor; a store writer can replace them together with the chain.
pub fn verify_bundle(
    bundle: &ReceiptChainBundle,
    trusted_keys: &[&str],
) -> Result<(), VerifyError> {
    if bundle.bundle_version != BUNDLE_VERSION {
        return Err(VerifyError {
            position: 0,
            seq: 0,
            message: format!("unsupported bundle version {}", bundle.bundle_version),
        });
    }
    if bundle.namespace.is_empty() {
        return Err(VerifyError {
            position: 0,
            seq: 0,
            message: "bundle namespace must be non-empty".into(),
        });
    }
    let trusted_ids = trusted_key_ids(trusted_keys).map_err(|message| VerifyError {
        position: 0,
        seq: 0,
        message,
    })?;
    let keys = verifying_keys(&bundle.keys).map_err(|message| VerifyError {
        position: 0,
        seq: 0,
        message,
    })?;
    let keys: BTreeMap<String, VerifyingKey> = keys
        .into_iter()
        .filter(|(id, _)| trusted_ids.contains(id))
        .collect();
    if keys.is_empty() {
        return Err(VerifyError {
            position: 0,
            seq: 0,
            message: "bundle signing keys are not in the trusted set".into(),
        });
    }
    let genesis = bundle
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.kind == CheckpointKind::Genesis)
        .ok_or_else(|| VerifyError {
            position: 0,
            seq: 0,
            message: "missing genesis checkpoint".into(),
        })?;
    verify_checkpoint(genesis, &keys, &bundle.namespace, 0)?;
    if genesis.head_seq != 0 || genesis.entry_count != 0 || genesis.head_hash != GENESIS_HEAD_HASH {
        return Err(VerifyError {
            position: 0,
            seq: 0,
            message: "genesis checkpoint does not describe an empty prefix".into(),
        });
    }

    let mut prev_hash = GENESIS_HEAD_HASH.to_string();
    for (index, entry) in bundle.entries.iter().enumerate() {
        let seq = i64::try_from(index).unwrap_or(i64::MAX) + 1;
        if entry.namespace != bundle.namespace {
            return Err(entry_error(
                index,
                entry.seq,
                "entry namespace does not match the bundle",
            ));
        }
        if entry.seq != seq {
            return Err(entry_error(index, entry.seq, format!("expected seq {seq}")));
        }
        if entry.prev_hash != prev_hash {
            return Err(entry_error(
                index,
                entry.seq,
                "prev_hash does not match the previous entry",
            ));
        }
        let expected = entry_hash(
            entry.seq,
            &entry.prev_hash,
            &entry.namespace,
            entry.kind,
            &entry.receipt_id,
            &entry.receipt_json,
            entry.created_at_ms,
        );
        if entry.entry_hash != expected {
            return Err(entry_error(index, entry.seq, "entry_hash mismatch"));
        }
        verify_entry_signature(entry, &keys)
            .map_err(|message| entry_error(index, entry.seq, message))?;
        prev_hash = entry.entry_hash.clone();
    }

    let latest = bundle
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.kind == CheckpointKind::Latest)
        .ok_or_else(|| VerifyError {
            position: bundle.entries.len().saturating_sub(1),
            seq: bundle.entries.last().map(|entry| entry.seq).unwrap_or(0),
            message: "missing latest checkpoint".into(),
        })?;
    let (head_seq, head_hash, count) = match bundle.entries.last() {
        Some(entry) => (entry.seq, entry.entry_hash.as_str(), entry.seq),
        None => (0, GENESIS_HEAD_HASH, 0),
    };
    verify_checkpoint(
        latest,
        &keys,
        &bundle.namespace,
        bundle.entries.len().saturating_sub(1),
    )?;
    if latest.head_seq != head_seq || latest.head_hash != head_hash || latest.entry_count != count {
        return Err(VerifyError {
            position: bundle.entries.len().saturating_sub(1),
            seq: head_seq,
            message: "latest checkpoint does not match the chain head".into(),
        });
    }

    for checkpoint in &bundle.checkpoints {
        if checkpoint.kind != CheckpointKind::Periodic {
            continue;
        }
        let position = usize::try_from(checkpoint.head_seq.saturating_sub(1)).unwrap_or(0);
        verify_checkpoint(checkpoint, &keys, &bundle.namespace, position)?;
        let Some(entry) = bundle
            .entries
            .iter()
            .find(|entry| entry.seq == checkpoint.head_seq)
        else {
            return Err(VerifyError {
                position,
                seq: checkpoint.head_seq,
                message: "periodic checkpoint does not name a chain entry".into(),
            });
        };
        if checkpoint.head_hash != entry.entry_hash || checkpoint.entry_count != checkpoint.head_seq
        {
            return Err(VerifyError {
                position,
                seq: checkpoint.head_seq,
                message: "periodic checkpoint does not match the named entry".into(),
            });
        }
    }
    Ok(())
}

/// Authenticate a checkpoint against published public keys. Used at write
/// time so a truncated chain cannot be extended until the signed head matches
/// the remaining rows.
pub fn authenticate_checkpoint(
    checkpoint: &Checkpoint,
    keys: &[PublishedKey],
) -> Result<(), String> {
    let map = verifying_keys(keys)?;
    verify_checkpoint(checkpoint, &map, &checkpoint.namespace, 0).map_err(|error| error.to_string())
}

fn trusted_key_ids(trusted_keys: &[&str]) -> Result<BTreeSet<String>, String> {
    if trusted_keys.is_empty() {
        return Err("trusted public key is required".into());
    }
    let mut ids = BTreeSet::new();
    for value in trusted_keys {
        let value = value.trim();
        if let Some(fingerprint) = value.strip_prefix("sha256:") {
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("trusted key id must be sha256: plus 64 hex chars".into());
            }
            ids.insert(format!("sha256:{}", fingerprint.to_ascii_lowercase()));
            continue;
        }
        let bytes = decode_hex32(
            value,
            "trusted public key must be a 32-byte hexadecimal Ed25519 key",
        )?;
        ids.insert(key_id(&bytes));
    }
    Ok(ids)
}

fn verifying_keys(keys: &[PublishedKey]) -> Result<BTreeMap<String, VerifyingKey>, String> {
    let mut out = BTreeMap::new();
    for key in keys {
        let bytes = decode_hex32(&key.public_key_hex, "published public key must be 32 bytes")?;
        let verifying = VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())?;
        let expected = key_id(&bytes);
        if key.key_id != expected {
            return Err("published key_id does not match public key".into());
        }
        out.insert(key.key_id.clone(), verifying);
    }
    Ok(out)
}

fn verify_entry_signature(
    entry: &ChainEntry,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Result<(), String> {
    let verifying = keys
        .get(&entry.key_id)
        .ok_or_else(|| format!("unknown signing key {}", entry.key_id))?;
    let signature = Signature::from_slice(&decode_hex(&entry.signature, 64)?)
        .map_err(|error| error.to_string())?;
    verifying
        .verify(&entry_signed_bytes(&entry.entry_hash), &signature)
        .map_err(|_| "entry signature is invalid".to_string())
}

fn verify_checkpoint(
    checkpoint: &Checkpoint,
    keys: &BTreeMap<String, VerifyingKey>,
    namespace: &str,
    position: usize,
) -> Result<(), VerifyError> {
    if checkpoint.namespace != namespace {
        return Err(VerifyError {
            position,
            seq: checkpoint.head_seq,
            message: "checkpoint namespace does not match the bundle".into(),
        });
    }
    let verifying = keys.get(&checkpoint.key_id).ok_or_else(|| VerifyError {
        position,
        seq: checkpoint.head_seq,
        message: format!("unknown checkpoint signing key {}", checkpoint.key_id),
    })?;
    let signed = checkpoint_signed_bytes(checkpoint).map_err(|message| VerifyError {
        position,
        seq: checkpoint.head_seq,
        message,
    })?;
    let signature =
        Signature::from_slice(&decode_hex(&checkpoint.signature, 64).map_err(|message| {
            VerifyError {
                position,
                seq: checkpoint.head_seq,
                message,
            }
        })?)
        .map_err(|error| VerifyError {
            position,
            seq: checkpoint.head_seq,
            message: error.to_string(),
        })?;
    verifying
        .verify(&signed, &signature)
        .map_err(|_| VerifyError {
            position,
            seq: checkpoint.head_seq,
            message: "checkpoint signature is invalid".into(),
        })
}

fn entry_signed_bytes(entry_hash: &str) -> Vec<u8> {
    let mut out = ENTRY_DOMAIN.to_vec();
    out.extend_from_slice(entry_hash.as_bytes());
    out
}

fn checkpoint_signed_bytes(checkpoint: &Checkpoint) -> Result<Vec<u8>, String> {
    let canonical = serde_json::to_vec(&(
        checkpoint.namespace.as_str(),
        checkpoint.kind.as_str(),
        checkpoint.head_seq,
        checkpoint.head_hash.as_str(),
        checkpoint.entry_count,
        checkpoint.key_id.as_str(),
        checkpoint.created_at_ms,
    ))
    .map_err(|error| error.to_string())?;
    let mut out = CHECKPOINT_DOMAIN.to_vec();
    out.extend_from_slice(&canonical);
    Ok(out)
}

fn entry_error(position: usize, seq: i64, message: impl Into<String>) -> VerifyError {
    VerifyError {
        position,
        seq,
        message: message.into(),
    }
}

fn decode_hex32(value: &str, error: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(value, 32).map_err(|_| error.to_string())?;
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex(value: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    if value.len() != expected_len * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "expected {expected_len} bytes of hexadecimal, got {} chars",
            value.len()
        ));
    }
    (0..expected_len)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid hexadecimal".to_string())
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governed_transform::{ISOLATED_CLASS, TransformRun};

    const SEED_A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SEED_B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn keys() -> SigningKeySet {
        SigningKeySet::from_seed_hex(SEED_A, 1).unwrap()
    }

    fn action_json(id: &str) -> String {
        format!(
            r#"{{"version":"operation.receipt/v1","operation_id":"{id}","namespace":"ns","events":[{{"kind":"action_performed"}}]}}"#
        )
    }

    fn agent_json(id: &str) -> String {
        format!(
            r#"{{"version":"operation.receipt/v1","operation_id":"{id}","namespace":"ns","events":[{{"kind":"model_called"}}]}}"#
        )
    }

    fn isolated_run_json(id: &str) -> String {
        serde_json::to_string(&TransformRun {
            run_id: id.into(),
            namespace: "ns".into(),
            transform_id: "tf-1".into(),
            definition_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            input_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            output_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            last_input_row_id: 3,
            incremental: true,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 2,
            rows_out: 2,
            lineage_parent: String::new(),
            created_at_ms: 40,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: ISOLATED_CLASS.into(),
            engine: "python".into(),
            runtime_image: "python:3.12".into(),
            dispatch_status: "completed".into(),
            trigger_cause: "manual".into(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        })
        .unwrap()
    }

    fn filled_chain() -> ReceiptChain {
        let mut chain = ReceiptChain::genesis("ns", keys(), 10).unwrap();
        chain
            .append(ReceiptKind::Action, "op-1", action_json("op-1"), 11)
            .unwrap();
        chain
            .append(
                ReceiptKind::TransformRun,
                "run-iso",
                isolated_run_json("run-iso"),
                12,
            )
            .unwrap();
        chain
            .append(ReceiptKind::AgentTurn, "op-2", agent_json("op-2"), 13)
            .unwrap();
        chain
    }

    fn trust(keys: &SigningKeySet) -> String {
        keys.current_public_key_hex()
    }

    fn verify(bundle: &ReceiptChainBundle, keys: &SigningKeySet) -> Result<(), VerifyError> {
        let hex = trust(keys);
        verify_bundle(bundle, &[hex.as_str()])
    }

    #[test]
    fn entry_hash_format_is_pinned() {
        assert_eq!(
            entry_hash(
                1,
                GENESIS_HEAD_HASH,
                "ns",
                ReceiptKind::Action,
                "op-1",
                r#"{"k":1}"#,
                10,
            ),
            "sha256:9e4b6d449853627eec188b52a6211c542baa72486953eb8cfe0e99ec53dcdc61"
        );
    }

    #[test]
    fn export_then_offline_verify_passes() {
        let bundle = filled_chain().bundle();
        verify(&bundle, &keys()).expect("fresh bundle verifies");
    }

    #[test]
    fn empty_genesis_bundle_verifies() {
        let bundle = ReceiptChain::genesis("ns", keys(), 10).unwrap().bundle();
        verify(&bundle, &keys()).expect("empty genesis verifies");
        assert!(bundle.entries.is_empty());
        assert!(
            bundle
                .checkpoints
                .iter()
                .any(|checkpoint| checkpoint.kind == CheckpointKind::Latest)
        );
    }

    #[test]
    fn verify_requires_an_independently_trusted_key() {
        let bundle = filled_chain().bundle();
        let error = verify_bundle(&bundle, &[]).expect_err("empty trust set must fail");
        assert!(error.message.contains("trusted public key"), "{error}");
        let attacker = SigningKeySet::from_seed_hex(SEED_B, 1).unwrap();
        let attacker_hex = attacker.current_public_key_hex();
        let error =
            verify_bundle(&bundle, &[attacker_hex.as_str()]).expect_err("foreign key must fail");
        assert!(
            error.message.contains("not in the trusted set")
                || error.message.contains("untrusted")
                || error.message.contains("unknown"),
            "{error}"
        );
    }

    #[test]
    fn altering_a_receipt_fails_at_that_position() {
        let mut bundle = filled_chain().bundle();
        bundle.entries[1].receipt_json.push(' ');
        let error = verify(&bundle, &keys()).expect_err("altered body must fail");
        assert_eq!(error.position, 1);
        assert_eq!(error.seq, 2);
        assert!(error.message.contains("entry_hash"), "{error}");
    }

    #[test]
    fn altering_an_entry_timestamp_fails_at_that_position() {
        let mut bundle = filled_chain().bundle();
        bundle.entries[1].created_at_ms += 1;
        let error = verify(&bundle, &keys()).expect_err("altered timestamp must fail");
        assert_eq!(error.position, 1);
        assert_eq!(error.seq, 2);
        assert!(error.message.contains("entry_hash"), "{error}");
    }

    #[test]
    fn removing_a_receipt_fails_at_the_gap() {
        let mut bundle = filled_chain().bundle();
        bundle.entries.remove(1);
        let error = verify(&bundle, &keys()).expect_err("removed body must fail");
        assert_eq!(error.position, 1);
        assert_eq!(error.seq, 3);
        assert!(
            error.message.contains("expected seq 2") || error.message.contains("prev_hash"),
            "{error}"
        );
    }

    #[test]
    fn reordering_receipts_fails_at_the_first_swapped_position() {
        let mut bundle = filled_chain().bundle();
        bundle.entries.swap(0, 1);
        let error = verify(&bundle, &keys()).expect_err("reordered bodies must fail");
        assert_eq!(error.position, 0);
        assert!(
            error.message.contains("expected seq") || error.message.contains("prev_hash"),
            "{error}"
        );
    }

    #[test]
    fn receipts_before_and_after_key_rotation_both_verify() {
        let mut chain = ReceiptChain::genesis("ns", keys(), 10).unwrap();
        chain
            .append(
                ReceiptKind::Action,
                "op-before",
                action_json("op-before"),
                11,
            )
            .unwrap();
        let before_key = chain.bundle().entries[0].key_id.clone();
        chain.rotate(SEED_B, 12).unwrap();
        chain
            .append(ReceiptKind::Action, "op-after", action_json("op-after"), 13)
            .unwrap();
        let bundle = chain.bundle();
        let before_hex = SigningKeySet::from_seed_hex(SEED_A, 1)
            .unwrap()
            .current_public_key_hex();
        let after_hex = SigningKeySet::from_seed_hex(SEED_B, 1)
            .unwrap()
            .current_public_key_hex();
        verify_bundle(&bundle, &[before_hex.as_str(), after_hex.as_str()])
            .expect("rotated chain verifies");
        assert_ne!(before_key, bundle.entries[1].key_id);
        assert_eq!(bundle.keys.len(), 2);
    }

    #[test]
    fn isolated_runner_transform_run_verifies_with_the_same_tool() {
        let json = isolated_run_json("run-iso");
        assert_eq!(
            classify_receipt_json(&json).unwrap(),
            ReceiptKind::TransformRun
        );
        let mut chain = ReceiptChain::genesis("ns", keys(), 10).unwrap();
        chain
            .append(ReceiptKind::TransformRun, "run-iso", json, 11)
            .unwrap();
        verify(&chain.bundle(), &keys()).expect("isolated transform run verifies");
    }

    #[test]
    fn classify_distinguishes_agent_turns_from_actions() {
        assert_eq!(
            classify_receipt_json(&action_json("op-1")).unwrap(),
            ReceiptKind::Action
        );
        assert_eq!(
            classify_receipt_json(&agent_json("op-2")).unwrap(),
            ReceiptKind::AgentTurn
        );
    }
}
