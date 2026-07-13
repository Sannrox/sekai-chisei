use prost::Message;
use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    EvidenceCausality, EvidenceEnvelope, EvidenceRelationship, EvidenceSubmissionResult,
    SubmitEvidenceRequest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const EVIDENCE_CONTRACT_VERSION: &str = "sekai.evidence/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterConfig {
    pub target: String,
    pub producer_identity: String,
    pub source_instance: String,
    pub namespace: String,
    pub target_external_id: String,
    pub target_kind: String,
    pub classification: String,
}

impl AdapterConfig {
    pub fn from_env() -> Result<Self, String> {
        let classification = env::var("EVIDENCE_CLASSIFICATION")
            .unwrap_or_else(|_| "internal".into())
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            classification.as_str(),
            "public" | "internal" | "confidential" | "restricted"
        ) {
            return Err("EVIDENCE_CLASSIFICATION is invalid".into());
        }
        Ok(Self {
            target: env::var("SEKAI_TARGET").unwrap_or_else(|_| "http://127.0.0.1:50051".into()),
            producer_identity: required_env("EVIDENCE_PRODUCER_IDENTITY")?,
            source_instance: required_env("EVIDENCE_SOURCE_INSTANCE")?,
            namespace: required_env("EVIDENCE_NAMESPACE")?,
            target_external_id: required_env("EVIDENCE_TARGET_EXTERNAL_ID")?,
            target_kind: required_env("EVIDENCE_TARGET_KIND")?,
            classification,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceDraft {
    pub source_type: String,
    pub source_record_id: String,
    pub source_version: String,
    pub source_sequence: i64,
    pub evidence_type: String,
    pub signal: String,
    pub schema_id: String,
    pub schema_version: String,
    pub observed_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub content: Value,
    pub relationships: Vec<EvidenceRelationship>,
    pub confidence_bps: u32,
    pub provenance: HashMap<String, String>,
    pub causality: Option<EvidenceCausality>,
}

impl EvidenceDraft {
    fn into_envelope(
        self,
        config: &AdapterConfig,
        collected_at_ms: i64,
    ) -> Result<EvidenceEnvelope, String> {
        for (field, value) in [
            ("source_type", self.source_type.as_str()),
            ("source_record_id", self.source_record_id.as_str()),
            ("source_version", self.source_version.as_str()),
            ("evidence_type", self.evidence_type.as_str()),
            ("signal", self.signal.as_str()),
            ("schema_id", self.schema_id.as_str()),
            ("schema_version", self.schema_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("adapter produced an empty {field}"));
            }
        }
        if self.source_sequence < 0 {
            return Err("adapter produced a negative source_sequence".into());
        }
        if self.confidence_bps > 10_000 {
            return Err("adapter confidence exceeds 10000 basis points".into());
        }
        let content_json = serde_json::to_vec(&self.content).map_err(|error| error.to_string())?;
        let content_digest = format!("{:x}", Sha256::digest(&content_json));
        let relationships = self
            .relationships
            .iter()
            .map(|relationship| {
                serde_json::json!({
                    "relation": relationship.relation,
                    "target_source_record_id": relationship.target_source_record_id,
                    "target_source_type": relationship.target_source_type,
                    "target_source_instance": relationship.target_source_instance,
                })
            })
            .collect::<Vec<_>>();
        let causality = self.causality.as_ref().map(|causality| {
            serde_json::json!({
                "operation_id": causality.operation_id,
                "parent_operation_id": causality.parent_operation_id,
                "attempt_id": causality.attempt_id,
                "model_call_id": causality.model_call_id,
                "subject_references": causality.subject_references,
                "trace_context": causality.trace_context,
            })
        });
        let idempotency_material = serde_json::json!({
            "contract_version": EVIDENCE_CONTRACT_VERSION,
            "source_type": self.source_type,
            "source_instance": config.source_instance,
            "source_record_id": self.source_record_id,
            "source_version": self.source_version,
            "source_sequence": self.source_sequence,
            "namespace": config.namespace,
            "target_external_id": config.target_external_id,
            "target_kind": config.target_kind,
            "evidence_type": self.evidence_type,
            "signal": self.signal,
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "schema_compatibility": "exact",
            "observed_at_ms": self.observed_at_ms,
            "collected_at_ms": collected_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "content_digest": content_digest,
            "relationships": relationships,
            "producer_identity": config.producer_identity,
            "confidence_bps": self.confidence_bps,
            "classification": config.classification,
            "provenance": self.provenance,
            "intent": "upsert",
            "causality": causality,
        });
        let idempotency_key = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&idempotency_material).map_err(|error| error.to_string())?
            )
        );
        Ok(EvidenceEnvelope {
            contract_version: EVIDENCE_CONTRACT_VERSION.into(),
            source_type: self.source_type,
            source_instance: config.source_instance.clone(),
            source_record_id: self.source_record_id,
            source_version: self.source_version,
            source_sequence: self.source_sequence,
            namespace: config.namespace.clone(),
            target_external_id: config.target_external_id.clone(),
            target_kind: config.target_kind.clone(),
            evidence_type: self.evidence_type,
            signal: self.signal,
            schema_id: self.schema_id,
            schema_version: self.schema_version,
            schema_compatibility: "exact".into(),
            observed_at_ms: self.observed_at_ms,
            collected_at_ms,
            expires_at_ms: self.expires_at_ms,
            content_json,
            relationships: self.relationships,
            producer_identity: config.producer_identity.clone(),
            confidence_bps: self.confidence_bps,
            classification: config.classification.clone(),
            provenance: self.provenance,
            idempotency_key,
            content_digest,
            intent: "upsert".into(),
            causality: self.causality,
        })
    }
}

#[derive(Debug)]
pub struct OutboxReceipt {
    path: PathBuf,
}

impl OutboxReceipt {
    pub fn acknowledge(self) -> Result<(), String> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to acknowledge adapter outbox entry: {error}"
            )),
        }
    }
}

pub fn prepare_delivery(
    config: &AdapterConfig,
    draft: EvidenceDraft,
    collected_at_ms: i64,
) -> Result<(EvidenceEnvelope, OutboxReceipt), String> {
    let outbox = env::var("EVIDENCE_OUTBOX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/evidence-adapter-outbox"));
    prepare_delivery_in(&outbox, config, draft, collected_at_ms)
}

pub fn prepare_delivery_in(
    outbox: &Path,
    config: &AdapterConfig,
    draft: EvidenceDraft,
    collected_at_ms: i64,
) -> Result<(EvidenceEnvelope, OutboxReceipt), String> {
    fs::create_dir_all(outbox)
        .map_err(|error| format!("failed to create adapter outbox: {error}"))?;
    let stable_identity = draft.clone().into_envelope(config, 0)?.idempotency_key;
    let path = outbox.join(format!("{stable_identity}.bin"));
    if path.exists() {
        return load_delivery(path);
    }

    let envelope = draft.into_envelope(config, collected_at_ms)?;
    let temporary = outbox.join(format!(".{stable_identity}.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("failed to create adapter outbox entry: {error}"))?;
    if let Err(error) = file
        .write_all(&envelope.encode_to_vec())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(format!("failed to persist adapter outbox entry: {error}"));
    }
    match fs::hard_link(&temporary, &path) {
        Ok(()) => {
            fs::remove_file(&temporary)
                .map_err(|error| format!("failed to finalize adapter outbox entry: {error}"))?;
            Ok((envelope, OutboxReceipt { path }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            load_delivery(path)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(format!("failed to publish adapter outbox entry: {error}"))
        }
    }
}

fn load_delivery(path: PathBuf) -> Result<(EvidenceEnvelope, OutboxReceipt), String> {
    let bytes =
        fs::read(&path).map_err(|error| format!("failed to read adapter outbox entry: {error}"))?;
    let envelope = EvidenceEnvelope::decode(bytes.as_slice())
        .map_err(|error| format!("adapter outbox entry is corrupt: {error}"))?;
    Ok((envelope, OutboxReceipt { path }))
}

pub async fn submit(
    config: &AdapterConfig,
    envelope: EvidenceEnvelope,
) -> Result<EvidenceSubmissionResult, Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.target).await?;
    let response = SekaiServiceClient::new(channel)
        .submit_evidence(SubmitEvidenceRequest {
            envelope: Some(envelope),
        })
        .await?
        .into_inner();
    response
        .result
        .ok_or_else(|| "Sekai returned no evidence submission result".into())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}
