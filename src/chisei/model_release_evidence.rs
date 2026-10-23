//! Two-way model-release evidence (#1396), companion to Tenkai ADR 0032.
//!
//! Tenkai signs `tenkai.model_runtime_evidence.v1` (health + canary). Chisei
//! verifies those signatures against installed trust roots before an opt-in
//! hosted route is admitted, and signs `chisei.model_evaluation_evidence.v1`
//! for Tenkai's promote gate. Canonical bytes and schema names must stay
//! field-for-field compatible with Tenkai; this crate does not depend on it.
//! Existing routes stay unchanged until a profile sets
//! `require_runtime_evidence`.

use std::collections::{BTreeSet, HashMap};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::chisei::decision_ledger::Decision;
use crate::chisei::eval::{EvalStore, GateDecision};
use crate::chisei::routing_profiles::HostedRoutingProfile;
use crate::chisei_store::{ChiseiDecisionStore, ChiseiModelReleaseEvidenceStore, ChiseiStore};

pub const RUNTIME_EVIDENCE_SCHEMA: &str = "tenkai.model_runtime_evidence.v1";
pub const EVALUATION_EVIDENCE_SCHEMA: &str = "chisei.model_evaluation_evidence.v1";
pub const MODEL_RELEASE_EVIDENCE_CONTRACT: &str = "chisei.model-release-evidence/v1";
pub const CLOCK_SKEW_ALLOWANCE_MS: i64 = 60_000;
pub const RUNTIME_EVIDENCE_TTL_MS: i64 = 3_600_000;
pub const EVALUATION_TRUST_VERSION: u32 = 1;
pub const ACTION_ADMIT_DENIED: &str = "model_release.admit_denied";
pub const ACTION_ADMIT_ALLOWED: &str = "model_release.admit_allowed";
pub const ACTION_EVAL_EXPORT: &str = "model_release.eval_export";
pub const REFUSAL_MISSING: &str = "model_release.missing";
pub const REFUSAL_STALE: &str = "model_release.stale";
pub const REFUSAL_INVALID: &str = "model_release.invalid";
const RUNTIME_EVIDENCE_DOMAIN: &[u8] = b"TENKAI-MODEL-RUNTIME-EVIDENCE-V1\0";
const EVALUATION_DOMAIN: &[u8] = b"TENKAI-MODEL-EVALUATION-V1\0";
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 128;

/// Shared model identity for both evidence directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReleaseIdentity {
    pub provider: String,
    pub model: String,
    pub profile_version: String,
    pub artifact_digest: String,
    pub endpoint: String,
}

/// Tenkai → Chisei runtime health and canary evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub release_id: String,
    pub release_digest: String,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

/// Chisei → Tenkai evaluation result for the same identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEvaluationEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub eval_suite_id: String,
    pub eval_run_id: String,
    pub outcome: EvaluationOutcome,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCanary {
    Passed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSigner {
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelReleaseEvidenceFailure {
    Missing,
    Stale,
    Invalid,
}

impl ModelReleaseEvidenceFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => REFUSAL_MISSING,
            Self::Stale => REFUSAL_STALE,
            Self::Invalid => REFUSAL_INVALID,
        }
    }

    pub fn matches_message(message: &str) -> bool {
        message == REFUSAL_MISSING
            || message == REFUSAL_STALE
            || message == REFUSAL_INVALID
            || message.starts_with(REFUSAL_MISSING)
            || message.starts_with(REFUSAL_STALE)
            || message.starts_with(REFUSAL_INVALID)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTrustRoots {
    pub version: u32,
    pub signers: Vec<TrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigner {
    pub key_id: String,
    pub public_key: String,
}

/// Operator-captured production feedback for a released identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReleaseFeedback {
    pub id: String,
    pub namespace: String,
    pub identity: ModelReleaseIdentity,
    pub actor: String,
    pub note: String,
    pub recorded_at_ms: i64,
}

impl ModelReleaseFeedback {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() || self.id != self.id.trim() {
            return Err("feedback id must be trimmed and non-empty".into());
        }
        if self.namespace != self.namespace.trim() {
            return Err("feedback namespace must be trimmed".into());
        }
        self.identity.validate()?;
        if self.actor.trim().is_empty() {
            return Err("feedback actor must not be empty".into());
        }
        if self.note.trim().is_empty() || self.note.len() > 4096 {
            return Err("feedback note must contain 1 to 4096 bytes".into());
        }
        if self.recorded_at_ms <= 0 {
            return Err("feedback recorded_at_ms must be positive".into());
        }
        Ok(())
    }
}

pub struct RuntimeEvidenceDraft {
    pub identity: ModelReleaseIdentity,
    pub release_id: String,
    pub release_digest: String,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
    pub expires_at: i64,
}

pub struct EvaluationEvidenceDraft {
    pub identity: ModelReleaseIdentity,
    pub eval_suite_id: String,
    pub eval_run_id: String,
    pub outcome: EvaluationOutcome,
    pub observed_at: i64,
    pub expires_at: i64,
}

impl ModelRuntimeEvidence {
    pub fn parse_json(value: &str) -> Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RUNTIME_EVIDENCE_SCHEMA {
            return Err(format!(
                "unsupported model runtime evidence schema {}",
                self.schema
            ));
        }
        self.identity.validate()?;
        if self.release_id.is_empty() {
            return Err("runtime evidence release_id must not be empty".into());
        }
        validate_prefixed_digest("release_digest", &self.release_digest)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        self.signer.validate()
    }
}

impl ModelEvaluationEvidence {
    pub fn parse_json(value: &str) -> Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_statement()?;
        self.signer.validate()
    }

    fn validate_statement(&self) -> Result<(), String> {
        if self.schema != EVALUATION_EVIDENCE_SCHEMA {
            return Err(format!(
                "unsupported model evaluation evidence schema {}",
                self.schema
            ));
        }
        self.identity.validate()?;
        validate_identifier("eval_suite_id", &self.eval_suite_id)?;
        validate_identifier("eval_run_id", &self.eval_run_id)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        validate_key_id("signer.key_id", &self.signer.key_id)
    }
}

impl ModelReleaseIdentity {
    pub fn validate(&self) -> Result<(), String> {
        validate_identifier("provider", &self.provider)?;
        validate_identifier("model", &self.model)?;
        validate_identifier("profile_version", &self.profile_version)?;
        validate_prefixed_digest("artifact_digest", &self.artifact_digest)?;
        validate_endpoint(&self.endpoint)
    }
}

impl EvidenceSigner {
    pub fn validate(&self) -> Result<(), String> {
        validate_key_id("signer.key_id", &self.key_id)?;
        decode_exact::<64>("signer.signature", &self.signature)
            .map(|_| ())
            .map_err(|error| {
                format!("signer.signature must be a 64-byte Ed25519 signature: {error}")
            })
    }
}

impl EvaluationTrustRoots {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != EVALUATION_TRUST_VERSION {
            return Err(format!(
                "unsupported model evaluation trust-root version {}; expected {EVALUATION_TRUST_VERSION}",
                self.version
            ));
        }
        if self.signers.is_empty() {
            return Err("model evaluation trust roots contain no signers".into());
        }
        let mut key_ids = BTreeSet::new();
        for signer in &self.signers {
            validate_key_id("model evaluation signer key id", &signer.key_id)?;
            if !key_ids.insert(signer.key_id.clone()) {
                return Err(format!(
                    "model evaluation trust roots contain duplicate key id {}",
                    signer.key_id
                ));
            }
            trusted_key(&signer.public_key, &signer.key_id)?;
        }
        Ok(())
    }
}

/// Admit a stored runtime record for an opt-in route. Missing, stale, or
/// invalid (including a failed signature or non-passing health/canary)
/// refuses closed.
pub fn admit_runtime_evidence(
    record_json: Option<&str>,
    expected: &ModelReleaseIdentity,
    roots: &EvaluationTrustRoots,
    now_ms: i64,
) -> Result<ModelRuntimeEvidence, ModelReleaseEvidenceFailure> {
    let Some(raw) = record_json.filter(|value| !value.trim().is_empty()) else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    let evidence = ModelRuntimeEvidence::parse_json(raw)?;
    if evidence.validate().is_err() || evidence.identity != *expected {
        return Err(ModelReleaseEvidenceFailure::Invalid);
    }
    if is_stale(evidence.observed_at, evidence.expires_at, now_ms) {
        return Err(ModelReleaseEvidenceFailure::Stale);
    }
    if evidence.health != RuntimeHealth::Healthy || evidence.canary != RuntimeCanary::Passed {
        return Err(ModelReleaseEvidenceFailure::Invalid);
    }
    verify_runtime_signature(&evidence, roots).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
    Ok(evidence)
}

pub fn sign_runtime_evidence(
    draft: RuntimeEvidenceDraft,
    key: &SigningKey,
) -> Result<ModelRuntimeEvidence, String> {
    let mut evidence = ModelRuntimeEvidence {
        schema: RUNTIME_EVIDENCE_SCHEMA.into(),
        identity: draft.identity,
        release_id: draft.release_id,
        release_digest: prefixed_digest("release_digest", &draft.release_digest)?,
        health: draft.health,
        canary: draft.canary,
        observed_at: draft.observed_at,
        expires_at: draft.expires_at,
        signer: EvidenceSigner {
            key_id: key_id(&key.verifying_key().to_bytes()),
            signature: String::new(),
        },
    };
    evidence.identity.validate()?;
    if evidence.release_id.is_empty() {
        return Err("runtime evidence release_id must not be empty".into());
    }
    validate_timestamps(evidence.observed_at, evidence.expires_at)?;
    let canonical = canonical_runtime_evidence_bytes(&evidence)?;
    evidence.signer.signature =
        base64::engine::general_purpose::STANDARD.encode(key.sign(&canonical).to_bytes());
    evidence.validate()?;
    Ok(evidence)
}

pub fn sign_evaluation_evidence(
    draft: EvaluationEvidenceDraft,
    key: &SigningKey,
) -> Result<ModelEvaluationEvidence, String> {
    let mut evidence = ModelEvaluationEvidence {
        schema: EVALUATION_EVIDENCE_SCHEMA.into(),
        identity: draft.identity,
        eval_suite_id: draft.eval_suite_id,
        eval_run_id: draft.eval_run_id,
        outcome: draft.outcome,
        observed_at: draft.observed_at,
        expires_at: draft.expires_at,
        signer: EvidenceSigner {
            key_id: key_id(&key.verifying_key().to_bytes()),
            signature: String::new(),
        },
    };
    evidence.validate_statement()?;
    let canonical = canonical_evaluation_bytes(&evidence)?;
    evidence.signer.signature =
        base64::engine::general_purpose::STANDARD.encode(key.sign(&canonical).to_bytes());
    evidence.validate()?;
    Ok(evidence)
}

pub fn verify_evaluation_signature(
    evidence: &ModelEvaluationEvidence,
    roots: &EvaluationTrustRoots,
) -> Result<(), String> {
    roots.validate()?;
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == evidence.signer.key_id)
        .ok_or_else(|| "model evaluation signer is not currently trusted".to_string())?;
    let key = trusted_key(&signer.public_key, &signer.key_id)?;
    verify_strict(
        &key,
        "model evaluation signature",
        &evidence.signer.signature,
        &canonical_evaluation_bytes(evidence)?,
    )
}

pub fn verify_runtime_signature(
    evidence: &ModelRuntimeEvidence,
    roots: &EvaluationTrustRoots,
) -> Result<(), String> {
    roots.validate()?;
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == evidence.signer.key_id)
        .ok_or_else(|| "model runtime signer is not currently trusted".to_string())?;
    let key = trusted_key(&signer.public_key, &signer.key_id)?;
    verify_strict(
        &key,
        "model runtime signature",
        &evidence.signer.signature,
        &canonical_runtime_evidence_bytes(evidence)?,
    )
}

fn canonical_evaluation_bytes(evidence: &ModelEvaluationEvidence) -> Result<Vec<u8>, String> {
    evidence.validate_statement()?;
    let mut bytes = EVALUATION_DOMAIN.to_vec();
    for value in [
        evidence.schema.as_bytes(),
        evidence.identity.provider.as_bytes(),
        evidence.identity.model.as_bytes(),
        evidence.identity.profile_version.as_bytes(),
        evidence.identity.artifact_digest.as_bytes(),
        evidence.identity.endpoint.as_bytes(),
        evidence.eval_suite_id.as_bytes(),
        evidence.eval_run_id.as_bytes(),
        match evidence.outcome {
            EvaluationOutcome::Passed => b"passed".as_slice(),
            EvaluationOutcome::Failed => b"failed".as_slice(),
        },
        evidence.signer.key_id.as_bytes(),
    ] {
        push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&evidence.observed_at.to_be_bytes());
    bytes.extend_from_slice(&evidence.expires_at.to_be_bytes());
    Ok(bytes)
}

fn canonical_runtime_evidence_bytes(evidence: &ModelRuntimeEvidence) -> Result<Vec<u8>, String> {
    let mut bytes = RUNTIME_EVIDENCE_DOMAIN.to_vec();
    for value in [
        evidence.schema.as_bytes(),
        evidence.identity.provider.as_bytes(),
        evidence.identity.model.as_bytes(),
        evidence.identity.profile_version.as_bytes(),
        evidence.identity.artifact_digest.as_bytes(),
        evidence.identity.endpoint.as_bytes(),
        evidence.release_id.as_bytes(),
        evidence.release_digest.as_bytes(),
        health_label(evidence.health).as_bytes(),
        canary_label(evidence.canary).as_bytes(),
        evidence.signer.key_id.as_bytes(),
    ] {
        push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&evidence.observed_at.to_be_bytes());
    bytes.extend_from_slice(&evidence.expires_at.to_be_bytes());
    Ok(bytes)
}

fn health_label(health: RuntimeHealth) -> &'static str {
    match health {
        RuntimeHealth::Healthy => "healthy",
        RuntimeHealth::Unhealthy => "unhealthy",
        RuntimeHealth::Unknown => "unknown",
    }
}

fn canary_label(canary: RuntimeCanary) -> &'static str {
    match canary {
        RuntimeCanary::Passed => "passed",
        RuntimeCanary::Failed => "failed",
        RuntimeCanary::Incomplete => "incomplete",
    }
}

fn push_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_identifier(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(format!(
            "{label} must contain 1 to {MAX_IDENTIFIER_BYTES} bytes"
        ));
    }
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        return Err(format!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_', '-', or '+'"
        ));
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || value.chars().any(char::is_control) {
        return Err("endpoint is empty, oversized, or contains control characters".into());
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err("endpoint must be an absolute URI".into());
    };
    if scheme.is_empty()
        || rest.is_empty()
        || scheme.bytes().any(|byte| !byte.is_ascii_alphanumeric())
    {
        return Err("endpoint must be an absolute URI".into());
    }
    Ok(())
}

fn validate_timestamps(observed_at: i64, expires_at: i64) -> Result<(), String> {
    if observed_at <= 0 || expires_at <= observed_at {
        return Err("evidence timestamps must be positive and expire after observation".into());
    }
    Ok(())
}

fn is_stale(observed_at: i64, expires_at: i64, now_ms: i64) -> bool {
    observed_at > now_ms.saturating_add(CLOCK_SKEW_ALLOWANCE_MS) || expires_at <= now_ms
}

fn prefixed_digest(label: &str, value: &str) -> Result<String, String> {
    let prefixed = if value.starts_with("sha256:") {
        value.to_string()
    } else {
        format!("sha256:{value}")
    };
    validate_prefixed_digest(label, &prefixed)?;
    Ok(prefixed)
}

fn validate_prefixed_digest(label: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{label} must use sha256:<hex>"));
    };
    validate_hex_digest(label, hex)
}

fn validate_key_id(label: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{label} must use the sha256:<hex> format"));
    };
    validate_hex_digest(label, hex)
}

fn validate_hex_digest(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(public_key))
}

fn decode_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{label} is not valid base64"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label} must decode to {N} bytes, got {}", bytes.len()))
}

fn trusted_key(public_key: &str, expected_key_id: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_exact::<32>("model evidence public key", public_key)?;
    let derived = key_id(&bytes);
    if expected_key_id != derived {
        return Err(format!(
            "model evidence public key id {expected_key_id} does not match its public key ({derived})"
        ));
    }
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "model evidence public key is not a valid Ed25519 public key".to_string())?;
    if key.is_weak() {
        return Err("model evidence public key is weak and cannot be trusted".into());
    }
    Ok(key)
}

fn verify_strict(
    key: &VerifyingKey,
    signature_label: &str,
    signature: &str,
    message: &[u8],
) -> Result<(), String> {
    let signature = decode_exact::<64>(signature_label, signature)?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| format!("{signature_label} verification failed"))
}

pub fn identity_from_hosted_profile(
    profile: &HostedRoutingProfile,
) -> Result<Option<ModelReleaseIdentity>, String> {
    if !profile.require_runtime_evidence {
        return Ok(None);
    }
    let Some(digest) = profile.artifact_digest.as_deref() else {
        return Err("artifact_digest is required when require_runtime_evidence is set".into());
    };
    let identity = ModelReleaseIdentity {
        provider: profile.evidence_provider.clone(),
        model: profile.evidence_model.clone(),
        profile_version: profile.evidence_profile_version.clone(),
        artifact_digest: profile.evidence_artifact_digest.clone(),
        endpoint: profile.evidence_endpoint.clone(),
    };
    identity.validate()?;
    if digest != identity.artifact_digest {
        return Err("evidence_artifact_digest must match the profile artifact_digest".into());
    }
    let bound_origin = crate::chisei::routing_profiles::canonical_origin(&identity.endpoint)
        .map_err(|_| "evidence_endpoint must match the served endpoint origin".to_string())?;
    if bound_origin != profile.endpoint_origin {
        return Err("evidence_endpoint must match the served endpoint origin".into());
    }
    Ok(Some(identity))
}

pub fn fingerprint_runtime(evidence: &ModelRuntimeEvidence) -> Result<String, String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_runtime_evidence_bytes(evidence)?)
    ))
}

pub fn install_trust_roots(
    db: &ChiseiStore,
    roots: EvaluationTrustRoots,
    updated_at_ms: i64,
) -> Result<EvaluationTrustRoots, String> {
    roots.validate()?;
    db.put_model_release_trust(&roots, updated_at_ms)?;
    Ok(roots)
}

pub fn load_trust_roots(db: &ChiseiStore) -> Result<Option<EvaluationTrustRoots>, String> {
    db.get_model_release_trust()
}

pub fn ingest_runtime_evidence(
    db: &ChiseiStore,
    evidence: ModelRuntimeEvidence,
    ingested_at_ms: i64,
) -> Result<ModelRuntimeEvidence, String> {
    evidence.validate()?;
    if is_stale(evidence.observed_at, evidence.expires_at, ingested_at_ms) {
        return Err("runtime evidence is stale or not yet valid".into());
    }
    let roots = db
        .get_model_release_trust()?
        .ok_or_else(|| "model release trust roots are not installed".to_string())?;
    verify_runtime_signature(&evidence, &roots)?;
    db.put_model_runtime_evidence(&evidence, ingested_at_ms)?;
    Ok(evidence)
}

pub fn load_runtime_evidence_json(
    db: &ChiseiStore,
    identity: &ModelReleaseIdentity,
) -> Result<Option<String>, String> {
    db.get_model_runtime_evidence(identity)
}

pub fn requested_model_matches_bound_identity(
    requested_model: &str,
    identity: &ModelReleaseIdentity,
) -> bool {
    if requested_model == identity.model {
        return true;
    }
    let Some(provider) = crate::provider_profile::hosted_provider_of(requested_model) else {
        return false;
    };
    requested_model
        .strip_prefix(provider)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|upstream| upstream == identity.model)
}

/// Whether an opt-in hosted profile may be used as a failover candidate.
/// Default (non-opt-in) profiles stay allowed. Failure is silent: unused
/// fallbacks do not write a ledger row.
pub fn route_runtime_evidence_allows(
    db: &ChiseiStore,
    profile: &HostedRoutingProfile,
    requested_model: &str,
    now_ms: i64,
) -> bool {
    admit_hosted_runtime_evidence(db, profile, Some(requested_model), now_ms, None).is_ok()
}

/// Admit an opt-in hosted route against stored Tenkai runtime evidence.
/// Non-opt-in profiles return Ok without a ledger row.
pub fn admit_hosted_runtime_evidence(
    db: &ChiseiStore,
    profile: &HostedRoutingProfile,
    requested_model: Option<&str>,
    now_ms: i64,
    actor: Option<&str>,
) -> Result<Option<ModelRuntimeEvidence>, ModelReleaseEvidenceFailure> {
    let identity = match identity_from_hosted_profile(profile) {
        Ok(None) => return Ok(None),
        Ok(Some(identity)) => identity,
        Err(_) => {
            let identity = ModelReleaseIdentity {
                provider: profile.evidence_provider.clone(),
                model: profile.evidence_model.clone(),
                profile_version: profile.evidence_profile_version.clone(),
                artifact_digest: profile.evidence_artifact_digest.clone(),
                endpoint: profile.evidence_endpoint.clone(),
            };
            return finish_admission(
                db,
                profile,
                &identity,
                Err(ModelReleaseEvidenceFailure::Invalid),
                actor,
            )
            .map(|_| None);
        }
    };
    if requested_model
        .is_some_and(|model| !requested_model_matches_bound_identity(model, &identity))
    {
        return finish_admission(
            db,
            profile,
            &identity,
            Err(ModelReleaseEvidenceFailure::Invalid),
            actor,
        )
        .map(|_| None);
    }
    let result = (|| {
        let roots = db
            .get_model_release_trust()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?
            .ok_or(ModelReleaseEvidenceFailure::Invalid)?;
        let record = db
            .get_model_runtime_evidence(&identity)
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        admit_runtime_evidence(record.as_deref(), &identity, &roots, now_ms)
    })();
    finish_admission(db, profile, &identity, result, actor)
}

fn finish_admission(
    db: &ChiseiStore,
    profile: &HostedRoutingProfile,
    identity: &ModelReleaseIdentity,
    result: Result<ModelRuntimeEvidence, ModelReleaseEvidenceFailure>,
    actor: Option<&str>,
) -> Result<Option<ModelRuntimeEvidence>, ModelReleaseEvidenceFailure> {
    match &result {
        Ok(evidence) => {
            if let Some(actor) = actor {
                let fingerprint = fingerprint_runtime(evidence).unwrap_or_default();
                audit_admission(
                    db,
                    actor,
                    identity,
                    &profile.namespace,
                    ACTION_ADMIT_ALLOWED,
                    "allowed",
                    None,
                    &fingerprint,
                )
                .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
            }
        }
        Err(failure) => {
            if let Some(actor) = actor {
                let _ = audit_admission(
                    db,
                    actor,
                    identity,
                    &profile.namespace,
                    ACTION_ADMIT_DENIED,
                    "denied",
                    Some(failure.as_str()),
                    "",
                );
            }
        }
    }
    result.map(Some)
}

#[allow(clippy::too_many_arguments)]
fn audit_admission(
    db: &ChiseiStore,
    actor: &str,
    identity: &ModelReleaseIdentity,
    namespace: &str,
    action: &str,
    outcome: &str,
    refusal: Option<&str>,
    fingerprint: &str,
) -> Result<(), String> {
    let mut evidence = HashMap::from([
        (
            "contract_version".into(),
            MODEL_RELEASE_EVIDENCE_CONTRACT.into(),
        ),
        ("namespace".into(), namespace.into()),
        ("provider".into(), identity.provider.clone()),
        ("model".into(), identity.model.clone()),
        ("profile_version".into(), identity.profile_version.clone()),
        ("artifact_digest".into(), identity.artifact_digest.clone()),
        ("endpoint".into(), identity.endpoint.clone()),
        ("evidence_fingerprint".into(), fingerprint.into()),
    ]);
    if let Some(refusal) = refusal {
        evidence.insert("refusal".into(), refusal.into());
    }
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: actor.to_string(),
        action: action.into(),
        reason: refusal.unwrap_or("admitted").into(),
        evidence,
        target_id: format!(
            "model-release-admit:{}:{}:{}:{}:{}",
            namespace,
            identity.provider,
            identity.model,
            identity.artifact_digest,
            identity.endpoint
        ),
        outcome: outcome.into(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn export_evaluation_from_compare(
    db: &ChiseiStore,
    identity: ModelReleaseIdentity,
    suite_id: &str,
    baseline_run_id: &str,
    candidate_run_id: &str,
    eval_run_id: &str,
    key: &SigningKey,
    now_ms: i64,
    actor: &str,
) -> Result<ModelEvaluationEvidence, String> {
    identity.validate()?;
    let eval = EvalStore::with_db(db.clone());
    let baseline = eval
        .get_run(baseline_run_id)
        .ok_or_else(|| "baseline eval run is unavailable for the regression gate".to_string())?;
    let candidate = eval
        .get_run(candidate_run_id)
        .ok_or_else(|| "candidate eval run is unavailable for the regression gate".to_string())?;
    if baseline.suite_id != suite_id || candidate.suite_id != suite_id {
        return Err("eval runs must belong to the pinned suite".into());
    }
    if candidate.config_ref != identity.artifact_digest {
        return Err("candidate eval run must be pinned to the release artifact digest".into());
    }
    if baseline.id == candidate.id {
        return Err("regression gate requires distinct baseline and candidate runs".into());
    }
    let suite = eval
        .get_suite(suite_id)
        .ok_or_else(|| "pinned eval suite is unavailable".to_string())?;
    if suite.cases.is_empty() {
        return Err("pinned eval suite has no cases".into());
    }
    let mut suite_cases = suite
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    let unique = suite_cases.len();
    suite_cases.sort();
    suite_cases.dedup();
    if suite_cases.len() != unique {
        return Err("pinned eval suite has duplicate cases".into());
    }
    let mut baseline_cases = baseline
        .results
        .iter()
        .map(|result| result.case_id.as_str())
        .collect::<Vec<_>>();
    let mut candidate_cases = candidate
        .results
        .iter()
        .map(|result| result.case_id.as_str())
        .collect::<Vec<_>>();
    baseline_cases.sort();
    candidate_cases.sort();
    if baseline_cases != suite_cases || candidate_cases != suite_cases {
        return Err("eval runs must cover every pinned suite case".into());
    }
    if !eval_run_id.is_empty() && eval_run_id != candidate.id {
        return Err("eval_run_id must be the candidate run".into());
    }
    let gate: GateDecision = eval
        .compare_runs(&baseline.id, &candidate.id)
        .ok_or_else(|| "eval runs are unavailable for the regression gate".to_string())?;
    let outcome = if gate.verdict == "pass" {
        EvaluationOutcome::Passed
    } else {
        EvaluationOutcome::Failed
    };
    let evidence = sign_evaluation_evidence(
        EvaluationEvidenceDraft {
            identity,
            eval_suite_id: suite_id.into(),
            eval_run_id: candidate.id.clone(),
            outcome,
            observed_at: now_ms,
            expires_at: now_ms.saturating_add(RUNTIME_EVIDENCE_TTL_MS),
        },
        key,
    )?;
    db.put_model_evaluation_export(&evidence, now_ms)?;
    let ledger = HashMap::from([
        (
            "contract_version".into(),
            MODEL_RELEASE_EVIDENCE_CONTRACT.into(),
        ),
        ("provider".into(), evidence.identity.provider.clone()),
        ("model".into(), evidence.identity.model.clone()),
        (
            "profile_version".into(),
            evidence.identity.profile_version.clone(),
        ),
        (
            "artifact_digest".into(),
            evidence.identity.artifact_digest.clone(),
        ),
        ("endpoint".into(), evidence.identity.endpoint.clone()),
        ("eval_suite_id".into(), evidence.eval_suite_id.clone()),
        ("eval_run_id".into(), evidence.eval_run_id.clone()),
        ("baseline_run_id".into(), baseline_run_id.into()),
        ("candidate_run_id".into(), candidate_run_id.into()),
        ("verdict".into(), gate.verdict.clone()),
        ("reason".into(), gate.reason.clone()),
        (
            "outcome".into(),
            match evidence.outcome {
                EvaluationOutcome::Passed => "passed".into(),
                EvaluationOutcome::Failed => "failed".into(),
            },
        ),
    ]);
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now_ms,
        actor: actor.into(),
        action: ACTION_EVAL_EXPORT.into(),
        reason: gate.reason,
        evidence: ledger,
        target_id: format!(
            "model-release-eval:{}:{}:{}",
            evidence.identity.provider, evidence.identity.model, evidence.eval_run_id
        ),
        outcome: gate.verdict,
    })?;
    Ok(evidence)
}

/// Signs evaluation evidence from a comparison of eval dataset runs
/// (#1677): the outcome is the comparison's gate verdict, and the decision
/// ledger keeps the whole comparison, so the exported release evidence
/// carries the counts, the p-value and the policy deltas it was decided on.
/// Whether `model` (`provider/model` or `model`) names the released model.
pub fn model_matches(model: &str, identity: &ModelReleaseIdentity) -> bool {
    model == format!("{}/{}", identity.provider, identity.model) || model == identity.model
}

/// A valid evidence identifier for `parts`: `<prefix>.<32 hex of SHA-256>`.
fn evidence_id(prefix: &str, parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\n").as_bytes());
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{prefix}.{hex}")
}

#[allow(clippy::too_many_arguments)]
pub fn export_evaluation_from_dataset_comparison(
    db: &ChiseiStore,
    identity: ModelReleaseIdentity,
    comparison: &crate::chisei::eval_compare::RunComparison,
    candidate: &crate::chisei::eval_run::EvalRunSpec,
    candidate_artifact: Option<&str>,
    evaluator_model: Option<&str>,
    key: &SigningKey,
    now_ms: i64,
    actor: &str,
) -> Result<ModelEvaluationEvidence, String> {
    identity.validate()?;
    // Only an evaluator that ran on the released model exercised it; a
    // deterministic evaluator judges the dataset alone, whatever the run's
    // model label says.
    if !evaluator_model.is_some_and(|model| model_matches(model, &identity)) {
        return Err("release evidence needs a run whose evaluator ran the released model".into());
    }
    if candidate.run_id != comparison.candidate_run_id {
        return Err("the comparison is not of this candidate run".into());
    }
    // Only a run pinned to the released artifact is evidence for it.
    if candidate_artifact != Some(identity.artifact_digest.as_str()) {
        return Err("candidate eval run must be pinned to the release artifact digest".into());
    }
    if !model_matches(&candidate.model, &identity) {
        return Err("candidate eval run must run the released model".into());
    }
    let outcome = if comparison.verdict == crate::chisei::eval_compare::VERDICT_PASS {
        EvaluationOutcome::Passed
    } else {
        EvaluationOutcome::Failed
    };
    let evidence = sign_evaluation_evidence(
        EvaluationEvidenceDraft {
            identity,
            // Evidence ids are narrower than dataset and run ids, so they
            // are derived; the ledger below keeps the ids themselves.
            eval_suite_id: evidence_id(
                "dataset",
                &[&comparison.dataset, &comparison.dataset_version],
            ),
            eval_run_id: evidence_id(
                "run",
                &[&comparison.namespace, &comparison.candidate_run_id],
            ),
            outcome,
            observed_at: now_ms,
            expires_at: now_ms.saturating_add(RUNTIME_EVIDENCE_TTL_MS),
        },
        key,
    )?;
    db.put_model_evaluation_export(&evidence, now_ms)?;
    let comparison_json = serde_json::to_string(comparison).map_err(|error| error.to_string())?;
    let ledger = HashMap::from([
        (
            "contract_version".into(),
            MODEL_RELEASE_EVIDENCE_CONTRACT.into(),
        ),
        ("provider".into(), evidence.identity.provider.clone()),
        ("model".into(), evidence.identity.model.clone()),
        (
            "artifact_digest".into(),
            evidence.identity.artifact_digest.clone(),
        ),
        ("eval_suite_id".into(), evidence.eval_suite_id.clone()),
        ("eval_run_id".into(), evidence.eval_run_id.clone()),
        ("dataset".into(), comparison.dataset.clone()),
        ("dataset_version".into(), comparison.dataset_version.clone()),
        ("baseline_run_id".into(), comparison.baseline_run_id.clone()),
        (
            "candidate_run_id".into(),
            comparison.candidate_run_id.clone(),
        ),
        ("verdict".into(), comparison.verdict.clone()),
        ("comparison".into(), comparison_json),
    ]);
    let reason = if comparison.reasons.is_empty() {
        "no significant regression and no new policy violation".to_string()
    } else {
        comparison.reasons.join("; ")
    };
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now_ms,
        actor: actor.into(),
        action: ACTION_EVAL_EXPORT.into(),
        reason,
        evidence: ledger,
        target_id: format!(
            "model-release-eval:{}:{}:{}",
            evidence.identity.provider, evidence.identity.model, evidence.eval_run_id
        ),
        outcome: comparison.verdict.clone(),
    })?;
    Ok(evidence)
}

pub fn record_model_release_feedback(
    db: &ChiseiStore,
    record: ModelReleaseFeedback,
) -> Result<ModelReleaseFeedback, String> {
    record.validate()?;
    db.put_model_release_feedback(&record)?;
    Ok(record)
}

pub fn list_model_release_feedback(
    db: &ChiseiStore,
    namespace: &str,
) -> Result<Vec<ModelReleaseFeedback>, String> {
    db.list_model_release_feedback(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: i64 = 1_700_000_100_000;
    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RELEASE_DIGEST: &str =
        "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const SERVED_ORIGIN: &str = "https://models.example.com";

    fn identity() -> ModelReleaseIdentity {
        ModelReleaseIdentity {
            provider: "huggingface".into(),
            model: "qwen-coder".into(),
            profile_version: "v1".into(),
            artifact_digest: DIGEST.into(),
            endpoint: "served://qwen-coder".into(),
        }
    }

    fn bound_identity() -> ModelReleaseIdentity {
        ModelReleaseIdentity {
            provider: "huggingface".into(),
            model: "qwen-coder".into(),
            profile_version: "v1".into(),
            artifact_digest: DIGEST.into(),
            endpoint: SERVED_ORIGIN.into(),
        }
    }

    fn opt_in_profile(namespace: &str, origin: &str, digest: Option<&str>) -> HostedRoutingProfile {
        HostedRoutingProfile {
            namespace: namespace.into(),
            profile_id: "hosted:acme".into(),
            endpoint_origin: origin.into(),
            model_patterns: vec!["qwen-coder".into()],
            credential_ref: "ACME".into(),
            artifact_digest: digest.map(str::to_string),
            registered_by: "root".into(),
            registered_at_ms: 1,
            require_runtime_evidence: true,
            evidence_provider: bound_identity().provider,
            evidence_model: bound_identity().model,
            evidence_profile_version: bound_identity().profile_version,
            evidence_artifact_digest: bound_identity().artifact_digest,
            evidence_endpoint: bound_identity().endpoint,
        }
    }

    fn signing_pair() -> (SigningKey, EvaluationTrustRoots) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = key.verifying_key().to_bytes();
        let roots = EvaluationTrustRoots {
            version: EVALUATION_TRUST_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&public),
                public_key: base64::engine::general_purpose::STANDARD.encode(public),
            }],
        };
        (key, roots)
    }

    fn runtime_draft() -> RuntimeEvidenceDraft {
        runtime_draft_for(identity())
    }

    fn runtime_draft_for(identity: ModelReleaseIdentity) -> RuntimeEvidenceDraft {
        RuntimeEvidenceDraft {
            identity,
            release_id: "qwen-coder@0.1.0".into(),
            release_digest: RELEASE_DIGEST.into(),
            health: RuntimeHealth::Healthy,
            canary: RuntimeCanary::Passed,
            observed_at: 1_700_000_000_000,
            expires_at: 1_700_003_600_000,
        }
    }

    #[test]
    fn signed_runtime_evidence_admits_when_fresh_and_passing() {
        let (key, roots) = signing_pair();
        let evidence = sign_runtime_evidence(runtime_draft(), &key).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        admit_runtime_evidence(Some(&json), &identity(), &roots, NOW_MS).unwrap();
    }

    #[test]
    fn missing_runtime_evidence_is_refused() {
        let (_, roots) = signing_pair();
        assert_eq!(
            admit_runtime_evidence(None, &identity(), &roots, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );
    }

    #[test]
    fn stale_runtime_evidence_is_refused() {
        let (key, roots) = signing_pair();
        let evidence = sign_runtime_evidence(runtime_draft(), &key).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        assert_eq!(
            admit_runtime_evidence(Some(&json), &identity(), &roots, evidence.expires_at)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Stale
        );
    }

    #[test]
    fn incomplete_canary_is_invalid() {
        let (key, roots) = signing_pair();
        let mut draft = runtime_draft();
        draft.canary = RuntimeCanary::Incomplete;
        let evidence = sign_runtime_evidence(draft, &key).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        assert_eq!(
            admit_runtime_evidence(Some(&json), &identity(), &roots, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn unknown_fields_are_invalid() {
        let mutated = r#"{
            "schema": "tenkai.model_runtime_evidence.v1",
            "extra": true,
            "identity": {
                "provider": "huggingface",
                "model": "qwen-coder",
                "profile_version": "v1",
                "artifact_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "endpoint": "served://qwen-coder"
            },
            "release_id": "qwen-coder@0.1.0",
            "release_digest": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "health": "healthy",
            "canary": "passed",
            "observed_at": 1700000000000,
            "expires_at": 1700003600000,
            "signer": {
                "key_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
            }
        }"#;
        assert_eq!(
            ModelRuntimeEvidence::parse_json(mutated).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn signed_evaluation_evidence_round_trips() {
        let (key, roots) = signing_pair();
        let evidence = sign_evaluation_evidence(
            EvaluationEvidenceDraft {
                identity: identity(),
                eval_suite_id: "model-quality".into(),
                eval_run_id: "run-1".into(),
                outcome: EvaluationOutcome::Passed,
                observed_at: 1_700_000_000_000,
                expires_at: 1_700_003_600_000,
            },
            &key,
        )
        .unwrap();
        verify_evaluation_signature(&evidence, &roots).unwrap();
        assert_eq!(evidence.schema, EVALUATION_EVIDENCE_SCHEMA);
        assert_eq!(evidence.identity, identity());
    }

    #[test]
    fn identity_mismatch_is_invalid() {
        let (key, roots) = signing_pair();
        let evidence = sign_runtime_evidence(runtime_draft(), &key).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let mut other = identity();
        other.model = "other-model".into();
        assert_eq!(
            admit_runtime_evidence(Some(&json), &other, &roots, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn untrusted_signer_is_invalid() {
        let (key, _) = signing_pair();
        let evidence = sign_runtime_evidence(runtime_draft(), &key).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let other = SigningKey::from_bytes(&[9; 32]);
        let public = other.verifying_key().to_bytes();
        let roots = EvaluationTrustRoots {
            version: EVALUATION_TRUST_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&public),
                public_key: base64::engine::general_purpose::STANDARD.encode(public),
            }],
        };
        assert_eq!(
            admit_runtime_evidence(Some(&json), &identity(), &roots, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }
    #[test]
    fn opt_in_profile_admits_ingested_runtime_evidence() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (key, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let evidence = sign_runtime_evidence(runtime_draft_for(bound_identity()), &key).unwrap();
        ingest_runtime_evidence(&db, evidence.clone(), NOW_MS).unwrap();
        let mut profile = opt_in_profile("sales", SERVED_ORIGIN, Some(DIGEST));
        admit_hosted_runtime_evidence(
            &db,
            &profile,
            Some("hosted.acme/qwen-coder"),
            NOW_MS,
            Some("root"),
        )
        .unwrap();
        profile.evidence_endpoint = format!("{SERVED_ORIGIN}/v1");
        assert_eq!(
            identity_from_hosted_profile(&profile)
                .unwrap()
                .unwrap()
                .endpoint,
            format!("{SERVED_ORIGIN}/v1")
        );
        profile.require_runtime_evidence = false;
        assert!(route_runtime_evidence_allows(
            &db,
            &profile,
            "hosted.acme/qwen-coder",
            NOW_MS
        ));
    }

    #[test]
    fn opt_in_profile_without_evidence_is_refused() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (_, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let profile = opt_in_profile("sales", SERVED_ORIGIN, Some(DIGEST));
        assert_eq!(
            admit_hosted_runtime_evidence(
                &db,
                &profile,
                Some("hosted.acme/qwen-coder"),
                NOW_MS,
                Some("root")
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );
    }

    #[test]
    fn compare_runs_export_signs_regression_outcome() {
        use crate::chisei::eval::{CaseResult, Run};
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let eval = EvalStore::with_db(db.clone());
        eval.put_suite(crate::chisei::eval::Suite {
            id: "quality".into(),
            name: "quality".into(),
            description: "pinned".into(),
            cases: vec![crate::chisei::eval::Case {
                id: "c1".into(),
                name: "c1".into(),
                namespace: "sales".into(),
                spec: "ok".into(),
                assertions: Vec::new(),
            }],
        })
        .unwrap();
        eval.put_run(Run {
            id: "base".into(),
            suite_id: "quality".into(),
            config_ref: RELEASE_DIGEST.into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "ok".into(),
                result: "ok".into(),
                score: 1,
                reason: "ok".into(),
                elapsed: 1,
            }],
            timestamp: 1,
        })
        .unwrap();
        eval.put_run(Run {
            id: "cand".into(),
            suite_id: "quality".into(),
            config_ref: DIGEST.into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: false,
                status: "fail".into(),
                result: "fail".into(),
                score: 0,
                reason: "regressed".into(),
                elapsed: 1,
            }],
            timestamp: 2,
        })
        .unwrap();
        let (key, _) = signing_pair();
        let evidence = export_evaluation_from_compare(
            &db,
            identity(),
            "quality",
            "base",
            "cand",
            "cand",
            &key,
            NOW_MS,
            "root",
        )
        .unwrap();
        assert_eq!(evidence.outcome, EvaluationOutcome::Failed);
        assert_eq!(evidence.schema, EVALUATION_EVIDENCE_SCHEMA);
    }

    #[test]
    fn a_dataset_comparison_decides_the_outcome_and_is_kept_with_the_export() {
        use crate::chisei::decision_ledger::DecisionFilter;
        use crate::chisei::eval_compare::{RunComparison, VERDICT_FAIL, VERDICT_PASS};
        use crate::chisei_store::{ChiseiDecisionStore, ChiseiStore};
        let db = ChiseiStore::memory();
        let (key, _) = signing_pair();
        let comparison = |verdict: &str, candidate: &str| RunComparison {
            contract_version: crate::chisei::eval_compare::EVAL_COMPARISON_CONTRACT.into(),
            namespace: "acme".into(),
            dataset: "triage".into(),
            dataset_version: "v0123456789abcdef".into(),
            baseline_run_id: "release-1.3.0".into(),
            candidate_run_id: candidate.into(),
            cases: 40,
            both_passed: 30,
            both_failed: 0,
            regressions: 10,
            improvements: 0,
            p_value: 0.001,
            alpha: 0.05,
            significant_regression: verdict == VERDICT_FAIL,
            policy: Vec::new(),
            policy_increased: Vec::new(),
            verdict: verdict.into(),
            reasons: Vec::new(),
        };
        let candidate = |run_id: &str, model: &str| crate::chisei::eval_run::EvalRunSpec {
            run_id: run_id.into(),
            model: model.into(),
            ..crate::chisei::eval_run::tests::spec(4, 1_000)
        };
        let model = "huggingface/qwen-coder";
        let blocked = export_evaluation_from_dataset_comparison(
            &db,
            identity(),
            &comparison(VERDICT_FAIL, "release-1.4.0"),
            &candidate("release-1.4.0", model),
            Some(DIGEST),
            Some(model),
            &key,
            NOW_MS,
            "root",
        )
        .unwrap();
        assert_eq!(blocked.outcome, EvaluationOutcome::Failed);
        assert!(blocked.eval_suite_id.starts_with("dataset."));
        let passed = export_evaluation_from_dataset_comparison(
            &db,
            identity(),
            &comparison(VERDICT_PASS, "release-1.4.1"),
            &candidate("release-1.4.1", model),
            Some(DIGEST),
            Some(model),
            &key,
            NOW_MS,
            "root",
        )
        .unwrap();
        assert_eq!(passed.outcome, EvaluationOutcome::Passed);
        // The comparison it was decided on is in the export's ledger record.
        let recorded = db
            .list_decisions(&DecisionFilter {
                action: Some(ACTION_EVAL_EXPORT.into()),
                ..DecisionFilter::default()
            })
            .unwrap();
        let kept: RunComparison = serde_json::from_str(
            &recorded
                .iter()
                .find(|decision| decision.evidence["candidate_run_id"] == "release-1.4.0")
                .unwrap()
                .evidence["comparison"],
        )
        .unwrap();
        assert_eq!(kept, comparison(VERDICT_FAIL, "release-1.4.0"));
        // A run of another artifact or model, or one never pinned to an
        // artifact, is not evidence for this release.
        let other = format!("sha256:{}", "ab".repeat(32));
        // A deterministic evaluator (no evaluator model) never ran it either.
        for (unbound, artifact, evaluator) in [
            (
                candidate("release-1.4.2", model),
                Some(other.as_str()),
                Some(model),
            ),
            (candidate("release-1.4.2", model), None, Some(model)),
            (
                candidate("release-1.4.2", "openai/other"),
                Some(DIGEST),
                Some(model),
            ),
            (candidate("release-1.4.2", model), Some(DIGEST), None),
        ] {
            assert!(
                export_evaluation_from_dataset_comparison(
                    &db,
                    identity(),
                    &comparison(VERDICT_PASS, "release-1.4.2"),
                    &unbound,
                    artifact,
                    evaluator,
                    &key,
                    NOW_MS,
                    "root",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn opt_in_profile_without_digest_is_invalid() {
        let profile = opt_in_profile("sales", SERVED_ORIGIN, None);
        assert!(
            identity_from_hosted_profile(&profile)
                .unwrap_err()
                .contains("artifact_digest is required")
        );
        assert!(ModelReleaseEvidenceFailure::matches_message(
            REFUSAL_MISSING
        ));
        assert!(ModelReleaseEvidenceFailure::matches_message(REFUSAL_STALE));
        assert!(ModelReleaseEvidenceFailure::matches_message(
            REFUSAL_INVALID
        ));
    }

    #[test]
    fn opt_in_profile_rejects_a_mismatched_route_digest() {
        let profile = opt_in_profile(
            "sales",
            SERVED_ORIGIN,
            Some(&format!("sha256:{}", "ab".repeat(32))),
        );
        assert!(
            identity_from_hosted_profile(&profile)
                .unwrap_err()
                .contains("must match the profile artifact_digest")
        );
    }

    #[test]
    fn opt_in_profile_refuses_a_foreign_namespace_that_omits_digest() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (key, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let evidence = sign_runtime_evidence(runtime_draft_for(bound_identity()), &key).unwrap();
        ingest_runtime_evidence(&db, evidence, NOW_MS).unwrap();
        let mut foreign = opt_in_profile("other-ns", SERVED_ORIGIN, None);
        foreign.evidence_endpoint = identity().endpoint;
        assert!(
            identity_from_hosted_profile(&foreign)
                .unwrap_err()
                .contains("artifact_digest is required")
        );
        assert_eq!(
            admit_hosted_runtime_evidence(
                &db,
                &foreign,
                Some("hosted.acme/qwen-coder"),
                NOW_MS,
                Some("root")
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
        let other_origin =
            opt_in_profile("other-ns", "https://elsewhere.example.com", Some(DIGEST));
        assert!(
            identity_from_hosted_profile(&other_origin)
                .unwrap_err()
                .contains("evidence_endpoint must match the served endpoint origin")
        );
        assert_eq!(
            admit_hosted_runtime_evidence(
                &db,
                &other_origin,
                Some("hosted.acme/qwen-coder"),
                NOW_MS,
                Some("root")
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }
    #[test]
    fn opt_in_profile_does_not_admit_a_sibling_model() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (key, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let evidence = sign_runtime_evidence(runtime_draft_for(bound_identity()), &key).unwrap();
        ingest_runtime_evidence(&db, evidence, NOW_MS).unwrap();
        let mut profile = opt_in_profile("sales", SERVED_ORIGIN, Some(DIGEST));
        profile.model_patterns = vec!["qwen-*".into()];
        assert_eq!(
            admit_hosted_runtime_evidence(
                &db,
                &profile,
                Some("hosted.acme/qwen-other"),
                NOW_MS,
                Some("root")
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn export_rejects_runs_from_another_suite() {
        use crate::chisei::eval::{CaseResult, Run};
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let eval = EvalStore::with_db(db.clone());
        eval.put_suite(crate::chisei::eval::Suite {
            id: "quality".into(),
            name: "quality".into(),
            description: "pinned".into(),
            cases: vec![crate::chisei::eval::Case {
                id: "c1".into(),
                name: "c1".into(),
                namespace: "sales".into(),
                spec: "ok".into(),
                assertions: Vec::new(),
            }],
        })
        .unwrap();
        eval.put_run(Run {
            id: "base".into(),
            suite_id: "other".into(),
            config_ref: DIGEST.into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "ok".into(),
                result: "ok".into(),
                score: 1,
                reason: "ok".into(),
                elapsed: 1,
            }],
            timestamp: 1,
        })
        .unwrap();
        eval.put_run(Run {
            id: "cand".into(),
            suite_id: "quality".into(),
            config_ref: DIGEST.into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "ok".into(),
                result: "ok".into(),
                score: 1,
                reason: "ok".into(),
                elapsed: 1,
            }],
            timestamp: 2,
        })
        .unwrap();
        let (key, _) = signing_pair();
        let error = export_evaluation_from_compare(
            &db,
            identity(),
            "quality",
            "base",
            "cand",
            "cand",
            &key,
            NOW_MS,
            "root",
        )
        .unwrap_err();
        assert!(error.contains("pinned suite"));
    }

    #[test]
    fn older_runtime_evidence_does_not_replace_newer() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (key, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let mut newer = runtime_draft();
        newer.observed_at = NOW_MS.saturating_add(30_000);
        newer.expires_at = newer.observed_at.saturating_add(RUNTIME_EVIDENCE_TTL_MS);
        newer.health = RuntimeHealth::Unhealthy;
        let newer = sign_runtime_evidence(newer, &key).unwrap();
        ingest_runtime_evidence(&db, newer.clone(), NOW_MS).unwrap();
        ingest_runtime_evidence(
            &db,
            sign_runtime_evidence(runtime_draft(), &key).unwrap(),
            NOW_MS,
        )
        .unwrap();
        let stored = ModelRuntimeEvidence::parse_json(
            &load_runtime_evidence_json(&db, &identity())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(stored.observed_at, newer.observed_at);
        assert_eq!(stored.health, RuntimeHealth::Unhealthy);
    }

    #[test]
    fn future_dated_runtime_evidence_is_not_ingested() {
        use crate::chisei_store::ChiseiStore;
        let db = ChiseiStore::memory();
        let (key, roots) = signing_pair();
        install_trust_roots(&db, roots, NOW_MS).unwrap();
        let mut draft = runtime_draft();
        draft.observed_at = NOW_MS.saturating_add(CLOCK_SKEW_ALLOWANCE_MS + 1);
        draft.expires_at = draft.observed_at.saturating_add(RUNTIME_EVIDENCE_TTL_MS);
        let error =
            ingest_runtime_evidence(&db, sign_runtime_evidence(draft, &key).unwrap(), NOW_MS)
                .unwrap_err();
        assert!(error.contains("stale or not yet valid"));
        assert!(
            load_runtime_evidence_json(&db, &identity())
                .unwrap()
                .is_none()
        );
    }
}
