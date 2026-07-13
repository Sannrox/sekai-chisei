//! Portable, independently verifiable operation attestations.

use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent};
use crate::sekai::attestation::{
    PolicyAttestation, attestation_content_hash, policy_version, replay_decision,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

pub const BUNDLE_VERSION: &str = "shomei.bundle/v3";
pub const CANONICALIZATION_VERSION: &str = "shomei.canonical-json/v1";
pub const VERIFICATION_POLICY_VERSION: &str = "shomei.verify/v1";
pub const DIGEST_ALGORITHM: &str = "sha-256";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDigest {
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub identity: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub signed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSignature {
    pub signer: SignerIdentity,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDisposition {
    Embedded,
    Referenced,
    Redacted,
    Unavailable,
    Uncovered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDeclaration {
    pub event_id: String,
    pub kind: String,
    pub reference: String,
    pub disposition: CoverageDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledArtifact {
    pub reference: String,
    pub digest_algorithm: String,
    pub digest: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub content_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Active,
    Rotated,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub state: KeyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_key_id: Option<String>,
}

impl KeyMetadata {
    pub fn active() -> Self {
        Self {
            state: KeyState::Active,
            valid_from_ms: None,
            valid_until_ms: None,
            revoked_at_ms: None,
            successor_key_id: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if let (Some(from), Some(until)) = (self.valid_from_ms, self.valid_until_ms)
            && from > until
        {
            return Err("key validity window starts after it ends".into());
        }
        if self.state == KeyState::Rotated
            && self
                .successor_key_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err("rotated key metadata requires a successor key id".into());
        }
        if self.state == KeyState::Revoked && self.revoked_at_ms.is_none() {
            return Err("revoked key metadata requires revoked_at_ms".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub bundle_version: String,
    pub receipt_schema_version: String,
    pub verification_policy_version: String,
    pub canonicalization: String,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub receipt_digest: String,
    pub event_chain: Vec<EventDigest>,
    pub receipt: OperationReceipt,
    #[serde(default)]
    pub coverage: Vec<CoverageDeclaration>,
    #[serde(default)]
    pub artifacts: Vec<BundledArtifact>,
    #[serde(default)]
    pub policy_attestations: Vec<PolicyAttestation>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<BundleSignature>,
}

impl AttestationBundle {
    pub fn unsigned(receipt: OperationReceipt) -> Result<Self, String> {
        let receipt_digest = digest_serializable(&receipt)?;
        let event_chain = event_digest_chain(&receipt.events)?;
        Ok(Self {
            bundle_version: BUNDLE_VERSION.into(),
            receipt_schema_version: receipt.version.clone(),
            verification_policy_version: VERIFICATION_POLICY_VERSION.into(),
            canonicalization: CANONICALIZATION_VERSION.into(),
            digest_algorithm: DIGEST_ALGORITHM.into(),
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
            receipt_digest,
            event_chain,
            coverage: coverage_from_receipt(&receipt),
            artifacts: Vec::new(),
            policy_attestations: Vec::new(),
            receipt,
            extensions: BTreeMap::new(),
            signature: None,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut signing_form = self.clone();
        if let Some(signature) = &mut signing_form.signature {
            signature.value.clear();
        }
        canonical_json(&signing_form)
    }

    pub fn sign(
        &mut self,
        signing_key: &SigningKey,
        identity: impl Into<String>,
        key_id: impl Into<String>,
        signed_at_ms: i64,
    ) -> Result<(), String> {
        if self.signature.is_some() {
            return Err("attestation bundle is already signed".into());
        }
        let signer = SignerIdentity {
            identity: required("signer identity", identity.into())?,
            algorithm: SIGNATURE_ALGORITHM.into(),
            key_id: required("signer key id", key_id.into())?,
            public_key: encode_hex(signing_key.verifying_key().as_bytes()),
            signed_at_ms,
        };
        self.signature = Some(BundleSignature {
            signer,
            value: String::new(),
        });
        let signature = signing_key.sign(&self.signing_bytes()?);
        self.signature
            .as_mut()
            .expect("signature metadata exists")
            .value = encode_hex(&signature.to_bytes());
        Ok(())
    }

    pub fn attach_artifact(
        &mut self,
        reference: &str,
        media_type: Option<String>,
        content: &[u8],
    ) -> Result<(), String> {
        if self.signature.is_some() {
            return Err("cannot attach an artifact after signing".into());
        }
        if self
            .artifacts
            .iter()
            .any(|item| item.reference == reference)
        {
            return Err(format!("artifact {reference} is already attached"));
        }
        let matching = self
            .coverage
            .iter_mut()
            .filter(|entry| entry.reference == reference)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(format!(
                "artifact {reference} is not referenced by the receipt"
            ));
        }
        let digest = encode_hex(&Sha256::digest(content));
        for declaration in matching {
            if let Some(expected) = &declaration.expected_digest
                && expected != &digest
            {
                return Err(format!(
                    "artifact {reference} digest does not match receipt reference"
                ));
            }
            declaration.disposition = CoverageDisposition::Embedded;
            declaration.expected_digest = Some(digest.clone());
            declaration.reason = None;
        }
        self.artifacts.push(BundledArtifact {
            reference: reference.into(),
            digest_algorithm: DIGEST_ALGORITHM.into(),
            digest,
            size_bytes: content.len() as u64,
            media_type,
            content_base64: BASE64.encode(content),
        });
        Ok(())
    }

    pub fn attach_policy_attestation(
        &mut self,
        attestation: PolicyAttestation,
    ) -> Result<(), String> {
        if self.signature.is_some() {
            return Err("cannot attach a policy attestation after signing".into());
        }
        if self
            .policy_attestations
            .iter()
            .any(|item| item.id == attestation.id)
        {
            return Err(format!(
                "policy attestation {} is already attached",
                attestation.id
            ));
        }
        if !receipt_links_policy_attestation(&self.receipt, &attestation) {
            return Err(format!(
                "policy attestation {} is not linked by the receipt",
                attestation.id
            ));
        }
        for declaration in self
            .coverage
            .iter_mut()
            .filter(|entry| entry.kind == "policy_attestation" && entry.reference == attestation.id)
        {
            declaration.disposition = CoverageDisposition::Embedded;
            declaration.reason = None;
        }
        self.policy_attestations.push(attestation);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityVerification {
    pub valid: bool,
    pub versions_supported: bool,
    pub receipt_digest_valid: bool,
    pub event_chain_valid: bool,
    pub artifacts_valid: bool,
    pub signer_trusted: bool,
    pub signature_valid: bool,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVerification {
    pub compliant: bool,
    pub receipt_complete: bool,
    pub coverage_complete: bool,
    #[serde(default)]
    pub missing_surfaces: Vec<String>,
    #[serde(default)]
    pub missing_artifacts: Vec<String>,
    #[serde(default)]
    pub coverage: Vec<CoverageDeclaration>,
    pub key: KeyVerification,
    #[serde(default)]
    pub policy_attestations: Vec<PolicyAttestationVerification>,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub integrity: IntegrityVerification,
    pub policy: PolicyVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerification {
    pub state: KeyState,
    pub acceptable_at_verification: bool,
    pub evaluated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_key_id: Option<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAttestationVerification {
    pub id: String,
    pub content_hash_valid: bool,
    pub policy_version_valid: bool,
    pub receipt_linked: bool,
    pub replay_valid: bool,
    pub replayed_decision: String,
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct TrustedKey {
    key: VerifyingKey,
    metadata: KeyMetadata,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedKeyring {
    keys: BTreeMap<(String, String), TrustedKey>,
}

impl TrustedKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(
        &mut self,
        identity: impl Into<String>,
        key_id: impl Into<String>,
        key: VerifyingKey,
    ) -> Result<(), String> {
        self.trust_with_metadata(identity, key_id, key, KeyMetadata::active())
    }

    pub fn trust_with_metadata(
        &mut self,
        identity: impl Into<String>,
        key_id: impl Into<String>,
        key: VerifyingKey,
        metadata: KeyMetadata,
    ) -> Result<(), String> {
        let identity = required("trusted signer identity", identity.into())?;
        let key_id = required("trusted signer key id", key_id.into())?;
        metadata.validate()?;
        match self.keys.entry((identity, key_id)) {
            Entry::Vacant(entry) => {
                entry.insert(TrustedKey { key, metadata });
                Ok(())
            }
            Entry::Occupied(_) => Err("trusted signer key already exists".into()),
        }
    }

    fn get(&self, identity: &str, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(&(identity.to_string(), key_id.to_string()))
    }
}

pub fn verify_bundle(
    bundle: &AttestationBundle,
    trusted_keys: &TrustedKeyring,
) -> VerificationReport {
    verify_bundle_at(bundle, trusted_keys, Utc::now().timestamp_millis())
}

pub fn verify_bundle_at(
    bundle: &AttestationBundle,
    trusted_keys: &TrustedKeyring,
    verification_time_ms: i64,
) -> VerificationReport {
    let mut errors = Vec::new();
    let versions_supported = [
        ("bundle", bundle.bundle_version.as_str(), BUNDLE_VERSION),
        (
            "canonicalization",
            bundle.canonicalization.as_str(),
            CANONICALIZATION_VERSION,
        ),
        (
            "verification policy",
            bundle.verification_policy_version.as_str(),
            VERIFICATION_POLICY_VERSION,
        ),
        (
            "digest algorithm",
            bundle.digest_algorithm.as_str(),
            DIGEST_ALGORITHM,
        ),
        (
            "signature algorithm",
            bundle.signature_algorithm.as_str(),
            SIGNATURE_ALGORITHM,
        ),
        (
            "receipt schema",
            bundle.receipt_schema_version.as_str(),
            OPERATION_RECEIPT_VERSION,
        ),
    ]
    .into_iter()
    .all(|(field, actual, expected)| {
        if actual == expected {
            true
        } else {
            errors.push(format!("unsupported {field} {actual}"));
            false
        }
    }) && if bundle.receipt_schema_version == bundle.receipt.version {
        true
    } else {
        errors.push("receipt schema version does not match embedded receipt".into());
        false
    };

    let receipt_digest_valid = match receipt_digest(&bundle.receipt) {
        Ok(digest) if digest == bundle.receipt_digest => true,
        Ok(_) => {
            errors.push("receipt digest mismatch".into());
            false
        }
        Err(error) => {
            errors.push(format!("receipt digest could not be reproduced: {error}"));
            false
        }
    };
    let event_chain_valid = match receipt_event_chain(&bundle.receipt.events) {
        Ok(chain) if chain == bundle.event_chain => true,
        Ok(_) => {
            errors.push("event digest chain mismatch".into());
            false
        }
        Err(error) => {
            errors.push(format!("event chain could not be reproduced: {error}"));
            false
        }
    };
    let (artifacts_valid, missing_artifacts) = verify_artifacts(bundle, &mut errors);
    let (signer_trusted, signature_valid, key_verification) =
        verify_signature(bundle, trusted_keys, verification_time_ms, &mut errors);
    let valid = versions_supported
        && receipt_digest_valid
        && event_chain_valid
        && artifacts_valid
        && signer_trusted
        && signature_valid
        && errors.is_empty();

    let completeness = bundle.receipt.completeness();
    let receipt_complete = completeness.complete;
    let policy_errors = completeness.errors;
    let missing_surfaces = completeness
        .missing_surfaces
        .into_iter()
        .map(|surface| surface.as_str().to_string())
        .collect::<Vec<_>>();
    let coverage_complete = missing_artifacts.is_empty()
        && bundle.coverage.iter().all(|entry| {
            !matches!(
                entry.disposition,
                CoverageDisposition::Unavailable | CoverageDisposition::Uncovered
            )
        });
    let mut seen_attestations = std::collections::BTreeSet::new();
    let policy_attestations = bundle
        .policy_attestations
        .iter()
        .map(|attestation| {
            let mut verification = verify_policy_attestation(&bundle.receipt, attestation);
            if !seen_attestations.insert(attestation.id.as_str()) {
                verification.valid = false;
                verification
                    .errors
                    .push("duplicate policy attestation id".into());
            }
            verification
        })
        .collect::<Vec<_>>();
    let policy_attestations_valid = policy_attestations.iter().all(|item| item.valid);
    VerificationReport {
        integrity: IntegrityVerification {
            valid,
            versions_supported,
            receipt_digest_valid,
            event_chain_valid,
            artifacts_valid,
            signer_trusted,
            signature_valid,
            errors,
        },
        policy: PolicyVerification {
            compliant: receipt_complete
                && coverage_complete
                && key_verification.acceptable_at_verification
                && policy_attestations_valid
                && missing_surfaces.is_empty()
                && policy_errors.is_empty(),
            receipt_complete,
            coverage_complete,
            missing_surfaces,
            missing_artifacts,
            coverage: bundle.coverage.clone(),
            key: key_verification,
            policy_attestations,
            errors: policy_errors,
        },
    }
}

fn coverage_from_receipt(receipt: &OperationReceipt) -> Vec<CoverageDeclaration> {
    let mut coverage = receipt
        .events
        .iter()
        .flat_map(|event| {
            event.references.iter().map(|reference| {
                let (disposition, reason) = if reference.omitted {
                    (
                        CoverageDisposition::Redacted,
                        reference
                            .omission_reason
                            .clone()
                            .or_else(|| Some("content was redacted".into())),
                    )
                } else if reference.content_hash.is_some() {
                    (CoverageDisposition::Referenced, None)
                } else {
                    (
                        CoverageDisposition::Unavailable,
                        Some("reference has no content digest or embedded material".into()),
                    )
                };
                CoverageDeclaration {
                    event_id: event.event_id.clone(),
                    kind: reference.kind.clone(),
                    reference: reference.reference.clone(),
                    disposition,
                    expected_digest: reference.content_hash.clone(),
                    reason,
                }
            })
        })
        .collect::<Vec<_>>();
    coverage.extend(receipt.events.iter().filter_map(|event| {
        let id = event.attributes.get("attestation_id")?;
        let hash = event.attributes.get("attestation_hash")?;
        Some(CoverageDeclaration {
            event_id: event.event_id.clone(),
            kind: "policy_attestation".into(),
            reference: id.clone(),
            disposition: CoverageDisposition::Referenced,
            expected_digest: Some(hash.clone()),
            reason: None,
        })
    }));
    coverage.extend(
        receipt
            .uncovered_surfaces
            .iter()
            .map(|uncovered| CoverageDeclaration {
                event_id: String::new(),
                kind: "receipt_surface".into(),
                reference: uncovered.surface.as_str().into(),
                disposition: CoverageDisposition::Uncovered,
                expected_digest: None,
                reason: Some(uncovered.reason.clone()),
            }),
    );
    coverage
}

fn verify_artifacts(bundle: &AttestationBundle, errors: &mut Vec<String>) -> (bool, Vec<String>) {
    let mut valid = true;
    let mut missing = Vec::new();
    let expected_coverage = coverage_from_receipt(&bundle.receipt);
    let mut matched = vec![false; bundle.coverage.len()];
    for expected in &expected_coverage {
        let Some((index, _)) = bundle.coverage.iter().enumerate().find(|(index, actual)| {
            !matched[*index]
                && actual.event_id == expected.event_id
                && actual.kind == expected.kind
                && actual.reference == expected.reference
                && (actual.expected_digest == expected.expected_digest
                    || (actual.disposition == CoverageDisposition::Embedded
                        && expected.expected_digest.is_none()))
                && (actual.disposition == expected.disposition
                    || (actual.disposition == CoverageDisposition::Embedded
                        && matches!(
                            expected.disposition,
                            CoverageDisposition::Referenced | CoverageDisposition::Unavailable
                        )))
        }) else {
            errors.push(format!(
                "receipt reference {} lacks a matching coverage declaration",
                expected.reference
            ));
            valid = false;
            continue;
        };
        matched[index] = true;
    }
    if matched.iter().any(|matched| !matched) {
        errors.push("bundle contains coverage declarations not present in the receipt".into());
        valid = false;
    }
    let artifacts = bundle
        .artifacts
        .iter()
        .map(|artifact| (artifact.reference.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if artifacts.len() != bundle.artifacts.len() {
        errors.push("bundle contains duplicate artifact references".into());
        valid = false;
    }
    for declaration in &bundle.coverage {
        match declaration.disposition {
            CoverageDisposition::Embedded => {
                if declaration.kind == "policy_attestation" {
                    if !bundle.policy_attestations.iter().any(|attestation| {
                        attestation.id == declaration.reference
                            && Some(&attestation.content_hash)
                                == declaration.expected_digest.as_ref()
                    }) {
                        missing.push(declaration.reference.clone());
                        valid = false;
                    }
                    continue;
                }
                let Some(artifact) = artifacts.get(declaration.reference.as_str()) else {
                    missing.push(declaration.reference.clone());
                    valid = false;
                    continue;
                };
                if artifact.digest_algorithm != DIGEST_ALGORITHM {
                    errors.push(format!(
                        "artifact {} uses unsupported digest algorithm {}",
                        artifact.reference, artifact.digest_algorithm
                    ));
                    valid = false;
                    continue;
                }
                let content = match BASE64.decode(&artifact.content_base64) {
                    Ok(content) => content,
                    Err(_) => {
                        errors.push(format!(
                            "artifact {} content is not valid base64",
                            artifact.reference
                        ));
                        valid = false;
                        continue;
                    }
                };
                let digest = encode_hex(&Sha256::digest(&content));
                if digest != artifact.digest
                    || declaration.expected_digest.as_ref() != Some(&digest)
                    || artifact.size_bytes != content.len() as u64
                {
                    errors.push(format!(
                        "artifact {} digest or size mismatch",
                        artifact.reference
                    ));
                    valid = false;
                }
            }
            CoverageDisposition::Referenced => missing.push(declaration.reference.clone()),
            CoverageDisposition::Redacted
            | CoverageDisposition::Unavailable
            | CoverageDisposition::Uncovered => {}
        }
    }
    for artifact in &bundle.artifacts {
        if !bundle.coverage.iter().any(|declaration| {
            declaration.reference == artifact.reference
                && declaration.disposition == CoverageDisposition::Embedded
        }) {
            errors.push(format!(
                "artifact {} has no embedded coverage declaration",
                artifact.reference
            ));
            valid = false;
        }
    }
    missing.sort();
    missing.dedup();
    (valid, missing)
}

fn verify_signature(
    bundle: &AttestationBundle,
    trusted_keys: &TrustedKeyring,
    verification_time_ms: i64,
    errors: &mut Vec<String>,
) -> (bool, bool, KeyVerification) {
    let unknown_key = || KeyVerification {
        state: KeyState::Unknown,
        acceptable_at_verification: false,
        evaluated_at_ms: verification_time_ms,
        successor_key_id: None,
        errors: vec!["key state is unknown".into()],
    };
    let Some(signature) = &bundle.signature else {
        errors.push("bundle is unsigned".into());
        return (false, false, unknown_key());
    };
    if signature.signer.algorithm != SIGNATURE_ALGORITHM {
        errors.push(format!(
            "unsupported signer algorithm {}",
            signature.signer.algorithm
        ));
        return (false, false, unknown_key());
    }
    let public_key = match decode_hex::<32>("signer public key", &signature.signer.public_key) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return (false, false, unknown_key());
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("invalid signer public key: {error}"));
            return (false, false, unknown_key());
        }
    };
    let Some(trusted_key) = trusted_keys.get(&signature.signer.identity, &signature.signer.key_id)
    else {
        errors.push(format!(
            "signer {} key {} is not trusted",
            signature.signer.identity, signature.signer.key_id
        ));
        return (false, false, unknown_key());
    };
    let key_verification = verify_key_metadata(&trusted_key.metadata, verification_time_ms);
    if trusted_key.key != verifying_key {
        errors.push("embedded signer public key does not match trusted key".into());
        return (false, false, key_verification);
    }
    let signature_bytes = match decode_hex::<64>("bundle signature", &signature.value) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return (true, false, key_verification);
        }
    };
    let signing_bytes = match bundle.signing_bytes() {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("signed bytes could not be reproduced: {error}"));
            return (true, false, key_verification);
        }
    };
    if verifying_key
        .verify_strict(&signing_bytes, &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        errors.push("bundle signature verification failed".into());
        return (true, false, key_verification);
    }
    (true, true, key_verification)
}

fn verify_key_metadata(metadata: &KeyMetadata, verification_time_ms: i64) -> KeyVerification {
    let mut errors = Vec::new();
    match metadata.state {
        KeyState::Active => {}
        KeyState::Rotated => {
            errors.push("rotated key requires independently trusted signing-time evidence".into())
        }
        KeyState::Revoked => {
            errors.push("revoked key requires independently trusted signing-time evidence".into())
        }
        KeyState::Unknown => errors.push("key state is unknown".into()),
    }
    if metadata
        .valid_from_ms
        .is_some_and(|valid_from| verification_time_ms < valid_from)
    {
        errors.push("key is not yet valid at verification time".into());
    }
    if metadata
        .valid_until_ms
        .is_some_and(|valid_until| verification_time_ms > valid_until)
    {
        errors.push("key is expired at verification time".into());
    }
    if metadata
        .revoked_at_ms
        .is_some_and(|revoked_at| verification_time_ms >= revoked_at)
    {
        errors.push("key is revoked at verification time".into());
    }
    KeyVerification {
        state: metadata.state,
        acceptable_at_verification: errors.is_empty(),
        evaluated_at_ms: verification_time_ms,
        successor_key_id: metadata.successor_key_id.clone(),
        errors,
    }
}

fn receipt_links_policy_attestation(
    receipt: &OperationReceipt,
    attestation: &PolicyAttestation,
) -> bool {
    receipt.events.iter().any(|event| {
        event.references.iter().any(|reference| {
            reference.kind == "policy_attestation"
                && reference.reference == attestation.id
                && reference.content_hash.as_deref() == Some(attestation.content_hash.as_str())
        }) || (event.attributes.get("attestation_id") == Some(&attestation.id)
            && event.attributes.get("attestation_hash") == Some(&attestation.content_hash))
    })
}

fn verify_policy_attestation(
    receipt: &OperationReceipt,
    attestation: &PolicyAttestation,
) -> PolicyAttestationVerification {
    let mut errors = Vec::new();
    let content_hash_valid = attestation_content_hash(attestation) == attestation.content_hash;
    if !content_hash_valid {
        errors.push("policy attestation content hash mismatch".into());
    }
    let policy_version_valid =
        policy_version(&attestation.policy_snapshot) == attestation.policy_version;
    if !policy_version_valid {
        errors.push("policy attestation version hash mismatch".into());
    }
    let receipt_linked = receipt_links_policy_attestation(receipt, attestation);
    if !receipt_linked {
        errors.push("policy attestation is not linked by the receipt".into());
    }
    let (replay_valid, replayed_decision) = replay_decision(attestation);
    if !replay_valid {
        errors.push(format!(
            "policy replay produced {replayed_decision}, expected {}",
            attestation.decision
        ));
    }
    PolicyAttestationVerification {
        id: attestation.id.clone(),
        content_hash_valid,
        policy_version_valid,
        receipt_linked,
        replay_valid,
        replayed_decision,
        valid: errors.is_empty(),
        errors,
    }
}

/// Canonical bytes for a complete Shomei bundle.
pub fn canonical_bundle_bytes(bundle: &AttestationBundle) -> Result<Vec<u8>, String> {
    canonical_json(bundle)
}

/// Stable digest for the supported operation-receipt schema.
pub fn receipt_digest(receipt: &OperationReceipt) -> Result<String, String> {
    digest_serializable(receipt)
}

/// Ordered causal digest chain for the supported receipt-event schema.
pub fn receipt_event_chain(events: &[OperationReceiptEvent]) -> Result<Vec<EventDigest>, String> {
    event_digest_chain(events)
}

/// Canonical JSON used by Shomei v1. Object keys are sorted lexicographically,
/// arrays retain their declared order, and strings use serde_json escaping.
/// Shomei v1 bundle schemas contain integer numeric fields only; extensions
/// use `serde_json::Value`, which cannot represent non-finite numbers. Keeping
/// this boundary private prevents callers from hashing arbitrary Rust floats
/// that `serde_json` would normalize before the validation pass.
pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    reject_floats(&value)?;
    serde_json::to_vec(&sort_json(value)).map_err(|error| error.to_string())
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(encode_hex(&Sha256::digest(canonical_json(value)?)))
}

pub(crate) fn event_digest_chain(
    events: &[OperationReceiptEvent],
) -> Result<Vec<EventDigest>, String> {
    let mut previous: Option<String> = None;
    let mut chain = Vec::with_capacity(events.len());
    for event in events {
        let digest = digest_serializable(&(&previous, event))?;
        chain.push(EventDigest {
            event_id: event.event_id.clone(),
            previous_digest: previous,
            digest: digest.clone(),
        });
        previous = Some(digest);
    }
    Ok(chain)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}

fn reject_floats(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(number) if number.is_f64() => {
            Err("floating-point numbers are not supported by shomei.canonical-json/v1".into())
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(format!("{field} must contain {} hexadecimal bytes", N));
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{field} is not hexadecimal"))?;
        decoded[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{field} is not hexadecimal"))?;
    }
    Ok(decoded)
}

fn required(field: &str, value: String) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, ReceiptEventKind};

    fn signed_bundle() -> AttestationBundle {
        let mut bundle = AttestationBundle::unsigned(receipt()).unwrap();
        bundle
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        bundle
    }

    fn trusted_keys() -> TrustedKeyring {
        let mut keys = TrustedKeyring::new();
        keys.trust(
            "node:test",
            "key-1",
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )
        .unwrap();
        keys
    }

    fn receipt() -> OperationReceipt {
        let mut events = Vec::new();
        for (id, parent, kind) in [
            ("intent", None, ReceiptEventKind::IntentRecorded),
            ("policy", Some("intent"), ReceiptEventKind::PolicyDecided),
            ("route", Some("policy"), ReceiptEventKind::RouteSelected),
            ("budget", Some("route"), ReceiptEventKind::BudgetDecided),
            ("outcome", Some("budget"), ReceiptEventKind::OutcomeRecorded),
        ] {
            events.push(OperationReceiptEvent {
                event_id: id.into(),
                operation_id: "op-1".into(),
                parent_event_id: parent.map(str::to_string),
                timestamp_ms: 1,
                kind,
                surface: kind.surface(),
                actor: "agent:test".into(),
                references: vec![],
                attributes: BTreeMap::new(),
            });
        }
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "default".into(),
            operation_class: "native_execution".into(),
            initiating_actor: "agent:test".into(),
            schema_version: "schema-v1".into(),
            policy_version: "policy-v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(2),
            events,
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn canonical_encoding_and_digests_are_stable() {
        let first = AttestationBundle::unsigned(receipt()).unwrap();
        let second = AttestationBundle::unsigned(receipt()).unwrap();
        assert_eq!(
            receipt_digest(&first.receipt).unwrap(),
            first.receipt_digest
        );
        assert_eq!(
            receipt_event_chain(&first.receipt.events).unwrap(),
            first.event_chain
        );
        assert_eq!(
            canonical_bundle_bytes(&first).unwrap(),
            canonical_json(&first).unwrap()
        );
        assert_eq!(first.receipt_digest, second.receipt_digest);
        assert_eq!(first.event_chain, second.event_chain);
        assert_eq!(
            first.signing_bytes().unwrap(),
            second.signing_bytes().unwrap()
        );
    }

    #[test]
    fn event_reordering_changes_the_chain() {
        let original = AttestationBundle::unsigned(receipt()).unwrap();
        let mut reordered = receipt();
        reordered.events.swap(1, 2);
        let reordered = AttestationBundle::unsigned(reordered).unwrap();
        assert_ne!(original.event_chain, reordered.event_chain);
        assert_ne!(original.receipt_digest, reordered.receipt_digest);
    }

    #[test]
    fn canonical_object_keys_are_sorted() {
        let value = serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}});
        assert_eq!(
            String::from_utf8(canonical_json(&value).unwrap()).unwrap(),
            r#"{"a":{"b":3,"y":2},"z":1}"#
        );
    }

    #[test]
    fn finite_float_values_are_rejected() {
        assert!(canonical_json(&serde_json::json!({"score": 1.5})).is_err());
    }

    #[test]
    fn complete_native_receipt_signs_and_verifies_offline() {
        let report = verify_bundle(&signed_bundle(), &trusted_keys());
        assert!(report.integrity.valid, "{:?}", report.integrity.errors);
        assert!(report.policy.compliant, "{:?}", report.policy.errors);
    }

    #[test]
    fn modified_removed_inserted_and_reordered_events_fail_integrity() {
        let bundle = signed_bundle();
        let mut variants = Vec::new();

        let mut modified = bundle.clone();
        modified.receipt.events[1].actor = "attacker".into();
        variants.push(modified);

        let mut removed = bundle.clone();
        removed.receipt.events.remove(1);
        variants.push(removed);

        let mut inserted = bundle.clone();
        let mut event = inserted.receipt.events[1].clone();
        event.event_id = "inserted".into();
        inserted.receipt.events.insert(2, event);
        variants.push(inserted);

        let mut reordered = bundle;
        reordered.receipt.events.swap(1, 2);
        variants.push(reordered);

        for variant in variants {
            assert!(!verify_bundle(&variant, &trusted_keys()).integrity.valid);
        }
    }

    #[test]
    fn signer_identity_is_covered_by_the_signature() {
        let mut bundle = signed_bundle();
        bundle.signature.as_mut().unwrap().signer.key_id = "key-2".into();
        assert!(
            !verify_bundle(&bundle, &trusted_keys())
                .integrity
                .signature_valid
        );
    }

    #[test]
    fn embedded_key_is_not_a_trust_anchor() {
        let report = verify_bundle(&signed_bundle(), &TrustedKeyring::new());
        assert!(!report.integrity.signer_trusted);
        assert!(!report.integrity.valid);
    }

    #[test]
    fn unsupported_receipt_schema_fails_integrity() {
        let mut bundle = AttestationBundle::unsigned(receipt()).unwrap();
        bundle.receipt.version = "operation.receipt/v2".into();
        bundle.receipt_schema_version = bundle.receipt.version.clone();
        bundle.receipt_digest = receipt_digest(&bundle.receipt).unwrap();
        bundle
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        let report = verify_bundle(&bundle, &trusted_keys());
        assert!(!report.integrity.versions_supported);
        assert!(!report.integrity.valid);
    }

    #[test]
    fn legacy_bundle_version_is_rejected_after_signed_schema_change() {
        let mut bundle = signed_bundle();
        bundle.bundle_version = "shomei.bundle/v1".into();
        let report = verify_bundle(&bundle, &trusted_keys());
        assert!(!report.integrity.versions_supported);
        assert!(!report.integrity.valid);
    }

    #[test]
    fn duplicate_trust_entry_preserves_original_key() {
        let mut keys = trusted_keys();
        assert!(
            keys.trust(
                "node:test",
                "key-1",
                SigningKey::from_bytes(&[8; 32]).verifying_key(),
            )
            .is_err()
        );
        assert!(verify_bundle(&signed_bundle(), &keys).integrity.valid);
    }

    #[test]
    fn embedded_artifact_is_verified_and_missing_reference_is_reported() {
        let mut source = receipt();
        source.events[0]
            .references
            .push(crate::chisei::receipt::GovernedReference {
                kind: "input".into(),
                reference: "artifact://input".into(),
                content_hash: Some(encode_hex(&Sha256::digest(b"evidence"))),
                disclosed_fields: vec![],
                omitted: false,
                omission_reason: None,
            });
        let mut missing = AttestationBundle::unsigned(source.clone()).unwrap();
        missing
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        let missing_report = verify_bundle(&missing, &trusted_keys());
        assert!(missing_report.integrity.valid);
        assert_eq!(
            missing_report.policy.missing_artifacts,
            ["artifact://input"]
        );
        assert!(!missing_report.policy.compliant);

        let mut embedded = AttestationBundle::unsigned(source).unwrap();
        embedded
            .attach_artifact("artifact://input", Some("text/plain".into()), b"evidence")
            .unwrap();
        embedded
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        let report = verify_bundle(&embedded, &trusted_keys());
        assert!(report.integrity.valid, "{:?}", report.integrity.errors);
        assert!(report.policy.compliant);

        let mut tampered = embedded;
        tampered.artifacts[0].content_base64 = BASE64.encode(b"tampered");
        let report = verify_bundle(&tampered, &trusted_keys());
        assert!(!report.integrity.artifacts_valid);
        assert!(!report.integrity.valid);
    }

    #[test]
    fn omitted_and_uncovered_content_are_declared() {
        let mut source = receipt();
        source.events[0]
            .references
            .push(crate::chisei::receipt::GovernedReference {
                kind: "context".into(),
                reference: "object://secret".into(),
                content_hash: None,
                disclosed_fields: vec![],
                omitted: true,
                omission_reason: Some("private field".into()),
            });
        source
            .uncovered_surfaces
            .push(crate::chisei::receipt::UncoveredSurface {
                surface: crate::chisei::receipt::ReceiptSurface::Action,
                reason: "external executor".into(),
            });
        let bundle = AttestationBundle::unsigned(source).unwrap();
        assert!(bundle.coverage.iter().any(|entry| {
            entry.disposition == CoverageDisposition::Redacted
                && entry.reference == "object://secret"
        }));
        assert!(bundle.coverage.iter().any(|entry| {
            entry.disposition == CoverageDisposition::Uncovered && entry.reference == "action"
        }));
    }

    #[test]
    fn key_lifecycle_is_evaluated_at_verification_time() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut revoked = TrustedKeyring::new();
        revoked
            .trust_with_metadata(
                "node:test",
                "key-1",
                key.verifying_key(),
                KeyMetadata {
                    state: KeyState::Revoked,
                    valid_from_ms: Some(0),
                    valid_until_ms: None,
                    revoked_at_ms: Some(20),
                    successor_key_id: Some("key-2".into()),
                },
            )
            .unwrap();
        let before_revocation = verify_bundle(&signed_bundle(), &revoked);
        assert!(!before_revocation.policy.key.acceptable_at_verification);

        let mut signed_after = AttestationBundle::unsigned(receipt()).unwrap();
        signed_after.sign(&key, "node:test", "key-1", 20).unwrap();
        let after_revocation = verify_bundle(&signed_after, &revoked);
        assert!(!after_revocation.policy.key.acceptable_at_verification);
        assert!(!after_revocation.policy.compliant);

        let mut unknown = TrustedKeyring::new();
        unknown
            .trust_with_metadata(
                "node:test",
                "key-1",
                key.verifying_key(),
                KeyMetadata {
                    state: KeyState::Unknown,
                    valid_from_ms: None,
                    valid_until_ms: None,
                    revoked_at_ms: None,
                    successor_key_id: None,
                },
            )
            .unwrap();
        let report = verify_bundle(&signed_bundle(), &unknown);
        assert_eq!(report.policy.key.state, KeyState::Unknown);
        assert!(!report.policy.key.acceptable_at_verification);

        let mut expired = TrustedKeyring::new();
        expired
            .trust_with_metadata(
                "node:test",
                "key-1",
                key.verifying_key(),
                KeyMetadata {
                    state: KeyState::Active,
                    valid_from_ms: Some(0),
                    valid_until_ms: Some(20),
                    revoked_at_ms: None,
                    successor_key_id: None,
                },
            )
            .unwrap();
        let backdated = verify_bundle_at(&signed_bundle(), &expired, 30);
        assert!(!backdated.policy.key.acceptable_at_verification);
        assert_eq!(backdated.policy.key.evaluated_at_ms, 30);

        let mut mislabeled_revoked = TrustedKeyring::new();
        mislabeled_revoked
            .trust_with_metadata(
                "node:test",
                "key-1",
                key.verifying_key(),
                KeyMetadata {
                    state: KeyState::Active,
                    valid_from_ms: None,
                    valid_until_ms: None,
                    revoked_at_ms: Some(20),
                    successor_key_id: None,
                },
            )
            .unwrap();
        assert!(
            !verify_bundle_at(&signed_bundle(), &mislabeled_revoked, 30)
                .policy
                .key
                .acceptable_at_verification
        );
    }

    #[test]
    fn linked_policy_attestation_replays_offline() {
        use crate::sekai::action::RiskClass;
        use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
        use crate::sekai::attestation::{ActionAttestationInput, build_action_attestation};

        let policy = ActionPolicy::allow_all("default");
        let attestation = build_action_attestation(ActionAttestationInput {
            decision_id: "decision-1",
            policy: &policy,
            action: "read_object",
            actor: "agent:test",
            risk: RiskClass::Read,
            namespace: "default",
            decision: ActionDecision::Allow,
            created: 5,
        });
        let mut attribute_linked = receipt();
        attribute_linked.events[1]
            .attributes
            .insert("attestation_id".into(), attestation.id.clone());
        attribute_linked.events[1]
            .attributes
            .insert("attestation_hash".into(), attestation.content_hash.clone());
        let mut missing = AttestationBundle::unsigned(attribute_linked).unwrap();
        missing
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        let missing_report = verify_bundle(&missing, &trusted_keys());
        assert_eq!(
            missing_report.policy.missing_artifacts,
            [attestation.id.clone()]
        );
        assert!(!missing_report.policy.compliant);

        let mut source = receipt();
        source.events[1]
            .references
            .push(crate::chisei::receipt::GovernedReference {
                kind: "policy_attestation".into(),
                reference: attestation.id.clone(),
                content_hash: Some(attestation.content_hash.clone()),
                disclosed_fields: vec![],
                omitted: false,
                omission_reason: None,
            });
        let mut bundle = AttestationBundle::unsigned(source).unwrap();
        bundle.attach_policy_attestation(attestation).unwrap();
        bundle
            .sign(&SigningKey::from_bytes(&[7; 32]), "node:test", "key-1", 10)
            .unwrap();
        let report = verify_bundle(&bundle, &trusted_keys());
        assert!(report.integrity.valid, "{:?}", report.integrity.errors);
        assert!(report.policy.compliant, "{:?}", report.policy);
        assert!(report.policy.policy_attestations[0].replay_valid);

        let mut altered = bundle;
        altered.policy_attestations[0].decision = "deny".into();
        let report = verify_bundle(&altered, &trusted_keys());
        assert!(!report.integrity.valid);
        assert!(!report.policy.policy_attestations[0].valid);
    }
}
