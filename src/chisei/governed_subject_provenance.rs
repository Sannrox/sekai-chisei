//! Authenticated, Tenkai-compatible provenance for governed software releases.
//!
//! This is deliberately not a generic receipt-signing facility. It implements
//! the single compiled `example.governed-subject-receipt/v1` consumer contract.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const PROFILE: &str = "example.governed-subject-receipt/v1";
pub const ISSUER: &str = "sekai-chisei";
pub const RECEIPT_SCHEMA: &str = "chisei.governed-subject-receipt/v1";
pub const TRUST_ROOT_VERSION: u32 = 1;
pub const MAX_EXPORT_ID_BYTES: usize = 256;
pub const MAX_ENVELOPE_TTL_MS: i64 = 31 * 24 * 60 * 60 * 1_000;
const SIGNING_DOMAIN: &[u8] = b"TENKAI-RELEASE-PROVENANCE-V1\0";
const CONTENT_DOMAIN: &[u8] = b"TENKAI-RELEASE-PROVENANCE-CONTENT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedReference {
    pub kind: String,
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEnvelope {
    pub profile: String,
    pub issuer: String,
    pub issuer_key_id: String,
    pub subject: String,
    pub content_digest: String,
    pub decision: String,
    pub receipt_schema: String,
    pub receipt_digest: String,
    pub governed_references: Vec<GovernedReference>,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequestBinding {
    pub actor: String,
    pub export_id: String,
    pub operation_id: String,
    pub expected_subject_identity: String,
    pub expected_subject_content_digest: String,
    pub expected_manifest_digest: String,
    pub expected_artifact_digest: String,
    pub expected_receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRecord {
    pub binding_digest: String,
    pub namespace: String,
    pub envelope: ProvenanceEnvelope,
    pub public_key: String,
    pub created_at_ms: i64,
}

pub fn validate_export_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_EXPORT_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "export_id must be non-empty, canonical, and at most {MAX_EXPORT_ID_BYTES} bytes"
        ));
    }
    Ok(())
}

pub fn validate_digest(label: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{label} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

pub fn binding_digest(binding: &ExportRequestBinding) -> Result<String, String> {
    validate_export_id(&binding.export_id)?;
    for (label, value) in [
        ("actor", binding.actor.as_str()),
        ("operation_id", binding.operation_id.as_str()),
        (
            "expected_subject_identity",
            binding.expected_subject_identity.as_str(),
        ),
    ] {
        if value.is_empty()
            || value.trim() != value
            || value.len() > 512
            || value.chars().any(char::is_control)
        {
            return Err(format!("{label} is not a bounded opaque identifier"));
        }
    }
    for (label, value) in [
        (
            "expected_subject_content_digest",
            binding.expected_subject_content_digest.as_str(),
        ),
        (
            "expected_manifest_digest",
            binding.expected_manifest_digest.as_str(),
        ),
        (
            "expected_artifact_digest",
            binding.expected_artifact_digest.as_str(),
        ),
        (
            "expected_receipt_digest",
            binding.expected_receipt_digest.as_str(),
        ),
    ] {
        validate_digest(label, value)?;
    }
    let bytes = serde_json::to_vec(binding).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub fn release_content_digest(
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<String, String> {
    validate_digest("manifest digest", manifest_digest)?;
    validate_digest("artifact digest", artifact_digest)?;
    let manifest = manifest_digest
        .strip_prefix("sha256:")
        .expect("validated digest prefix");
    let artifact = artifact_digest
        .strip_prefix("sha256:")
        .expect("validated digest prefix");
    let mut canonical = CONTENT_DOMAIN.to_vec();
    push_bytes(&mut canonical, manifest.as_bytes());
    push_bytes(&mut canonical, artifact.as_bytes());
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

pub fn signing_key_from_hex(value: &str) -> Result<ed25519_dalek::SigningKey, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("provenance signing key must be a 32-byte hexadecimal Ed25519 seed".into());
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        seed[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| "invalid signing key encoding")?,
            16,
        )
        .map_err(|_| "invalid signing key encoding")?;
    }
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(public_key))
}

impl ProvenanceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        signing_key: &ed25519_dalek::SigningKey,
        subject: String,
        content_digest: String,
        receipt_digest: String,
        operation_id: String,
        observed_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, String> {
        let mut envelope = Self {
            profile: PROFILE.into(),
            issuer: ISSUER.into(),
            issuer_key_id: key_id(&signing_key.verifying_key().to_bytes()),
            subject,
            content_digest,
            decision: "allow".into(),
            receipt_schema: RECEIPT_SCHEMA.into(),
            receipt_digest: receipt_digest.clone(),
            governed_references: vec![GovernedReference {
                kind: "operation".into(),
                id: operation_id,
                digest: receipt_digest,
            }],
            observed_at_unix_ms,
            expires_at_unix_ms,
            signature: String::new(),
        };
        envelope.validate_structure()?;
        envelope.signature = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(&envelope.signed_bytes()?).to_bytes());
        Ok(envelope)
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), String> {
        self.validate_structure()?;
        if self.expires_at_unix_ms <= now_ms {
            return Err("governed-subject provenance is stale".into());
        }
        Ok(())
    }

    pub fn validate_structure(&self) -> Result<(), String> {
        if self.profile != PROFILE
            || self.issuer != ISSUER
            || self.decision != "allow"
            || self.receipt_schema != RECEIPT_SCHEMA
        {
            return Err("unsupported governed-subject provenance contract".into());
        }
        validate_digest("issuer_key_id", &self.issuer_key_id)?;
        validate_digest("content_digest", &self.content_digest)?;
        validate_digest("receipt_digest", &self.receipt_digest)?;
        if self.subject.is_empty()
            || self.subject.len() > 256
            || self.subject.chars().any(char::is_control)
            || self.subject.contains("://")
            || self.subject.contains('/')
            || self.subject.contains('\\')
        {
            return Err("provenance subject is not a bounded opaque identifier".into());
        }
        if self.governed_references.len() != 1 {
            return Err("provenance must contain exactly one operation reference".into());
        }
        let reference = &self.governed_references[0];
        if reference.kind != "operation"
            || reference.id.is_empty()
            || reference.id.len() > 256
            || reference.id.chars().any(char::is_control)
            || reference.id.contains("://")
            || reference.id.contains('/')
            || reference.id.contains('\\')
            || reference.digest != self.receipt_digest
        {
            return Err("provenance operation reference is invalid".into());
        }
        if self.observed_at_unix_ms <= 0
            || self.expires_at_unix_ms < self.observed_at_unix_ms
            || self.expires_at_unix_ms - self.observed_at_unix_ms > MAX_ENVELOPE_TTL_MS
        {
            return Err("provenance freshness interval is invalid".into());
        }
        if !self.signature.is_empty() {
            let signature = base64::engine::general_purpose::STANDARD
                .decode(&self.signature)
                .map_err(|_| "provenance signature is not valid base64")?;
            if signature.len() != 64 {
                return Err("provenance signature must contain 64 bytes".into());
            }
        }
        Ok(())
    }

    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_structure()?;
        let mut output = SIGNING_DOMAIN.to_vec();
        for value in [
            &self.profile,
            &self.issuer,
            &self.issuer_key_id,
            &self.subject,
            &self.content_digest,
            &self.decision,
            &self.receipt_schema,
            &self.receipt_digest,
        ] {
            push_bytes(&mut output, value.as_bytes());
        }
        output.extend_from_slice(&(self.governed_references.len() as u64).to_be_bytes());
        for reference in &self.governed_references {
            push_bytes(&mut output, reference.kind.as_bytes());
            push_bytes(&mut output, reference.id.as_bytes());
            push_bytes(&mut output, reference.digest.as_bytes());
        }
        output.extend_from_slice(&self.observed_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<String, String> {
        let mut canonical = self.signed_bytes()?;
        push_bytes(&mut canonical, self.signature.as_bytes());
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }

    pub fn verify(&self, public_key: &[u8; 32], now_ms: i64) -> Result<(), String> {
        self.validate(now_ms)?;
        if self.issuer_key_id != key_id(public_key) {
            return Err("provenance issuer key id does not match its public key".into());
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|error| error.to_string())?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|_| "provenance signature is not valid base64")?;
        let signature =
            ed25519_dalek::Signature::from_slice(&signature).map_err(|error| error.to_string())?;
        verifying_key
            .verify(&self.signed_bytes()?, &signature)
            .map_err(|_| "provenance issuer signature is invalid".into())
    }
}

impl ExportRecord {
    pub fn from_json(value: &str) -> Result<Self, String> {
        let record: Self =
            serde_json::from_str(value).map_err(|_| "stored provenance export is invalid")?;
        record.validate()?;
        Ok(record)
    }

    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_digest("stored export binding digest", &self.binding_digest)?;
        if self.namespace.is_empty()
            || self.namespace.len() > 256
            || self.namespace.chars().any(char::is_control)
        {
            return Err("stored provenance namespace is invalid".into());
        }
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|_| "stored provenance public key is not valid base64")?;
        let public_key: &[u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| "stored provenance public key must contain 32 bytes")?;
        self.envelope
            .verify(public_key, self.envelope.observed_at_unix_ms)
    }
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn release_binding_matches_tenkai_contract() {
        assert_eq!(
            release_content_digest(&digest('a'), &digest('b')).unwrap(),
            "sha256:f7e2664c5c737c44d9c4de577d7e6b04fcc0820f6fd893987d5377088ba85ef5"
        );
    }

    #[test]
    fn signed_envelope_is_strict_and_every_binding_is_authenticated() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let envelope = ProvenanceEnvelope::issue(
            &key,
            "subject-1".into(),
            digest('1'),
            digest('2'),
            "operation-1".into(),
            1_000,
            2_000,
        )
        .unwrap();
        envelope
            .verify(&key.verifying_key().to_bytes(), 1_500)
            .unwrap();

        for mutate in [
            |value: &mut ProvenanceEnvelope| value.subject = "subject-2".into(),
            |value: &mut ProvenanceEnvelope| value.content_digest = digest('3'),
            |value: &mut ProvenanceEnvelope| value.receipt_digest = digest('4'),
            |value: &mut ProvenanceEnvelope| value.expires_at_unix_ms += 1,
        ] {
            let mut changed = envelope.clone();
            mutate(&mut changed);
            assert!(
                changed
                    .verify(&key.verifying_key().to_bytes(), 1_500)
                    .is_err()
            );
        }
        assert!(
            envelope
                .verify(&key.verifying_key().to_bytes(), 2_001)
                .is_err()
        );
        assert!(
            envelope
                .verify(&key.verifying_key().to_bytes(), 2_000)
                .is_err()
        );
    }

    #[test]
    fn export_storage_round_trips_without_private_key_material() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        let envelope = ProvenanceEnvelope::issue(
            &key,
            "subject-1".into(),
            digest('1'),
            digest('2'),
            "operation-1".into(),
            1_000,
            2_000,
        )
        .unwrap();
        let record = ExportRecord {
            binding_digest: digest('3'),
            namespace: "ns".into(),
            envelope,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
            created_at_ms: 1_000,
        };
        let stored = record.to_json().unwrap();
        assert!(!stored.contains(&"07".repeat(32)));
        assert_eq!(ExportRecord::from_json(&stored).unwrap(), record);
    }
}
