//! Portable, independently verifiable operation attestations.

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BUNDLE_VERSION: &str = "shomei.bundle/v1";
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityVerification {
    pub valid: bool,
    pub versions_supported: bool,
    pub receipt_digest_valid: bool,
    pub event_chain_valid: bool,
    pub signature_valid: bool,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVerification {
    pub compliant: bool,
    pub receipt_complete: bool,
    #[serde(default)]
    pub missing_surfaces: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub integrity: IntegrityVerification,
    pub policy: PolicyVerification,
}

pub fn verify_bundle(bundle: &AttestationBundle) -> VerificationReport {
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
    let signature_valid = verify_signature(bundle, &mut errors);
    let valid = versions_supported
        && receipt_digest_valid
        && event_chain_valid
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
    VerificationReport {
        integrity: IntegrityVerification {
            valid,
            versions_supported,
            receipt_digest_valid,
            event_chain_valid,
            signature_valid,
            errors,
        },
        policy: PolicyVerification {
            compliant: receipt_complete && missing_surfaces.is_empty() && policy_errors.is_empty(),
            receipt_complete,
            missing_surfaces,
            errors: policy_errors,
        },
    }
}

fn verify_signature(bundle: &AttestationBundle, errors: &mut Vec<String>) -> bool {
    let Some(signature) = &bundle.signature else {
        errors.push("bundle is unsigned".into());
        return false;
    };
    if signature.signer.algorithm != SIGNATURE_ALGORITHM {
        errors.push(format!(
            "unsupported signer algorithm {}",
            signature.signer.algorithm
        ));
        return false;
    }
    let public_key = match decode_hex::<32>("signer public key", &signature.signer.public_key) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return false;
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("invalid signer public key: {error}"));
            return false;
        }
    };
    let signature_bytes = match decode_hex::<64>("bundle signature", &signature.value) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return false;
        }
    };
    let signing_bytes = match bundle.signing_bytes() {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("signed bytes could not be reproduced: {error}"));
            return false;
        }
    };
    if verifying_key
        .verify_strict(&signing_bytes, &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        errors.push("bundle signature verification failed".into());
        return false;
    }
    true
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
        let report = verify_bundle(&signed_bundle());
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
            assert!(!verify_bundle(&variant).integrity.valid);
        }
    }

    #[test]
    fn signer_identity_is_covered_by_the_signature() {
        let mut bundle = signed_bundle();
        bundle.signature.as_mut().unwrap().signer.key_id = "key-2".into();
        assert!(!verify_bundle(&bundle).integrity.signature_valid);
    }
}
