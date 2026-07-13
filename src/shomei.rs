//! Portable, independently verifiable operation attestations.

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent};
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
        let mut unsigned = self.clone();
        unsigned.signature = None;
        canonical_json(&unsigned)
    }
}

/// Canonical JSON used by Shomei v1. Object keys are sorted lexicographically,
/// arrays retain their declared order, strings use serde_json escaping, and v1
/// rejects floating-point numbers to avoid cross-runtime number ambiguity.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    reject_floats(&value)?;
    serde_json::to_vec(&sort_json(value)).map_err(|error| error.to_string())
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(encode_hex(&Sha256::digest(canonical_json(value)?)))
}

pub fn event_digest_chain(events: &[OperationReceiptEvent]) -> Result<Vec<EventDigest>, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, ReceiptEventKind};

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
}
