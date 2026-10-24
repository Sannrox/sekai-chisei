//! Signed source-webhook deliveries as object-sync transport (#673).
//!
//! A verified push envelope becomes one `sekai.source-batch/v1`. Signatures
//! prove delivery authenticity only. Checkpoint ownership stays on
//! `ApplySourceBatch`.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    MAX_SOURCE_BATCH_RECORDS, SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBatch, SourceBatchResult,
    SourceRecord,
};
use crate::shomei;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const WEBHOOK_DELIVERY_CONTRACT: &str = "sekai.source-webhook-delivery/v1";
pub const WEBHOOK_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const MAX_WEBHOOK_BYTES: usize = 256 * 1024;
pub const MAX_DELIVERY_SKEW_MS: i64 = 60_000;
pub const ADMIT_UNAVAILABLE: &str = "source webhook delivery is not admitted";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWebhookKeyPin {
    pub pin_id: String,
    pub namespace: String,
    pub source_instance: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWebhookSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWebhookDelivery {
    pub contract_version: String,
    pub delivery_id: String,
    pub namespace: String,
    pub producer_identity: String,
    pub source: String,
    pub source_instance: String,
    pub type_digest: String,
    pub current_cursor: String,
    pub proposed_next_cursor: String,
    pub signed_at_ms: i64,
    pub not_after_ms: i64,
    pub records: Vec<SourceRecord>,
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SourceWebhookSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceWebhookAdmitResult {
    pub delivery_id: String,
    pub content_digest: String,
    pub outcome: String,
    pub batch: SourceBatchResult,
}

pub fn pin_source_webhook_key(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    source_instance: &str,
    key_id: &str,
    public_key_hex: &str,
    now_ms: i64,
) -> Result<SourceWebhookKeyPin, String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    required("source instance", source_instance)?;
    required("key id", key_id)?;
    decode_hex(public_key_hex)?;
    if now_ms < 0 {
        return Err("pin timestamp must be non-negative".into());
    }
    let pin = SourceWebhookKeyPin {
        pin_id: format!("webhook-key:{namespace}:{source_instance}:{key_id}"),
        namespace: namespace.into(),
        source_instance: source_instance.into(),
        key_id: key_id.into(),
        public_key_hex: public_key_hex.trim().to_ascii_lowercase(),
        enabled: true,
        created_by: actor.into(),
        created_at_ms: now_ms,
    };
    db.put_source_webhook_key(&pin)?;
    Ok(pin)
}

pub fn list_source_webhook_keys(
    db: &RuntimeDb,
    namespace: Option<&str>,
    source_instance: Option<&str>,
) -> Result<Vec<SourceWebhookKeyPin>, String> {
    db.list_source_webhook_keys(namespace, source_instance)
}

pub fn sign_source_webhook(
    delivery: &mut SourceWebhookDelivery,
    signing_key: &SigningKey,
    key_id: &str,
) -> Result<(), String> {
    if delivery.signature.is_some() {
        return Err("source webhook delivery is already signed".into());
    }
    required("delivery id", &delivery.delivery_id)?;
    required("key id", key_id)?;
    delivery.content_digest = content_digest_for(delivery)?;
    let mut unsigned = delivery.clone();
    unsigned.signature = Some(SourceWebhookSignature {
        algorithm: WEBHOOK_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: String::new(),
    });
    let bytes = shomei::canonical_json(&unsigned)?;
    delivery.signature = Some(SourceWebhookSignature {
        algorithm: WEBHOOK_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: encode_hex(&signing_key.sign(&bytes).to_bytes()),
    });
    Ok(())
}

pub fn admit_source_webhook(
    db: &RuntimeDb,
    actor: &str,
    delivery: &SourceWebhookDelivery,
    now_ms: i64,
) -> Result<SourceWebhookAdmitResult, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("admit timestamp must be non-negative".into());
    }
    authenticate_delivery(db, actor, delivery, now_ms)?;
    let batch = delivery_to_batch(delivery)?;
    let result = db.apply_source_batch(&batch, actor, now_ms.max(1))?;
    Ok(SourceWebhookAdmitResult {
        delivery_id: delivery.delivery_id.clone(),
        content_digest: delivery.content_digest.clone(),
        outcome: if result.transaction.outcome
            == crate::sekai::object_sync::OperationOutcome::Success
        {
            "accepted".into()
        } else {
            "denied".into()
        },
        batch: result,
    })
}

fn authenticate_delivery(
    db: &RuntimeDb,
    actor: &str,
    delivery: &SourceWebhookDelivery,
    now_ms: i64,
) -> Result<(), String> {
    if delivery.contract_version != WEBHOOK_DELIVERY_CONTRACT {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    required("delivery id", &delivery.delivery_id)?;
    if delivery.producer_identity != actor {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    if delivery.source != SOURCE_GITHUB {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    if encoded_size(delivery)? > MAX_WEBHOOK_BYTES
        || delivery.records.len() > MAX_SOURCE_BATCH_RECORDS
    {
        return Err("source webhook delivery is oversized".into());
    }
    if delivery.signed_at_ms > now_ms.saturating_add(MAX_DELIVERY_SKEW_MS)
        || now_ms >= delivery.not_after_ms
    {
        return Err("source webhook delivery is expired".into());
    }
    if content_digest_for(delivery)? != delivery.content_digest {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    let signature = delivery.signature.as_ref().ok_or(ADMIT_UNAVAILABLE)?;
    if signature.algorithm != WEBHOOK_SIGNATURE_ALGORITHM {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    let pin = db
        .get_source_webhook_key(
            &delivery.namespace,
            &delivery.source_instance,
            &signature.key_id,
        )?
        .ok_or(ADMIT_UNAVAILABLE)?;
    if !pin.enabled
        || !pin
            .public_key_hex
            .eq_ignore_ascii_case(&signature.public_key_hex)
    {
        return Err(ADMIT_UNAVAILABLE.into());
    }
    verify_signature(delivery, signature).map_err(|_| ADMIT_UNAVAILABLE.to_string())
}

fn delivery_to_batch(delivery: &SourceWebhookDelivery) -> Result<SourceBatch, String> {
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: delivery.namespace.clone(),
        producer_identity: delivery.producer_identity.clone(),
        source: delivery.source.clone(),
        source_instance: delivery.source_instance.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: delivery.type_digest.clone(),
        current_cursor: delivery.current_cursor.clone(),
        proposed_next_cursor: delivery.proposed_next_cursor.clone(),
        idempotency_key: delivery.delivery_id.clone(),
        batch_digest: String::new(),
        collected_at_ms: delivery.signed_at_ms,
        records: delivery.records.clone(),
        delivery: None,
    };
    batch.batch_digest = batch
        .canonical_digest()
        .map_err(|error| error.to_string())?;
    Ok(batch)
}

fn content_digest_for(delivery: &SourceWebhookDelivery) -> Result<String, String> {
    let mut unsigned = delivery.clone();
    unsigned.signature = None;
    unsigned.content_digest.clear();
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&unsigned)?
    ))
}

fn verify_signature(
    delivery: &SourceWebhookDelivery,
    signature: &SourceWebhookSignature,
) -> Result<(), String> {
    let public_bytes = decode_hex(&signature.public_key_hex)?;
    let public_key = VerifyingKey::from_bytes(
        public_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ADMIT_UNAVAILABLE.to_string())?,
    )
    .map_err(|_| ADMIT_UNAVAILABLE.to_string())?;
    let mut unsigned = delivery.clone();
    unsigned.signature = Some(SourceWebhookSignature {
        signature_hex: String::new(),
        ..signature.clone()
    });
    let bytes = shomei::canonical_json(&unsigned)?;
    let signature_bytes = decode_hex(&signature.signature_hex)?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ADMIT_UNAVAILABLE.to_string())?;
    public_key
        .verify(
            &bytes,
            &ed25519_dalek::Signature::from_bytes(&signature_array),
        )
        .map_err(|_| ADMIT_UNAVAILABLE.to_string())
}

fn encoded_size(delivery: &SourceWebhookDelivery) -> Result<usize, String> {
    serde_json::to_vec(delivery)
        .map(|bytes| bytes.len())
        .map_err(|error| error.to_string())
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|error| format!("invalid hex: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_sync::GITHUB_OBJECT_SYNC_TYPE_DIGEST;
    use std::collections::BTreeMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key_hex(seed: u8) -> String {
        encode_hex(signing_key(seed).verifying_key().as_bytes())
    }

    fn record() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "sekai-project/sekai-chisei".into(),
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Webhook issue".into(),
            payload_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Webhook issue".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn unsigned_delivery(id: &str, now_ms: i64) -> SourceWebhookDelivery {
        SourceWebhookDelivery {
            contract_version: WEBHOOK_DELIVERY_CONTRACT.into(),
            delivery_id: id.into(),
            namespace: "ops".into(),
            producer_identity: "connector/ops".into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "sekai-project/sekai-chisei".into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
            current_cursor: String::new(),
            proposed_next_cursor: format!("push:{id}"),
            signed_at_ms: now_ms,
            not_after_ms: now_ms + 60_000,
            records: vec![record()],
            content_digest: String::new(),
            signature: None,
        }
    }

    fn signed_delivery(id: &str, now_ms: i64, seed: u8) -> SourceWebhookDelivery {
        let mut delivery = unsigned_delivery(id, now_ms);
        sign_source_webhook(&mut delivery, &signing_key(seed), "k1").unwrap();
        delivery
    }

    fn pin(db: &RuntimeDb, seed: u8, now_ms: i64) {
        pin_source_webhook_key(
            db,
            "admin",
            "ops",
            "sekai-project/sekai-chisei",
            "k1",
            &public_key_hex(seed),
            now_ms,
        )
        .unwrap();
    }

    #[test]
    fn accepted_delivery_uses_source_batch_identity() {
        let runtime = db();
        pin(&runtime, 1, 1_000);
        let delivery = signed_delivery("d1", 5_000, 1);
        let admitted = admit_source_webhook(&runtime, "connector/ops", &delivery, 5_100).unwrap();
        assert_eq!(admitted.outcome, "accepted");
        assert_eq!(admitted.delivery_id, "d1");
        assert!(admitted.batch.checkpoint_advanced);
        assert_eq!(admitted.batch.transaction.idempotency_key, "d1");
        let replay = admit_source_webhook(&runtime, "connector/ops", &delivery, 5_200).unwrap();
        assert_eq!(
            replay.batch.transaction.transaction_id,
            admitted.batch.transaction.transaction_id
        );
        assert_eq!(replay.batch.records, admitted.batch.records);
    }

    #[test]
    fn forged_expired_oversized_and_unpinned_fail_closed() {
        let runtime = db();
        pin(&runtime, 1, 1_000);
        let mut forged = signed_delivery("d-forged", 6_000, 1);
        forged.records[0].display_name = "tampered".into();
        assert_eq!(
            admit_source_webhook(&runtime, "connector/ops", &forged, 6_100).unwrap_err(),
            ADMIT_UNAVAILABLE
        );

        let expired = signed_delivery("d-expired", 6_000, 1);
        assert!(
            admit_source_webhook(&runtime, "connector/ops", &expired, 70_000)
                .unwrap_err()
                .contains("expired")
        );

        let mut oversized = unsigned_delivery("d-oversize", 6_000);
        oversized.records = vec![record(); MAX_SOURCE_BATCH_RECORDS + 1];
        sign_source_webhook(&mut oversized, &signing_key(1), "k1").unwrap();
        assert!(
            admit_source_webhook(&runtime, "connector/ops", &oversized, 6_100)
                .unwrap_err()
                .contains("oversized")
        );

        let other = db();
        let unpinned = signed_delivery("d-unpinned", 6_000, 1);
        assert_eq!(
            admit_source_webhook(&other, "connector/ops", &unpinned, 6_100).unwrap_err(),
            ADMIT_UNAVAILABLE
        );
        assert_eq!(
            admit_source_webhook(
                &runtime,
                "intruder",
                &signed_delivery("d-actor", 6_000, 1),
                6_100
            )
            .unwrap_err(),
            ADMIT_UNAVAILABLE
        );
    }

    #[test]
    fn reused_delivery_id_with_different_content_conflicts() {
        let runtime = db();
        pin(&runtime, 1, 1_000);
        let first = signed_delivery("d-same", 7_000, 1);
        admit_source_webhook(&runtime, "connector/ops", &first, 7_100).unwrap();
        let mut second = unsigned_delivery("d-same", 7_000);
        second.proposed_next_cursor = "push:other".into();
        sign_source_webhook(&mut second, &signing_key(1), "k1").unwrap();
        let err = admit_source_webhook(&runtime, "connector/ops", &second, 7_200).unwrap_err();
        assert!(
            err.contains("idempotency") || err.contains("conflict"),
            "{err}"
        );
    }
}
