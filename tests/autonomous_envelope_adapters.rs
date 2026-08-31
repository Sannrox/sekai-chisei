#[path = "../adapters/autonomy_evaluate.rs"]
mod autonomy_evaluate;
#[path = "../adapters/autonomy_simulate.rs"]
mod autonomy_simulate;

use ed25519_dalek::Signer;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::autonomous_envelope::{
    AUTONOMY_UNAVAILABLE, AutonomousEnvelope, PROFILE_EVALUATE, PROFILE_SIMULATE,
    RECEIPT_INVALIDATED, STATUS_LEASE_LOST, STATUS_ROLLED_BACK, STATUS_STOPPED, admit_envelope,
    envelope_digest_for, invalidate_receipt, note_lease_loss, rollback_envelope, stop_envelope,
};
use sha2::{Digest, Sha256};

fn sign(envelope: &mut AutonomousEnvelope) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    envelope.signer_digest = format!("sha256:{:x}", Sha256::digest(public_key));
    envelope.public_key_hex = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    envelope.envelope_digest = envelope_digest_for(envelope).unwrap();
    let signature = signing_key.sign(envelope.envelope_digest.as_bytes());
    envelope.signature_hex = signature
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
}

fn adapter_lifecycle(adapter_id: &str) {
    let db = RuntimeDb::memory();
    let mut envelope = if adapter_id == PROFILE_SIMULATE {
        autonomy_simulate::translate_envelope(
            &autonomy_simulate::parse(include_bytes!(
                "../adapters/fixtures/autonomy_simulate.json"
            ))
            .unwrap(),
        )
        .unwrap()
    } else {
        autonomy_evaluate::translate_envelope(
            &autonomy_evaluate::parse(include_bytes!(
                "../adapters/fixtures/autonomy_evaluate.json"
            ))
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(envelope.adapter_id, adapter_id);
    sign(&mut envelope);
    let admitted = admit_envelope(&db, "operator", &envelope, 1_000).unwrap();
    assert_eq!(
        admit_envelope(&db, "operator", &admitted, 1_100)
            .unwrap()
            .envelope_digest,
        admitted.envelope_digest
    );
    let mut stale = envelope.clone();
    stale.pins.prompt_digest =
        "sha256:09ababababababababababababababababababababababababababababababab".into();
    sign(&mut stale);
    assert_eq!(
        admit_envelope(&db, "operator", &stale, 1_200).unwrap_err(),
        AUTONOMY_UNAVAILABLE
    );
    let stopped = stop_envelope(&db, "operator", "ops", &envelope.envelope_id, 2_000).unwrap();
    assert_eq!(stopped.status, STATUS_STOPPED);
    let rolled = rollback_envelope(&db, "operator", "ops", &envelope.envelope_id, 3_000).unwrap();
    assert_eq!(rolled.status, STATUS_ROLLED_BACK);
}

#[test]
fn two_adapters_pass_current_pin_stop_and_rollback() {
    adapter_lifecycle(PROFILE_SIMULATE);
    adapter_lifecycle(PROFILE_EVALUATE);
}

#[test]
fn lease_loss_and_receipt_invalidation_fail_closed() {
    let db = RuntimeDb::memory();
    let mut envelope = autonomy_simulate::translate_envelope(
        &autonomy_simulate::parse(include_bytes!(
            "../adapters/fixtures/autonomy_simulate.json"
        ))
        .unwrap(),
    )
    .unwrap();
    envelope.envelope_id = "auto:lease".into();
    sign(&mut envelope);
    admit_envelope(&db, "operator", &envelope, 1_000).unwrap();
    assert_eq!(
        note_lease_loss(&db, "operator", "ops", "auto:lease", 2_000)
            .unwrap()
            .status,
        STATUS_LEASE_LOST
    );
    let mut receipt = envelope.clone();
    receipt.envelope_id = "auto:receipt".into();
    sign(&mut receipt);
    admit_envelope(&db, "operator", &receipt, 3_000).unwrap();
    assert_eq!(
        invalidate_receipt(&db, "operator", "ops", "auto:receipt", 3_100)
            .unwrap()
            .receipt_status,
        RECEIPT_INVALIDATED
    );
    assert_eq!(
        admit_envelope(&db, "operator", &receipt, 3_200).unwrap_err(),
        AUTONOMY_UNAVAILABLE
    );
}

#[test]
fn hidden_fields_fail_closed() {
    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../adapters/fixtures/autonomy_simulate.json"
    ))
    .unwrap();
    document
        .as_object_mut()
        .unwrap()
        .insert("token".into(), serde_json::json!("sk-live"));
    assert!(autonomy_simulate::parse(&serde_json::to_vec(&document).unwrap()).is_err());
    assert_eq!(autonomy_simulate::ADAPTER_ID, PROFILE_SIMULATE);
    assert_eq!(autonomy_evaluate::ADAPTER_ID, PROFILE_EVALUATE);
}
