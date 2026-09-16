use ed25519_dalek::SigningKey;
use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use sekai_chisei::compliance_export::{
    ComplianceExportBundle, ComplianceExportRequest, RedactionMode, build_compliance_export,
    sign_compliance_export,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::peer_import::{
    PeerTrustRoot, import_compliance_bundle, peer_import_grants_permit_authority, put_trust_root,
};
use std::collections::BTreeMap;

fn db() -> RuntimeDb {
    RuntimeDb::memory()
}

fn sample_receipt(namespace: &str) -> OperationReceipt {
    let event = |id: &str, kind: ReceiptEventKind| OperationReceiptEvent {
        event_id: id.into(),
        operation_id: "op-1".into(),
        parent_event_id: None,
        timestamp_ms: 1_500,
        kind,
        surface: kind.surface(),
        actor: "peer".into(),
        references: Vec::new(),
        attributes: BTreeMap::new(),
    };
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: "op-1".into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "triage".into(),
        initiating_actor: "peer".into(),
        schema_version: "schema-v1".into(),
        policy_version: "pol-v1".into(),
        started_at_ms: 1_000,
        completed_at_ms: Some(2_000),
        events: vec![
            event("e0", ReceiptEventKind::IntentRecorded),
            event("e1", ReceiptEventKind::OutcomeRecorded),
        ],
        uncovered_surfaces: Vec::new(),
        reporter_grants: vec![],
        ontology_digest: None,
        artifact: None,
    }
}

fn public_key_hex(signing: &SigningKey) -> String {
    signing
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn signed_bundle(namespace: &str, signing: &SigningKey) -> ComplianceExportBundle {
    let request = ComplianceExportRequest {
        namespace: namespace.into(),
        start_timestamp_ms: 0,
        end_timestamp_ms: 10_000,
        redaction: RedactionMode::Full,
        actor: "peer-exporter".into(),
        request_id: "export-1".into(),
    };
    let mut bundle =
        build_compliance_export(&request, vec![sample_receipt(namespace)], vec![], 5_000).unwrap();
    sign_compliance_export(&mut bundle, signing, "peer-site-a", "k1", 5_100).unwrap();
    bundle
}

#[test]
fn imports_valid_signed_bundle_under_trust_root() {
    let db = db();
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let public = public_key_hex(&signing);
    put_trust_root(
        &db,
        &PeerTrustRoot {
            namespace: "support".into(),
            site_identity: "peer-site-a".into(),
            key_id: "k1".into(),
            public_key_hex: public,
            enabled: true,
            created_by: "admin".into(),
            created_at_ms: 1,
        },
    )
    .unwrap();
    let bundle = signed_bundle("support", &signing);
    let result = import_compliance_bundle(&db, "admin", "support", &bundle, 6_000).unwrap();
    assert!(result.record.verified);
    assert!(!result.record.permit_authority);
    assert!(!peer_import_grants_permit_authority(&result.record));
    assert_eq!(result.record.receipt_count, 1);

    let again = import_compliance_bundle(&db, "admin", "support", &bundle, 6_001).unwrap();
    assert_eq!(again.record.import_id, result.record.import_id);
}

#[test]
fn rejects_unsigned_or_untrusted_signer() {
    let db = db();
    let signing = SigningKey::from_bytes(&[3u8; 32]);
    let public = public_key_hex(&signing);
    put_trust_root(
        &db,
        &PeerTrustRoot {
            namespace: "support".into(),
            site_identity: "peer-site-a".into(),
            key_id: "k1".into(),
            public_key_hex: public,
            enabled: true,
            created_by: "admin".into(),
            created_at_ms: 1,
        },
    )
    .unwrap();
    let other = SigningKey::from_bytes(&[4u8; 32]);
    let bundle = signed_bundle("support", &other);
    assert!(
        import_compliance_bundle(&db, "admin", "support", &bundle, 6_000)
            .unwrap_err()
            .contains("trust root")
    );
}

#[test]
fn rejects_tampered_bundle() {
    let db = db();
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let public = public_key_hex(&signing);
    put_trust_root(
        &db,
        &PeerTrustRoot {
            namespace: "support".into(),
            site_identity: "peer-site-a".into(),
            key_id: "k1".into(),
            public_key_hex: public,
            enabled: true,
            created_by: "admin".into(),
            created_at_ms: 1,
        },
    )
    .unwrap();
    let mut bundle = signed_bundle("support", &signing);
    bundle.manifest.receipt_count = 99;
    assert!(
        import_compliance_bundle(&db, "admin", "support", &bundle, 6_000)
            .unwrap_err()
            .contains("verification failed")
    );
}
