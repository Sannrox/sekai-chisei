//! Connector certifications behave the same on SQLite and PostgreSQL (#1481):
//! certify, get, verify, and revoke, including a revoked or unknown
//! certification that fails verification, and a connector bound to a
//! registered source type descriptor (#1698).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::connector_certification::{
    CONNECTOR_CONTRACT, CONNECTOR_UNAVAILABLE, ConnectorCertification, REVOCATION_REVOKED,
    certify_connector, get_connector, revoke_connector, verify_connector,
};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, GITHUB_OBJECT_SYNC_TYPE_DIGEST,
};
use sekai_chisei::sekai::source_type_descriptor::{
    descriptor_digest, register_source_type_descriptor, retire_source_type_descriptor,
    synthetic_pager_alert_v1,
};
use sha2::{Digest, Sha256};

use crate::postgres_scratch::ScratchDatabase;

fn digest(tag: u8) -> String {
    format!("sha256:{tag:02x}{}", "ab".repeat(31))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sign(certification: &mut ConnectorCertification) {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    certification.connector_digest =
        sekai_chisei::sekai::connector_certification::connector_digest_for(certification).unwrap();
    certification.certification_digest =
        sekai_chisei::sekai::connector_certification::certification_digest_for(
            certification,
            &certification.connector_digest,
        )
        .unwrap();
    let signature = signing_key.sign(certification.certification_digest.as_bytes());
    certification.signature_hex = hex(&signature.to_bytes());
}

fn certification(namespace: &str, certification_id: &str) -> ConnectorCertification {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut certification = ConnectorCertification {
        contract_version: CONNECTOR_CONTRACT.into(),
        certification_id: certification_id.into(),
        namespace: namespace.into(),
        owner: "reviewer".into(),
        connector_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        connector_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        producer_identity: "connector/github-primary".into(),
        signer_id: "signer:ops".into(),
        signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
        public_key_hex: hex(&public_key),
        signature_hex: String::new(),
        test_suite_digest: digest(4),
        test_result_digest: digest(5),
        sdk_version: sekai_source_sdk::SDK_VERSION.into(),
        conformance_suite_digest: sekai_source_sdk::conformance_suite_digest(),
        connector_digest: String::new(),
        certification_digest: String::new(),
        revocation: String::new(),
        revocation_reason: String::new(),
        revoked_at_ms: 0,
        predecessor_id: String::new(),
        superseded_by: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    sign(&mut certification);
    certification
}

fn exercise_lifecycle(db: &RuntimeDb, namespace: &str) {
    let first = certification(namespace, "cert:github-1");
    let certified = certify_connector(db, "reviewer", &first, 1_000).unwrap();
    let viewed = get_connector(db, "reviewer", namespace, "cert:github-1").unwrap();
    assert_eq!(viewed.certification_digest, certified.certification_digest);
    assert_eq!(
        certify_connector(db, "reviewer", &first, 2_000).unwrap(),
        certified
    );
    verify_connector(db, "reviewer", namespace, "cert:github-1", &first).unwrap();

    assert_eq!(
        get_connector(db, "reviewer", namespace, "cert:missing").unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    assert_eq!(
        verify_connector(db, "reviewer", namespace, "cert:missing", &first).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );

    let mut next = certification(namespace, "cert:github-2");
    next.predecessor_id = "cert:github-1".into();
    next.producer_identity = "connector/github-replica".into();
    sign(&mut next);
    let recertified = certify_connector(db, "reviewer", &next, 3_000).unwrap();
    let previous = get_connector(db, "reviewer", namespace, "cert:github-1").unwrap();
    assert_eq!(previous.superseded_by, "cert:github-2");
    assert_eq!(
        verify_connector(db, "reviewer", namespace, "cert:github-1", &first).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    verify_connector(db, "reviewer", namespace, "cert:github-2", &recertified).unwrap();

    let revoked = revoke_connector(
        db,
        "reviewer",
        namespace,
        "cert:github-2",
        "signer rotated",
        4_000,
    )
    .unwrap();
    assert_eq!(revoked.revocation, REVOCATION_REVOKED);
    assert_eq!(
        get_connector(db, "reviewer", namespace, "cert:github-2")
            .unwrap()
            .revocation,
        REVOCATION_REVOKED
    );
    assert_eq!(
        verify_connector(db, "reviewer", namespace, "cert:github-2", &recertified).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );

    let mut after_revoke = certification(namespace, "cert:github-3");
    after_revoke.predecessor_id = "cert:github-2".into();
    after_revoke.producer_identity = "connector/github-rotated".into();
    sign(&mut after_revoke);
    let rotated = certify_connector(db, "reviewer", &after_revoke, 5_000).unwrap();
    let revoked_predecessor = get_connector(db, "reviewer", namespace, "cert:github-2").unwrap();
    assert_eq!(revoked_predecessor.revocation, REVOCATION_REVOKED);
    assert_eq!(revoked_predecessor.superseded_by, "cert:github-3");
    verify_connector(db, "reviewer", namespace, "cert:github-3", &rotated).unwrap();
}

/// A connector of a registered descriptor's kind certifies and verifies,
/// stops verifying once the descriptor retires, and an unregistered or
/// foreign descriptor is refused with the same answer.
fn exercise_descriptor_binding(db: &RuntimeDb, namespace: &str) {
    let descriptor = synthetic_pager_alert_v1();
    let type_digest = descriptor_digest(&descriptor).unwrap();
    let bound = |certification_id: &str, type_digest: &str| {
        let mut bound = certification(namespace, certification_id);
        bound.connector_id = "connector/pager".into();
        bound.connector_version = "2.1.0".into();
        bound.producer_identity = format!("connector/pager-{certification_id}");
        bound.type_digest = type_digest.into();
        sign(&mut bound);
        bound
    };
    let pager = bound("cert:pager-1", &type_digest);
    assert_eq!(
        certify_connector(db, "reviewer", &pager, 1_000).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    register_source_type_descriptor(db, "registrar", "elsewhere", &descriptor, 1_000).unwrap();
    // Registered only in another namespace: the same refusal.
    assert_eq!(
        certify_connector(db, "reviewer", &pager, 1_000).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    register_source_type_descriptor(db, "registrar", namespace, &descriptor, 1_000).unwrap();
    let certified = certify_connector(db, "reviewer", &pager, 2_000).unwrap();
    verify_connector(db, "reviewer", namespace, "cert:pager-1", &pager).unwrap();

    retire_source_type_descriptor(db, "registrar", namespace, &type_digest, 3_000).unwrap();
    assert_eq!(
        verify_connector(db, "reviewer", namespace, "cert:pager-1", &pager).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    assert_eq!(
        get_connector(db, "reviewer", namespace, "cert:pager-1").unwrap(),
        certified
    );
    assert_eq!(
        certify_connector(db, "reviewer", &bound("cert:pager-2", &type_digest), 4_000).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
    assert_eq!(
        certify_connector(db, "reviewer", &bound("cert:pager-3", &digest(9)), 4_000).unwrap_err(),
        CONNECTOR_UNAVAILABLE
    );
}

#[test]
fn sqlite_connector_certification_backend_conformance() {
    exercise_lifecycle(&RuntimeDb::memory(), "ops");
    exercise_descriptor_binding(&RuntimeDb::memory(), "ops");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_connector_certification_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise_lifecycle(&db, "ops");
    exercise_descriptor_binding(&db, "ops-descriptors");
}
