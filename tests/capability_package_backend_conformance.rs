//! Shared SQLite/PostgreSQL conformance for capability-package certifications (#1478).

use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::capability_package::{
    CapabilityPackageCertification, MEMBER_ACTION_TYPE, MEMBER_CHANGE_SET, PACKAGE_CONTRACT,
    PACKAGE_UNAVAILABLE, PackageMember, REVOCATION_REVOKED, certification_digest_for,
    certify_package, get_package, package_digest_for, revoke_package, verify_package,
};

use crate::postgres_scratch::ScratchDatabase;

fn digest(tag: u8) -> String {
    format!("sha256:{tag:02x}{}", "ab".repeat(31))
}

fn members() -> Vec<PackageMember> {
    vec![
        PackageMember {
            kind: MEMBER_CHANGE_SET.into(),
            member_id: "cs:intake".into(),
            digest: digest(1),
        },
        PackageMember {
            kind: MEMBER_ACTION_TYPE.into(),
            member_id: "act:review".into(),
            digest: digest(2),
        },
    ]
}

fn certification() -> CapabilityPackageCertification {
    let members = members();
    let compatibility = vec!["sekai.governed-action/v1".into()];
    let package_digest = package_digest_for("pkg:intake", &members, &compatibility).unwrap();
    let mut certification = CapabilityPackageCertification {
        contract_version: PACKAGE_CONTRACT.into(),
        certification_id: "cert:1".into(),
        namespace: "ops".into(),
        owner: "reviewer".into(),
        package_id: "pkg:intake".into(),
        package_digest: package_digest.clone(),
        signer_id: "signer:ops".into(),
        signer_digest: digest(3),
        members,
        compatibility,
        test_suite_digest: digest(4),
        test_result_digest: digest(5),
        revocation: String::new(),
        revocation_reason: String::new(),
        revoked_at_ms: 0,
        predecessor_id: String::new(),
        superseded_by: String::new(),
        certification_digest: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    certification.certification_digest =
        certification_digest_for(&certification, &package_digest).unwrap();
    certification
}

fn exercise(db: &RuntimeDb) {
    let first = certify_package(db, "reviewer", &certification(), 1_000).unwrap();
    assert_eq!(
        get_package(db, "reviewer", "ops", "cert:1")
            .unwrap()
            .certification_id,
        "cert:1"
    );
    verify_package(db, "reviewer", "ops", "cert:1", &first).unwrap();
    assert_eq!(
        certify_package(db, "reviewer", &certification(), 2_000).unwrap(),
        first
    );

    let mut next = certification();
    next.certification_id = "cert:2".into();
    next.predecessor_id = "cert:1".into();
    next.members[1].digest = digest(8);
    next.package_digest.clear();
    next.certification_digest.clear();
    let recertified = certify_package(db, "reviewer", &next, 3_000).unwrap();
    assert_eq!(
        get_package(db, "reviewer", "ops", "cert:1")
            .unwrap()
            .superseded_by,
        "cert:2"
    );
    assert_eq!(
        verify_package(db, "reviewer", "ops", "cert:1", &first).unwrap_err(),
        PACKAGE_UNAVAILABLE
    );
    verify_package(db, "reviewer", "ops", "cert:2", &recertified).unwrap();

    let revoked = revoke_package(db, "reviewer", "ops", "cert:2", "signer rotated", 4_000).unwrap();
    assert_eq!(revoked.revocation, REVOCATION_REVOKED);
    assert_eq!(db.list_capability_packages("ops").unwrap().len(), 2);
}

#[test]
fn sqlite_capability_package_backend_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_capability_package_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db);
}
