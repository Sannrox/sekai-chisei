use sekai_chisei::db::deduplication::DeduplicationBackend;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::retention::RetentionPolicyBackend;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::deduplication::{
    ContentObligations, ContentReferenceRequest, ContentScope, ReconciliationAction,
    ReconciliationCandidate, ReconciliationDisposition, ReconciliationRequest,
};
use sekai_chisei::sekai::retention::{RetentionPolicy, SubjectErasureRequest};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

fn scope(prefix: &str) -> ContentScope {
    ContentScope {
        namespace: format!("{prefix}:namespace"),
        classification: "confidential".into(),
        encryption_key_id: "key-1".into(),
        residency: "eu".into(),
    }
}

fn reference(prefix: &str, suffix: &str) -> ContentReferenceRequest {
    ContentReferenceRequest {
        reference_id: format!("{prefix}:reference:{suffix}"),
        actor: format!("{prefix}:actor"),
        operation_id: format!("{prefix}:operation"),
        causal_identity: format!("{prefix}:cause:{suffix}"),
        idempotency_key: format!("{prefix}:put:{suffix}"),
        retention_until_ms: None,
        retention_hold: false,
        legal_hold: false,
        archived: false,
        receipt_required: false,
        attestation_required: false,
        preserve_tombstone: true,
    }
}

fn exercise_content(db: &dyn DeduplicationBackend, prefix: &str) {
    let scope = scope(prefix);
    let first = reference(prefix, "one");
    let admitted = db
        .put_scoped_content(&scope, &first, b"shared content", 100)
        .unwrap();
    assert!(admitted.stored_new_blob);
    assert!(!admitted.deduplicated);
    assert_eq!(
        db.put_scoped_content(&scope, &first, b"shared content", 101)
            .unwrap()
            .reference
            .reference_id,
        first.reference_id
    );
    let second = reference(prefix, "two");
    let deduplicated = db
        .put_scoped_content(&scope, &second, b"shared content", 102)
        .unwrap();
    assert!(!deduplicated.stored_new_blob);
    assert_eq!(admitted.reference.blob_id, deduplicated.reference.blob_id);
    let mut wrong_scope = scope.clone();
    wrong_scope.namespace.push_str(":other");
    assert_eq!(
        db.read_scoped_content(&wrong_scope, &first.reference_id)
            .unwrap(),
        None
    );

    db.set_content_obligations(
        &scope,
        &first.reference_id,
        &ContentObligations {
            legal_hold: true,
            preserve_tombstone: true,
            ..ContentObligations::default()
        },
        "legal",
        "preserve evidence",
        &format!("{prefix}:hold"),
        110,
    )
    .unwrap();
    db.release_content_reference(
        &scope,
        &first.reference_id,
        "operator",
        "operation complete",
        &format!("{prefix}:release:one"),
        120,
    )
    .unwrap();
    db.release_content_reference(
        &scope,
        &second.reference_id,
        "operator",
        "operation complete",
        &format!("{prefix}:release:two"),
        120,
    )
    .unwrap();
    assert_eq!(
        db.collect_scoped_content_garbage(&scope, "collector", 130)
            .unwrap()
            .payloads_erased,
        0
    );
    db.set_content_obligations(
        &scope,
        &first.reference_id,
        &ContentObligations {
            preserve_tombstone: true,
            ..ContentObligations::default()
        },
        "legal",
        "hold released",
        &format!("{prefix}:unhold"),
        140,
    )
    .unwrap();
    let collected = db
        .collect_scoped_content_garbage(&scope, "collector", 150)
        .unwrap();
    assert_eq!(collected.payloads_erased, 1);
    assert_eq!(collected.tombstones_preserved, 2);
    assert_eq!(
        db.read_scoped_content(&scope, &first.reference_id).unwrap(),
        None
    );
    assert!(
        db.set_content_obligations(
            &scope,
            &first.reference_id,
            &ContentObligations {
                legal_hold: true,
                ..ContentObligations::default()
            },
            "legal",
            "too late",
            &format!("{prefix}:late-hold"),
            160,
        )
        .is_err()
    );
}

fn exercise_reconciliation(db: &dyn DeduplicationBackend, graph: &dyn GraphBackend, prefix: &str) {
    let namespace = format!("{prefix}:namespace");
    let external_id = format!("{prefix}:same");
    for suffix in ["a", "b"] {
        graph
            .create_object(
                &Object {
                    id: format!("{prefix}:object:{suffix}"),
                    kind: "artifact".into(),
                    name: suffix.into(),
                    namespace: namespace.clone(),
                    external_id: external_id.clone(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                },
                "fixture",
            )
            .unwrap();
    }
    let request = ReconciliationRequest {
        namespace,
        kind: "artifact".into(),
        external_identity: external_id,
        candidates: vec![
            ReconciliationCandidate {
                object_id: format!("{prefix}:object:a"),
                source: "registry".into(),
                precedence: 100,
                authoritative: true,
            },
            ReconciliationCandidate {
                object_id: format!("{prefix}:object:b"),
                source: "import".into(),
                precedence: 10,
                authoritative: false,
            },
        ],
        action: ReconciliationAction::Merge,
        subjects: vec![format!("{prefix}:object:a"), format!("{prefix}:object:b")],
        canonical_object_id: Some(format!("{prefix}:object:a")),
        actor: "reconciler".into(),
        reason: "same durable identity".into(),
        idempotency_key: format!("{prefix}:reconcile"),
    };
    let first = db.reconcile_objects(&request, 200).unwrap();
    assert!(!first.deduplicated);
    assert!(db.reconcile_objects(&request, 201).unwrap().deduplicated);
    assert_eq!(
        db.reconciliation_state(&first.decision.case_id)
            .unwrap()
            .objects
            .get(&format!("{prefix}:object:b")),
        Some(&ReconciliationDisposition::MergedInto(format!(
            "{prefix}:object:a"
        )))
    );
    db.reverse_reconciliation(
        &first.decision.id,
        "reviewer",
        "sources diverged",
        &format!("{prefix}:reverse"),
        210,
    )
    .unwrap();
    assert_eq!(
        db.reconciliation_state(&first.decision.case_id)
            .unwrap()
            .objects
            .get(&format!("{prefix}:object:b")),
        Some(&ReconciliationDisposition::Independent)
    );
}

fn exercise_policies(db: &dyn RetentionPolicyBackend, prefix: &str) {
    let policy = RetentionPolicy {
        dataset: "audit".into(),
        namespace: format!("{prefix}:namespace"),
        data_class: "confidential".into(),
        retention_days: 30,
        updated: 100,
    };
    db.set_retention_policy(&policy).unwrap();
    assert!(db.list_retention_policies().unwrap().contains(&policy));
    let mut invalid = policy;
    invalid.retention_days = 0;
    assert!(db.set_retention_policy(&invalid).is_err());
}

fn exercise_subject_erasure(
    dedup: &dyn DeduplicationBackend,
    retention: &dyn RetentionPolicyBackend,
    prefix: &str,
) {
    let scope = scope(prefix);
    let mut held = reference(prefix, "erasure-held");
    held.operation_id = format!("{prefix}:subject");
    held.legal_hold = true;
    dedup
        .put_scoped_content(&scope, &held, b"held evidence", 300)
        .unwrap();
    let request = SubjectErasureRequest {
        subject_kind: "work_unit".into(),
        subject: held.operation_id.clone(),
        requested_by: "privacy-operator".into(),
        reason: "validated request".into(),
        timestamp: 310,
    };
    assert!(retention.erase_subject(&request).is_err());
    dedup
        .set_content_obligations(
            &scope,
            &held.reference_id,
            &ContentObligations {
                preserve_tombstone: true,
                ..ContentObligations::default()
            },
            "legal",
            "hold released",
            &format!("{prefix}:erasure-unhold"),
            320,
        )
        .unwrap();
    let erased = retention
        .erase_subject(&SubjectErasureRequest {
            timestamp: 330,
            ..request
        })
        .unwrap();
    assert!(!erased.subject_hash.is_empty());
    assert_eq!(
        dedup
            .read_scoped_content(&scope, &held.reference_id)
            .unwrap(),
        None
    );
}

fn exercise_backend(
    dedup: &dyn DeduplicationBackend,
    retention: &dyn RetentionPolicyBackend,
    graph: &dyn GraphBackend,
    prefix: &str,
) {
    exercise_content(dedup, prefix);
    exercise_reconciliation(dedup, graph, prefix);
    exercise_policies(retention, prefix);
    exercise_subject_erasure(dedup, retention, prefix);
}

#[test]
fn sqlite_retention_deduplication_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_backend(&db, &db, &db, "sqlite");
}

fn postgres_test_database() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        Ok(path) => {
            let certificate = std::fs::read(path).expect("read PostgreSQL test CA certificate");
            PostgresDb::connect_with_ca_certificate(&url, 8, &certificate).unwrap()
        }
        Err(_) => PostgresDb::connect(&url, 8).unwrap(),
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_retention_deduplication_conformance() {
    let db = postgres_test_database();
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_backend(&db, &db, &db, &prefix);
    let archive_subject = format!("{prefix}:archived-agent");
    let archive_scope = scope(&format!("{prefix}:archive"));
    let mut archive_reference = reference(&format!("{prefix}:archive"), "subject");
    archive_reference.actor = archive_subject.clone();
    db.put_scoped_content(
        &archive_scope,
        &archive_reference,
        b"archived subject content",
        400,
    )
    .unwrap();
    let archived = db.archive_lifecycle_records(1_000).unwrap();
    assert!(archived.audit_archived > 0);
    assert!(db.verify_lifecycle_archive(&archived.batch_id).unwrap().ok);
    db.erase_subject(&SubjectErasureRequest {
        subject_kind: "agent".into(),
        subject: archive_subject,
        requested_by: "privacy-operator".into(),
        reason: "validated request".into(),
        timestamp: 1_100,
    })
    .unwrap();
    assert!(db.verify_lifecycle_archive(&archived.batch_id).unwrap().ok);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_collectors_erase_once() {
    let db = Arc::new(postgres_test_database());
    let prefix = format!("collector-race-{}", uuid::Uuid::new_v4().simple());
    let scope = scope(&prefix);
    let request = reference(&prefix, "race");
    db.put_scoped_content(&scope, &request, b"race", 100)
        .unwrap();
    db.release_content_reference(
        &scope,
        &request.reference_id,
        "operator",
        "done",
        &format!("{prefix}:release"),
        110,
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [(), ()].map(|_| {
        let db = db.clone();
        let barrier = barrier.clone();
        let scope = scope.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.collect_scoped_content_garbage(&scope, "collector", 120)
                .unwrap()
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(
        results
            .iter()
            .map(|result| result.payloads_erased)
            .sum::<u64>(),
        1
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_archive_and_erasure_race_leaves_no_subject_data() {
    let db = Arc::new(postgres_test_database());
    let prefix = format!("archive-erasure-race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("{prefix}:agent");
    let scope = scope(&prefix);
    let mut reference = reference(&prefix, "race");
    reference.actor = subject.clone();
    db.put_scoped_content(&scope, &reference, b"private", 100)
        .unwrap();
    let request = SubjectErasureRequest {
        subject_kind: "agent".into(),
        subject: subject.clone(),
        requested_by: "privacy-operator".into(),
        reason: "validated request".into(),
        timestamp: 200,
    };
    let barrier = Arc::new(Barrier::new(3));
    let archive = {
        let db = db.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.archive_lifecycle_records(300).unwrap()
        })
    };
    let erasure = {
        let db = db.clone();
        let barrier = barrier.clone();
        let request = request.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.erase_subject(&request).unwrap()
        })
    };
    barrier.wait();
    let archived = archive.join().unwrap();
    erasure.join().unwrap();
    if !archived.batch_id.is_empty() {
        assert!(db.verify_lifecycle_archive(&archived.batch_id).unwrap().ok);
    }
    // A second pass is a physical-residue check: the fail-closed scanner would
    // reject this if the racing archive had persisted the original subject.
    db.erase_subject(&SubjectErasureRequest {
        timestamp: 400,
        ..request
    })
    .unwrap();
}
