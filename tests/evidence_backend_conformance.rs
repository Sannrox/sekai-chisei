use sekai_chisei::db::attestation::AttestationBackend;
use sekai_chisei::db::evidence::EvidenceBackend;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::handoff::HandoffBackend;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::action::RiskClass;
use sekai_chisei::sekai::action_policy::{ActionDecision, ActionPolicy};
use sekai_chisei::sekai::attestation::{
    ActionAttestationInput, EVIDENCE_ATTESTATION_HASH, EVIDENCE_ATTESTATION_ID,
    build_action_attestation,
};
use sekai_chisei::sekai::audit::Decision;
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use sekai_chisei::sekai::evidence_store::{
    EvidenceProducerCapability, EvidenceSchemaDefinition, EvidenceSubmissionFilter,
    canonical_content_digest,
};
use sekai_chisei::sekai::handoff::{HANDOFF_VERSION, HandoffManifest, HandoffReference};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Barrier};

fn capability(prefix: &str) -> EvidenceProducerCapability {
    EvidenceProducerCapability {
        producer_identity: format!("{prefix}:producer"),
        config_version: 1,
        source_types: vec!["verification_system".into()],
        source_instances: vec![format!("{prefix}:checks")],
        namespaces: vec![format!("{prefix}:namespace")],
        evidence_types: vec!["verification.result".into()],
        target_kinds: vec!["service".into()],
        classification_ceiling: EvidenceClassification::Confidential,
        allowed_intents: vec![
            EvidenceIntent::Upsert,
            EvidenceIntent::Retract,
            EvidenceIntent::MarkStale,
        ],
        allow_operation_attachment: true,
        replay_window_ms: 10_000,
        max_clock_skew_ms: 1_000,
        max_payload_bytes: 1_024,
        max_relationships: 4,
        rate_limit_per_minute: 20,
        max_retained_submissions: 100,
        revoked: false,
    }
}

fn envelope(prefix: &str) -> EvidenceEnvelope {
    let content = json!({"result": "passed"});
    EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "verification_system".into(),
        source_instance: format!("{prefix}:checks"),
        source_record_id: format!("{prefix}:run"),
        source_version: "attempt-1".into(),
        source_sequence: 1,
        target: EvidenceTarget {
            namespace: format!("{prefix}:namespace"),
            object_external_id: format!("{prefix}:service"),
            object_kind: "service".into(),
        },
        evidence_type: "verification.result".into(),
        signal: EvidenceSignal::Verification,
        schema_id: "verification.result".into(),
        schema_version: "1.0.0".into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: 1_000,
        collected_at_ms: 1_010,
        expires_at_ms: Some(2_000),
        content_digest: canonical_content_digest(&content).unwrap(),
        content,
        relationships: vec![],
        producer_identity: format!("{prefix}:producer"),
        confidence_bps: 9_500,
        classification: EvidenceClassification::Internal,
        provenance: BTreeMap::new(),
        idempotency_key: format!("{prefix}:delivery"),
        intent: EvidenceIntent::Upsert,
        causality: None,
    }
}

fn exercise_evidence(db: &dyn EvidenceBackend, graph: &dyn GraphBackend, prefix: &str) {
    graph
        .create_object(
            &Object {
                id: format!("{prefix}:service-object"),
                kind: "service".into(),
                name: "service".into(),
                namespace: format!("{prefix}:namespace"),
                external_id: format!("{prefix}:service"),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
            "test",
        )
        .unwrap();
    let capability = capability(prefix);
    db.upsert_evidence_producer(&capability, 100).unwrap();
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            evidence_type: "verification.result".into(),
            compatible_versions: vec![],
        },
        100,
    )
    .unwrap();
    let envelope = envelope(prefix);
    let first = db
        .submit_evidence(&envelope, &capability.producer_identity, 1_010)
        .unwrap();
    assert!(first.accepted);
    assert!(!first.deduplicated);
    assert_eq!(
        first.submission.envelope.as_ref().unwrap().content,
        envelope.content
    );
    let replay = db
        .submit_evidence(&envelope, &capability.producer_identity, 1_011)
        .unwrap();
    assert!(replay.deduplicated);
    assert_eq!(replay.submission.id, first.submission.id);
    assert_eq!(
        db.evidence_lifecycle_history(&first.submission.id).unwrap(),
        vec![
            sekai_chisei::sekai::evidence::EvidenceLifecycleState::Received,
            sekai_chisei::sekai::evidence::EvidenceLifecycleState::Validated,
            sekai_chisei::sekai::evidence::EvidenceLifecycleState::Deduplicated,
            sekai_chisei::sekai::evidence::EvidenceLifecycleState::Authorized,
        ]
    );
    assert_eq!(
        db.list_evidence_submissions(&EvidenceSubmissionFilter {
            namespace: Some(capability.namespaces[0].clone()),
            ..Default::default()
        })
        .unwrap()
        .len(),
        1
    );
    let projection = db
        .project_evidence_submission(&first.submission.id, 1_100)
        .unwrap();
    assert!(projection.projected);
    assert_eq!(
        projection.lifecycle_state,
        sekai_chisei::sekai::evidence::EvidenceLifecycleState::Available
    );
    let projected = graph
        .get_object(projection.evidence_object_id.as_deref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        projected
            .properties
            .get("observed_at_ms")
            .map(String::as_str),
        Some("1000")
    );

    let mut conflicting = envelope;
    conflicting.content = json!({"result": "failed"});
    conflicting.content_digest = canonical_content_digest(&conflicting.content).unwrap();
    let rejected = db
        .submit_evidence(&conflicting, &capability.producer_identity, 1_012)
        .unwrap();
    assert!(!rejected.accepted);
    assert_eq!(
        rejected.submission.rejection_code.as_deref(),
        Some("idempotency_conflict")
    );
    assert!(rejected.submission.envelope.is_none());
}

fn exercise_handoff(db: &dyn HandoffBackend, prefix: &str) {
    let manifest = HandoffManifest {
        schema_version: HANDOFF_VERSION.into(),
        id: format!("{prefix}:handoff"),
        namespace: format!("{prefix}:namespace"),
        parent_operation_id: "operation".into(),
        parent_attempt_id: "attempt".into(),
        parent_work_unit_id: "work".into(),
        references: vec![HandoffReference {
            kind: "evidence".into(),
            id: "evidence-1".into(),
            version: "v1".into(),
            omitted: false,
            omission_reason: String::new(),
        }],
        creator_principal: format!("{prefix}:creator"),
        intended_principal: format!("{prefix}:receiver"),
        intended_scope: "review".into(),
        purpose: "continue verification".into(),
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
        digest: String::new(),
        supersedes_manifest_id: String::new(),
        revoked: false,
    };
    let created = db.create_handoff(&manifest, "create-1").unwrap();
    assert_eq!(db.create_handoff(&manifest, "create-1").unwrap(), created);
    assert_eq!(
        db.get_handoff_by_request(&manifest.creator_principal, "create-1")
            .unwrap()
            .unwrap()
            .1,
        created
    );
    assert!(!db.handoff_is_superseded(&created.id).unwrap());
    let revoked = db
        .revoke_handoff(&created.id, "operator", "obsolete", "revoke-1", 1_100)
        .unwrap();
    assert!(revoked.revoked);
    assert!(
        db.revoke_handoff(&created.id, "operator", "changed", "revoke-1", 1_101)
            .is_err()
    );
}

fn exercise_attestation(db: &dyn AttestationBackend, prefix: &str) {
    let policy = ActionPolicy::allow_all(format!("{prefix}:scope"));
    let attestation = build_action_attestation(ActionAttestationInput {
        decision_id: &format!("{prefix}:decision"),
        policy: &policy,
        action: "read_object",
        actor: "actor",
        risk: RiskClass::Read,
        namespace: "namespace",
        decision: ActionDecision::Allow,
        created: 1_000,
    });
    let decision = Decision {
        id: attestation.decision_id.clone(),
        timestamp: 1_000,
        actor: "actor".into(),
        action: "read_object".into(),
        reason: "allowed".into(),
        evidence: HashMap::from([
            (EVIDENCE_ATTESTATION_ID.into(), attestation.id.clone()),
            (
                EVIDENCE_ATTESTATION_HASH.into(),
                attestation.content_hash.clone(),
            ),
        ]),
        target_id: "object".into(),
        outcome: "allow".into(),
    };
    db.record_decision_with_attestation(&decision, Some(&attestation))
        .unwrap();
    assert_eq!(
        db.get_attestation(&attestation.id).unwrap(),
        Some(attestation.clone())
    );
    assert!(db.verify_attestation(&attestation.id).unwrap().ok);
}

fn exercise_backend(
    evidence: &dyn EvidenceBackend,
    graph: &dyn GraphBackend,
    handoffs: &dyn HandoffBackend,
    attestations: &dyn AttestationBackend,
    prefix: &str,
) {
    exercise_evidence(evidence, graph, prefix);
    exercise_handoff(handoffs, prefix);
    exercise_attestation(attestations, prefix);
}

#[test]
fn sqlite_evidence_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_backend(&db, &db, &db, &db, "sqlite");
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
fn postgres_evidence_conformance() {
    let db = postgres_test_database();
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_backend(&db, &db, &db, &db, &prefix);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_idempotent_submission_has_one_outcome() {
    let db = Arc::new(postgres_test_database());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let capability = capability(&prefix);
    db.upsert_evidence_producer(&capability, 100).unwrap();
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            evidence_type: "verification.result".into(),
            compatible_versions: vec![],
        },
        100,
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [(), ()].map(|_| {
        let db = db.clone();
        let barrier = barrier.clone();
        let envelope = envelope(&prefix);
        let producer = capability.producer_identity.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.submit_evidence(&envelope, &producer, 1_010).unwrap()
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results[0].submission.id, results[1].submission.id);
    assert_eq!(
        results.iter().filter(|result| !result.deduplicated).count(),
        1
    );
}
