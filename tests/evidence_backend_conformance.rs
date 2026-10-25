use sekai_chisei::db::attestation::AttestationBackend;
use sekai_chisei::db::evidence::EvidenceBackend;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::handoff::HandoffBackend;
use sekai_chisei::db::postgres::{PostgresDb, off_runtime};
use sekai_chisei::db::runtime_db::RuntimeDb;
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
use sekai_chisei::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
use sekai_chisei::sekai::evidence_store::{
    EvidenceProducerCapability, EvidenceSchemaDefinition, EvidenceSubmissionFilter,
    canonical_content_digest,
};
use sekai_chisei::sekai::execution_evidence::{
    EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_TYPE, ExecutionEvidence, ExecutionLifecycleState,
};
use sekai_chisei::sekai::external_permit::{DEFAULT_SITE_ID, Redemption};
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

fn execution_producer(prefix: &str) -> EvidenceProducerCapability {
    EvidenceProducerCapability {
        producer_identity: format!("{prefix}:executor"),
        config_version: 1,
        source_types: vec!["host_executor".into()],
        source_instances: vec![format!("{prefix}:instance")],
        namespaces: vec![format!("{prefix}:ns")],
        evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
        target_kinds: vec!["action".into()],
        classification_ceiling: EvidenceClassification::Internal,
        allowed_intents: vec![EvidenceIntent::Upsert],
        allow_operation_attachment: false,
        replay_window_ms: 60_000,
        max_clock_skew_ms: 60_000,
        max_payload_bytes: 64 * 1024,
        max_relationships: 8,
        rate_limit_per_minute: 100,
        max_retained_submissions: 100,
        revoked: false,
    }
}

fn execution_report(
    prefix: &str,
    state: ExecutionLifecycleState,
    observed_at_ms: i64,
) -> ExecutionEvidence {
    ExecutionEvidence {
        version: EXECUTION_EVIDENCE_SCHEMA.into(),
        permit_id: format!("{prefix}:permit"),
        redemption_id: format!("{prefix}:redemption"),
        execution_id: format!("{prefix}:execution"),
        host_identity: format!("{prefix}:executor"),
        lifecycle_state: state,
        observed_at_ms,
        started_at_ms: (!matches!(state, ExecutionLifecycleState::Accepted)).then_some(1_200),
        finished_at_ms: state.is_terminal().then_some(1_400),
        enforced_preconditions: BTreeMap::new(),
        normalized_effects: vec![],
        affected_resource_references: vec![],
        cost_micros: 0,
        resource_use: BTreeMap::new(),
        artifact_hashes: vec![],
        exit_classification: String::new(),
        error_classification: String::new(),
        compensation_evidence_hashes: vec![],
        host_schema_version: "host-evidence/v1".into(),
        host_software_version: "executor/1.0".into(),
    }
}

fn execution_envelope(report: &ExecutionEvidence, prefix: &str, sequence: i64) -> EvidenceEnvelope {
    let content = serde_json::to_value(report).unwrap();
    EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "host_executor".into(),
        source_instance: format!("{prefix}:instance"),
        source_record_id: report.redemption_id.clone(),
        source_version: format!("state-{sequence}"),
        source_sequence: sequence,
        target: EvidenceTarget {
            namespace: format!("{prefix}:ns"),
            object_external_id: format!("{prefix}:action"),
            object_kind: "action".into(),
        },
        evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
        signal: EvidenceSignal::Delivery,
        schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: report.observed_at_ms,
        collected_at_ms: report.observed_at_ms,
        expires_at_ms: None,
        content_digest: canonical_content_digest(&content).unwrap(),
        content,
        relationships: vec![],
        producer_identity: report.host_identity.clone(),
        confidence_bps: 8_000,
        classification: EvidenceClassification::Internal,
        provenance: BTreeMap::new(),
        idempotency_key: format!("{}-{sequence}", report.redemption_id),
        intent: EvidenceIntent::Upsert,
        causality: None,
    }
}

fn insert_redemption(db: &RuntimeDb, redemption: &Redemption) {
    let json = serde_json::to_string(redemption).unwrap();
    match db {
        RuntimeDb::Sqlite(sqlite) => {
            sqlite
                .conn()
                .execute(
                    "INSERT INTO chisei_external_action_redemptions
                     (permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,
                      invocation_ordinal,redemption_id,evidence_due_at_ms)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    rusqlite::params![
                        redemption.permit_id,
                        redemption.idempotency_key,
                        redemption.execution_id,
                        json,
                        redemption.redeemed_at_ms,
                        redemption.invocation_ordinal,
                        redemption.redemption_id,
                        redemption.evidence_due_at_ms
                    ],
                )
                .unwrap();
        }
        RuntimeDb::Postgres(pg) => {
            let ordinal = i64::from(redemption.invocation_ordinal);
            off_runtime(|| {
                pg.connection()
                    .unwrap()
                    .execute(
                        "INSERT INTO chisei_external_action_redemptions
                     (permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,
                      invocation_ordinal,redemption_id,evidence_due_at_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                        &[
                            &redemption.permit_id,
                            &redemption.idempotency_key,
                            &redemption.execution_id,
                            &json,
                            &redemption.redeemed_at_ms,
                            &ordinal,
                            &redemption.redemption_id,
                            &redemption.evidence_due_at_ms,
                        ],
                    )
                    .unwrap();
            });
        }
    }
}

fn execution_state(db: &RuntimeDb, redemption_id: &str) -> String {
    match db {
        RuntimeDb::Sqlite(sqlite) => sqlite
            .conn()
            .query_row(
                "SELECT lifecycle_state FROM sekai_external_action_execution_state
                 WHERE redemption_id=?1",
                [redemption_id],
                |row| row.get(0),
            )
            .unwrap(),
        RuntimeDb::Postgres(pg) => off_runtime(|| {
            pg.connection()
                .unwrap()
                .query_one(
                    "SELECT lifecycle_state FROM sekai_external_action_execution_state
                 WHERE redemption_id=$1",
                    &[&redemption_id],
                )
                .unwrap()
                .get(0)
        }),
    }
}

fn conflict_alert_count(db: &RuntimeDb, redemption_id: &str) -> i64 {
    match db {
        RuntimeDb::Sqlite(sqlite) => sqlite
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_external_action_execution_alerts
                 WHERE kind='conflicting_execution_evidence' AND redemption_id=?1",
                [redemption_id],
                |row| row.get(0),
            )
            .unwrap(),
        RuntimeDb::Postgres(pg) => off_runtime(|| {
            pg.connection()
                .unwrap()
                .query_one(
                    "SELECT COUNT(*)::bigint FROM sekai_external_action_execution_alerts
                 WHERE kind='conflicting_execution_evidence' AND redemption_id=$1",
                    &[&redemption_id],
                )
                .unwrap()
                .get(0)
        }),
    }
}

/// Admit, reject invalid host identity, record Accepted→Started→OutcomeUnknown,
/// idempotent re-record, conflict after terminal, and resolve on both backends.
/// Shared/memory RuntimeDb only: dest-pair SchemaPlane::Sekai has no
/// `chisei_external_action_redemptions` until permit redeem is dual-backend (#1323).
pub(crate) fn exercise_execution_recording(db: &RuntimeDb, prefix: &str) {
    let producer = execution_producer(prefix);
    db.create_object(&Object {
        id: format!("{prefix}:action-object"),
        kind: "action".into(),
        name: "action".into(),
        namespace: format!("{prefix}:ns"),
        external_id: format!("{prefix}:action"),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    })
    .unwrap();
    db.upsert_evidence_producer(&producer, 1_000).unwrap();
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            compatible_versions: vec![],
        },
        1_000,
    )
    .unwrap();
    let redemption = Redemption {
        version: "external-action.redemption/v1".into(),
        permit_id: format!("{prefix}:permit"),
        redemption_id: format!("{prefix}:redemption"),
        executor: producer.producer_identity.clone(),
        execution_id: format!("{prefix}:execution"),
        idempotency_key: format!("{prefix}:redeem"),
        redeemed_at_ms: 1_000,
        invocation_ordinal: 1,
        evidence_due_at_ms: 2_000,
        site_id: DEFAULT_SITE_ID.into(),
    };
    insert_redemption(db, &redemption);

    let lifecycle = EvidenceAdmissionLifecycle::new(db);
    let mut invalid = execution_report(prefix, ExecutionLifecycleState::Accepted, 1_500);
    invalid.host_identity = format!("{prefix}:other");
    let mut invalid = execution_envelope(&invalid, prefix, 10);
    invalid.producer_identity = producer.producer_identity.clone();
    let rejected = lifecycle
        .admit(
            &invalid,
            &producer.producer_identity,
            invalid.observed_at_ms,
        )
        .unwrap();
    assert!(!rejected.admitted);
    assert!(!rejected.execution_recorded);
    assert_eq!(rejected.submission.lifecycle_state.as_str(), "rejected");

    for (sequence, state) in [
        (1, ExecutionLifecycleState::Accepted),
        (2, ExecutionLifecycleState::Started),
        (3, ExecutionLifecycleState::OutcomeUnknown),
    ] {
        let report = execution_report(prefix, state, 1_500 + sequence);
        let envelope = execution_envelope(&report, prefix, sequence);
        let admitted = lifecycle
            .admit(
                &envelope,
                &producer.producer_identity,
                report.observed_at_ms,
            )
            .unwrap();
        assert!(admitted.admitted);
        assert!(admitted.execution_recorded);
        assert!(
            admitted
                .projection
                .as_ref()
                .is_some_and(|value| value.projected)
        );
        assert_eq!(admitted.submission.lifecycle_state.as_str(), "available");
        assert!(
            db.record_execution_evidence(&admitted.submission.id)
                .unwrap()
        );
        let resolved = db
            .get_evidence_submission(&admitted.submission.id)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.id, admitted.submission.id);
        assert_eq!(resolved.lifecycle_state.as_str(), "available");
    }
    assert_eq!(
        execution_state(db, &redemption.redemption_id),
        "outcome_unknown"
    );

    let conflict = execution_report(prefix, ExecutionLifecycleState::Failed, 1_600);
    let conflict = execution_envelope(&conflict, prefix, 4);
    let admitted = lifecycle
        .admit(
            &conflict,
            &producer.producer_identity,
            conflict.observed_at_ms,
        )
        .unwrap();
    assert!(admitted.admitted);
    assert!(!admitted.execution_recorded);
    assert!(
        !db.record_execution_evidence(&admitted.submission.id)
            .unwrap()
    );
    assert_eq!(conflict_alert_count(db, &redemption.redemption_id), 1);
    assert_eq!(
        execution_state(db, &redemption.redemption_id),
        "outcome_unknown"
    );
}

#[test]
fn sqlite_evidence_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_backend(&db, &db, &db, &db, "sqlite");
    exercise_execution_recording(&RuntimeDb::memory(), "sqlite-exec");
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
    let exec_prefix = format!("pg-exec-{}", uuid::Uuid::new_v4().simple());
    exercise_execution_recording(&RuntimeDb::Postgres(Arc::new(db)), &exec_prefix);
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
