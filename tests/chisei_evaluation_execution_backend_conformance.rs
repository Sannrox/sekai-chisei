//! SQLite/PostgreSQL conformance for receipt-authoritative evaluation indexes.

use sekai_chisei::chisei::evaluation_execution::{
    EXECUTION_OPERATION_CLASS, EXECUTOR_VERSION, EvaluationExecutionIndex,
};
use sekai_chisei::chisei::evaluation_manifest::*;
use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface,
};
use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb, sekai::SekaiDb};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

fn manifest(namespace: &str, suffix: &str) -> ResolvedEvaluationManifest {
    prepare_manifest(ResolvedEvaluationManifest {
        contract_version: MANIFEST_CONTRACT.into(),
        resolver_version: RESOLVER_VERSION.into(),
        manifest_id: String::new(),
        manifest_digest: String::new(),
        namespace: namespace.into(),
        plan_version_id: format!("evaluation-plan:{suffix}"),
        plan_digest: format!("sha256:{}", "a".repeat(64)),
        subject_profile: "document/v1".into(),
        subject_identity: format!("document:{suffix}"),
        subject_content_digest: format!("sha256:{}", "b".repeat(64)),
        invariant_set_id: format!("invariant-set:{suffix}"),
        invariant_set_digest: format!("sha256:{}", "c".repeat(64)),
        invariant_profile_digest: format!("sha256:{}", "d".repeat(64)),
        evaluation_time_ms: 42,
        resolved_by: "operator".into(),
        requirements: vec![],
        nodes: vec![ResolvedEvaluationNode {
            node_id: "schema".into(),
            evaluator: ResolvedEvaluatorBinding {
                definition_id: format!("evaluator-definition:{suffix}"),
                definition_digest: format!("sha256:{}", "e".repeat(64)),
                implementation_digest: format!("sha256:{}", "f".repeat(64)),
                stochastic_policy: None,
            },
            depends_on_node_ids: vec![],
            input_bindings: vec![ResolvedInputBinding {
                name: "document".into(),
                source_kind: "invariant".into(),
                schema_id: "schema://document/v1".into(),
            }],
            parameters_json: "{}".into(),
            invariants: vec![ResolvedInvariantBinding {
                invariant_version_id: format!("governed-invariant-version:{suffix}"),
                content_digest: format!("sha256:{}", "1".repeat(64)),
                predicate_kind: "schema_conforms".into(),
                input_schema: "schema://document/v1".into(),
                result_schema: "schema://pass-fail/v1".into(),
                evidence_types: vec![],
                provenance_evidence_object_ids: vec![],
                waiver_version_ids: vec![],
            }],
            evidence_object_ids: vec![],
            classification: "required".into(),
        }],
        evidence: vec![],
        waivers: vec![],
        created_at_ms: 100,
    })
    .unwrap()
}

fn execution(
    manifest: &ResolvedEvaluationManifest,
) -> (EvaluationExecutionIndex, OperationReceipt) {
    let operation_id = format!(
        "evaluation-execution:{}",
        manifest.manifest_digest.trim_start_matches("sha256:")
    );
    let intent = OperationReceiptEvent {
        event_id: format!("{operation_id}:intent"),
        operation_id: operation_id.clone(),
        parent_event_id: None,
        timestamp_ms: 200,
        kind: ReceiptEventKind::IntentRecorded,
        surface: ReceiptSurface::Intent,
        actor: "operator".into(),
        references: vec![],
        attributes: BTreeMap::from([("manifest_digest".into(), manifest.manifest_digest.clone())]),
    };
    (
        EvaluationExecutionIndex {
            manifest_digest: manifest.manifest_digest.clone(),
            operation_id: operation_id.clone(),
            namespace: manifest.namespace.clone(),
            executor_version: EXECUTOR_VERSION.into(),
            started_by: "operator".into(),
            created_at_ms: 200,
        },
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id,
            parent_operation_id: None,
            namespace: manifest.namespace.clone(),
            operation_class: EXECUTION_OPERATION_CLASS.into(),
            initiating_actor: "operator".into(),
            schema_version: EXECUTOR_VERSION.into(),
            policy_version: "required_all_pass_advisory_observed/v1".into(),
            started_at_ms: 200,
            completed_at_ms: None,
            events: vec![intent],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
        },
    )
}

fn exercise(db: &RuntimeDb, namespace: &str, suffix: &str) -> (String, String) {
    let manifest = manifest(namespace, suffix);
    db.put_evaluation_manifest(&manifest, "resolve", "request-digest")
        .unwrap();
    let (index, receipt) = execution(&manifest);
    assert_eq!(
        db.create_evaluation_execution(&index, &receipt).unwrap(),
        index
    );
    assert_eq!(
        db.create_evaluation_execution(&index, &receipt).unwrap(),
        index
    );
    assert_eq!(
        db.get_evaluation_execution_index(&manifest.manifest_digest)
            .unwrap()
            .unwrap(),
        index
    );
    let step = OperationReceiptEvent {
        event_id: format!("{}:step:schema", index.operation_id),
        operation_id: index.operation_id.clone(),
        parent_event_id: Some(format!("{}:intent", index.operation_id)),
        timestamp_ms: 201,
        kind: ReceiptEventKind::VerificationRecorded,
        surface: ReceiptSurface::Verification,
        actor: "chisei.evaluation-executor".into(),
        references: vec![],
        attributes: BTreeMap::from([("status".into(), "pass".into())]),
    };
    db.append_operation_receipt_event(&index.operation_id, step)
        .unwrap();
    assert_eq!(
        db.get_operation_receipt(&index.operation_id)
            .unwrap()
            .unwrap()
            .events
            .len(),
        2
    );
    (manifest.manifest_digest, index.operation_id)
}

#[test]
fn sqlite_evaluation_execution_conformance_restart_and_concurrency() {
    let path = std::env::temp_dir().join(format!(
        "sekai-evaluation-execution-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let path = path.to_string_lossy().into_owned();
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    let manifest = manifest("sqlite-execution", "sqlite");
    db.put_evaluation_manifest(&manifest, "resolve", "request-digest")
        .unwrap();
    let (index, receipt) = execution(&manifest);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let db = db.clone();
        let barrier = barrier.clone();
        let index = index.clone();
        let receipt = receipt.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            db.create_evaluation_execution(&index, &receipt).unwrap()
        }));
    }
    barrier.wait();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), index);
    }
    let step = OperationReceiptEvent {
        event_id: format!("{}:step:schema", index.operation_id),
        operation_id: index.operation_id.clone(),
        parent_event_id: Some(format!("{}:intent", index.operation_id)),
        timestamp_ms: 201,
        kind: ReceiptEventKind::VerificationRecorded,
        surface: ReceiptSurface::Verification,
        actor: "chisei.evaluation-executor".into(),
        references: vec![],
        attributes: BTreeMap::from([("status".into(), "pass".into())]),
    };
    db.append_operation_receipt_event(&index.operation_id, step)
        .unwrap();
    drop(db);

    let restarted = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    assert_eq!(
        restarted
            .get_evaluation_execution_index(&manifest.manifest_digest)
            .unwrap()
            .unwrap(),
        index
    );
    assert_eq!(
        restarted
            .get_operation_receipt(&index.operation_id)
            .unwrap()
            .unwrap()
            .events
            .len(),
        2
    );
    std::fs::remove_file(path).ok();
}

fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_evaluation_execution_conformance_and_restart() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("pg-execution-{suffix}");
    let (manifest_digest, operation_id) = exercise(&postgres(), &namespace, &suffix);
    let restarted = postgres();
    assert!(
        restarted
            .get_evaluation_execution_index(&manifest_digest)
            .unwrap()
            .is_some()
    );
    assert!(
        restarted
            .get_operation_receipt(&operation_id)
            .unwrap()
            .is_some()
    );
}
