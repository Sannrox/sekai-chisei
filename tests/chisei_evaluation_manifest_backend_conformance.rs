//! Shared SQLite/PostgreSQL persistence conformance for resolved evaluation manifests.

use sekai_chisei::chisei::evaluation_manifest::*;
use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb, sekai::SekaiDb};
use std::sync::Arc;

fn manifest(
    namespace: &str,
    subject_identity: &str,
    created_at_ms: i64,
) -> ResolvedEvaluationManifest {
    prepare_manifest(ResolvedEvaluationManifest {
        contract_version: MANIFEST_CONTRACT.into(),
        resolver_version: RESOLVER_VERSION.into(),
        manifest_id: String::new(),
        manifest_digest: String::new(),
        namespace: namespace.into(),
        plan_version_id: "evaluation-plan:fixture".into(),
        plan_digest: format!("sha256:{}", "a".repeat(64)),
        subject_profile: "document/v1".into(),
        subject_identity: subject_identity.into(),
        subject_content_digest: format!("sha256:{}", "b".repeat(64)),
        invariant_set_id: "invariant-set:fixture".into(),
        invariant_set_digest: format!("sha256:{}", "c".repeat(64)),
        invariant_profile_digest: format!("sha256:{}", "d".repeat(64)),
        evaluation_time_ms: 42,
        resolved_by: "operator".into(),
        requirements: vec![],
        nodes: vec![ResolvedEvaluationNode {
            node_id: "schema".into(),
            evaluator: ResolvedEvaluatorBinding {
                definition_id: "evaluator-definition:fixture".into(),
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
                invariant_version_id: "governed-invariant-version:fixture".into(),
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
        created_at_ms,
    })
    .unwrap()
}

fn exercise(db: &RuntimeDb, namespace: &str, subject_identity: &str) -> String {
    let first = manifest(namespace, subject_identity, 100);
    let stored = db
        .put_evaluation_manifest(&first, "resolve-1", "request-digest-1")
        .unwrap();
    assert_eq!(stored, first);
    assert_eq!(
        db.put_evaluation_manifest(&first, "resolve-1", "request-digest-1")
            .unwrap(),
        first
    );
    let replay = db
        .get_evaluation_manifest_for_request(namespace, "operator", "resolve-1")
        .unwrap()
        .unwrap();
    assert_eq!(replay.request_digest, "request-digest-1");
    assert_eq!(replay.manifest, first);

    // Creation time is storage metadata rather than a content-bound input. A
    // second request for the same immutable inputs reuses the original row.
    let later = manifest(namespace, subject_identity, 200);
    assert_eq!(later.manifest_digest, first.manifest_digest);
    let deduplicated = db
        .put_evaluation_manifest(&later, "resolve-2", "request-digest-2")
        .unwrap();
    assert_eq!(deduplicated.created_at_ms, 100);
    assert_eq!(
        db.get_evaluation_manifest_for_request(namespace, "operator", "resolve-2")
            .unwrap()
            .unwrap()
            .manifest,
        first
    );

    assert!(
        db.put_evaluation_manifest(&first, "resolve-1", "changed")
            .unwrap_err()
            .contains("different content")
    );
    assert_eq!(
        db.get_evaluation_manifest(&first.manifest_digest)
            .unwrap()
            .unwrap(),
        first
    );
    first.manifest_digest
}

#[test]
fn sqlite_evaluation_manifest_conformance_and_restart() {
    let path = std::env::temp_dir().join(format!(
        "sekai-evaluation-manifest-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let path = path.to_string_lossy().into_owned();
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    let digest = exercise(&db, "sqlite-manifest", "document:sqlite");
    drop(db);

    let restarted = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    assert!(
        restarted
            .get_evaluation_manifest(&digest)
            .unwrap()
            .is_some()
    );
    assert!(
        restarted
            .get_evaluation_manifest_for_request("sqlite-manifest", "operator", "resolve-1",)
            .unwrap()
            .is_some()
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
fn postgres_evaluation_manifest_conformance_and_restart() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("pg-manifest-{suffix}");
    let subject_identity = format!("document:{suffix}");
    let digest = exercise(&postgres(), &namespace, &subject_identity);
    assert!(
        postgres()
            .get_evaluation_manifest(&digest)
            .unwrap()
            .is_some()
    );
}
