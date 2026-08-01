//! Shared SQLite/PostgreSQL conformance for kioku memory lifecycle.

use sekai_chisei::chisei::kioku::{
    HumanMemoryReview, HumanReviewAction, KIOKU_MEMORY_VERSION, KiokuEvidenceLink, KiokuMemory,
    MemoryEvidenceStance, MemoryKind, MemoryLifecycleState,
};
use sekai_chisei::db::chisei_kioku::ChiseiKiokuBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::evidence::EvidenceClassification;

trait KiokuHarness: ChiseiKiokuBackend {}
impl KiokuHarness for SekaiDb {}
impl KiokuHarness for PostgresDb {}

fn candidate(prefix: &str) -> KiokuMemory {
    KiokuMemory {
        contract_version: KIOKU_MEMORY_VERSION.into(),
        id: format!("{prefix}-memory"),
        version: 1,
        kind: MemoryKind::Warning,
        claim: "Verify generated migrations before deployment".into(),
        namespace: format!("{prefix}-ns"),
        operation_classes: vec!["schema_change".into()],
        affinity_object_ids: vec!["component:migrations".into()],
        outcome_definition: "deployment verification passed".into(),
        confidence_bps: 10_000,
        sample_size: 1,
        uncertainty: "single verified operation".into(),
        producer_identity: "kioku:test".into(),
        derivation_method: "verified_binary_outcomes/v1".into(),
        classification: EvidenceClassification::Internal,
        retention_until_ms: Some(300),
        state: MemoryLifecycleState::Candidate,
        created_at_ms: 100,
        reviewed_at_ms: None,
        expires_at_ms: Some(200),
        last_confirmed_at_ms: Some(100),
        supersedes: None,
        evidence_basis: vec![],
        evidence_basis_digest: String::new(),
        reassessment_key: String::new(),
        reassessment_actor: String::new(),
    }
}

fn evidence(memory: &KiokuMemory) -> KiokuEvidenceLink {
    KiokuEvidenceLink {
        memory_id: memory.id.clone(),
        memory_version: memory.version,
        operation_id: format!("{}-op", memory.id),
        verification_event_id: "verify-1".into(),
        evidence_reference: "artifact://verification".into(),
        evidence_digest: "abc123".into(),
        stance: MemoryEvidenceStance::Supporting,
        outcome_metric: "deployment verification passed".into(),
        outcome_value: 1.0,
        observed_at_ms: 100,
    }
}

fn exercise(db: &dyn KiokuHarness, prefix: &str) {
    let memory = candidate(prefix);
    let link = evidence(&memory);
    db.insert_kioku_memory(&memory, std::slice::from_ref(&link))
        .unwrap();
    assert_eq!(
        db.get_kioku_memory(&memory.id, memory.version)
            .unwrap()
            .unwrap()
            .claim,
        memory.claim
    );
    assert_eq!(
        db.list_kioku_evidence(&memory.id, memory.version)
            .unwrap()
            .len(),
        1
    );
    let listed = db
        .list_kioku_candidates(&memory.namespace, Some("schema_change"), 10)
        .unwrap();
    assert_eq!(listed.len(), 1);

    let validation = db
        .validate_kioku_candidate(&memory.id, memory.version)
        .unwrap();
    assert!(validation.valid, "{:?}", validation.errors);

    let promoted = db
        .review_kioku_candidate(
            &memory.id,
            memory.version,
            HumanMemoryReview {
                action: HumanReviewAction::Promote,
                reviewer: "reviewer".into(),
                rationale: "verified".into(),
                reviewed_at_ms: 120,
            },
        )
        .unwrap();
    assert_eq!(promoted.state, MemoryLifecycleState::Active);

    let disabled = db
        .disable_kioku_memory(&memory.id, memory.version, "reviewer", "regressed", 130)
        .unwrap();
    assert_eq!(disabled.state, MemoryLifecycleState::Rejected);
    let events = db
        .list_kioku_lifecycle_events(&memory.id, memory.version)
        .unwrap();
    assert!(events.iter().any(|event| event.action == "created"));
    assert!(events.iter().any(|event| event.action == "promoted"));
    assert!(events.iter().any(|event| event.action == "disabled"));
}

#[test]
fn sqlite_chisei_kioku_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_chisei_kioku_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert_eq!(
        restarted
            .get_kioku_memory(&format!("{prefix}-memory"), 1)
            .unwrap()
            .unwrap()
            .state,
        MemoryLifecycleState::Rejected
    );
}
