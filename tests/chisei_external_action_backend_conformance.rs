//! Shared SQLite/PostgreSQL conformance for external-action authorization.

use sekai_chisei::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, DECISION_VERSION, ExternalActionDecision,
    ExternalActionRequest, REQUEST_VERSION,
};
use sekai_chisei::db::chisei_external_action::ChiseiExternalActionBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use std::collections::BTreeMap;

trait ExternalHarness: ChiseiExternalActionBackend {}
impl ExternalHarness for SekaiDb {}
impl ExternalHarness for PostgresDb {}

fn request(prefix: &str) -> ExternalActionRequest {
    ExternalActionRequest {
        version: REQUEST_VERSION.into(),
        operation_id: format!("{prefix}-op"),
        parent_operation_id: format!("{prefix}-parent"),
        attempt_id: format!("{prefix}-attempt"),
        request_id: format!("{prefix}-req"),
        actor: format!("{prefix}-actor"),
        namespace: format!("{prefix}-ns"),
        requesting_harness: "harness-a".into(),
        intended_executor: "executor-a".into(),
        action_type: "repository.write/v1".into(),
        parameter_schema: "repository.write.params/v1".into(),
        canonical_arguments_digest: "sha256:arguments".into(),
        policy_summary: BTreeMap::from([("branch".into(), "feature".into())]),
        target_selectors: vec![format!("project:{prefix}-ns/repo:example/repo")],
        immutable_preconditions: BTreeMap::from([("head".into(), "abc123".into())]),
        risk_class: "write".into(),
        expected_effects: vec!["git.commit".into()],
        requested_invocation_count: 1,
        deadline_ms: 4_102_444_800_000,
        estimated_cost_micros: 0,
        estimated_volume: 1,
        affected_resource_count: 1,
        rollback_capability: "revert_commit".into(),
        required_host_capabilities: vec!["git.ref-precondition/v1".into()],
        idempotency_key: format!("{prefix}-idem"),
        policy_project: format!("{prefix}-ns"),
    }
}

fn exercise(db: &dyn ExternalHarness, prefix: &str) {
    let request = request(prefix);
    let digest = request.canonical_digest().unwrap();
    let authorization_id = format!("{prefix}-auth");
    assert_eq!(
        db.claim_external_action_authorization(&request, &digest, &authorization_id, 1)
            .unwrap(),
        AuthorizationClaim::Claimed(authorization_id.clone())
    );
    // In-progress claim until record is stored.
    assert_eq!(
        db.claim_external_action_authorization(&request, &digest, &authorization_id, 1)
            .unwrap(),
        AuthorizationClaim::InProgress
    );

    let record = AuthorizationRecord {
        request: request.clone(),
        decision: ExternalActionDecision {
            version: DECISION_VERSION.into(),
            authorization_id: authorization_id.clone(),
            request_digest: digest.clone(),
            decision: "allow".into(),
            reason: "conformance".into(),
            approval_id: String::new(),
            policy_scope: request.namespace.clone(),
            policy_version: "sha256:policy".into(),
            created_at_ms: 1,
            expires_at_ms: request.deadline_ms,
            cancelled_at_ms: 0,
            assurance: Default::default(),
        },
        approval_status: String::new(),
        budget_reserved: false,
        blast_radius_reserved: false,
        decision_actor: request.actor.clone(),
        decision_updated_at_ms: 1,
    };
    db.put_external_action_authorization(&record).unwrap();
    assert_eq!(
        db.get_external_action_authorization(
            &request.actor,
            &request.operation_id,
            &request.idempotency_key
        )
        .unwrap()
        .unwrap()
        .decision
        .authorization_id,
        authorization_id
    );
    assert_eq!(
        db.get_external_action_authorization_by_id(&authorization_id)
            .unwrap()
            .unwrap()
            .decision
            .decision,
        "allow"
    );

    db.reserve_external_action_blast_radius(&authorization_id, &request, Some(10), Some(10))
        .unwrap();
    // Idempotent reserve for same identity.
    db.reserve_external_action_blast_radius(&authorization_id, &request, Some(10), Some(10))
        .unwrap();
    db.release_external_action_blast_radius(&authorization_id, &request)
        .unwrap();

    let mut next = record.clone();
    next.decision.decision = "deny".into();
    assert!(
        db.compare_and_swap_external_action_authorization(&record, &next)
            .unwrap()
    );
    assert!(
        !db.compare_and_swap_external_action_authorization(&record, &next)
            .unwrap()
    );

    let listed = db.list_external_action_authorizations().unwrap();
    assert!(
        listed
            .iter()
            .any(|item| item.decision.authorization_id == authorization_id)
    );
}

#[test]
fn sqlite_chisei_external_action_conformance() {
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
fn postgres_chisei_external_action_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .get_external_action_authorization_by_id(&format!("{prefix}-auth"))
            .unwrap()
            .is_some()
    );
}
