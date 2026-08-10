//! Shared SQLite/PostgreSQL conformance for external permit policy and issuance markers.

use sekai_chisei::chisei::external_action::PERMIT_VERSION;
use sekai_chisei::chisei::external_permit::{ExternalPermitPolicy, Permit};
use sekai_chisei::db::chisei_external_permit::ChiseiExternalPermitBackend;
use sekai_chisei::db::decision::DecisionBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use std::collections::BTreeMap;

trait PermitHarness: ChiseiExternalPermitBackend + DecisionBackend {}
impl PermitHarness for SekaiDb {}
impl PermitHarness for PostgresDb {}

fn sample_permit(prefix: &str) -> Permit {
    Permit {
        version: PERMIT_VERSION.into(),
        permit_id: format!("{prefix}-permit"),
        authorization_id: format!("{prefix}-auth"),
        request_digest: "sha256:req".into(),
        issuer: "issuer".into(),
        subject_actor: format!("{prefix}-actor"),
        namespace: format!("{prefix}-ns"),
        operation_id: format!("{prefix}-op"),
        requesting_harness: "harness".into(),
        executor: "executor".into(),
        action_type: "repository.write/v1".into(),
        parameter_schema: "repository.write.params/v1".into(),
        canonical_arguments_digest: "sha256:args".into(),
        target_selectors: vec!["repo".into()],
        immutable_preconditions: BTreeMap::new(),
        allowed_effects: vec!["git.commit".into()],
        required_host_capabilities: vec![],
        constraints: vec![],
        risk_class: "write".into(),
        budget_micros: 0,
        volume_limit: 1,
        blast_radius_limit: 1,
        max_invocations: 1,
        not_before_ms: 0,
        expires_at_ms: 9_999_999_999_999,
        redemption_mode: "online".into(),
        approval_identities: vec![],
        policy_version: "sha256:policy".into(),
        policy_scope: format!("{prefix}-ns"),
        schema_version: "v1".into(),
        capability_version: "v1".into(),
        pricing_version: "v1".into(),
        nonce: format!("{prefix}-nonce"),
        delegation_depth: 0,
        parent_permit_id: String::new(),
        parent_chain: vec![],
        initiating_actor: format!("{prefix}-actor"),
        revocation_handle: format!("{prefix}-revoke"),
        signature_algorithm: "ed25519".into(),
        key_id: "key-1".into(),
        public_key: "pk".into(),
        issued_at_ms: 1_000,
        revocation_latency_ms: 0,
        offline_revocation_unavailable: false,
        site_id: "local".into(),
        signed_digest: "sha256:signed".into(),
        signature: vec![1, 2, 3],
    }
}

fn exercise(db: &dyn PermitHarness, prefix: &str) {
    let scope = format!("{prefix}-ns");
    db.set_external_permit_policy(
        &ExternalPermitPolicy {
            scope: scope.clone(),
            offline_action_types: vec!["repository.read/v1".into()],
            offline_max_duration_ms: 60_000,
            offline_max_invocations: 2,
            permitted_delegators: vec!["admin".into()],
            max_delegation_depth: 1,
        },
        1_000,
    )
    .unwrap();
    let policy = db.get_external_permit_policy(&scope).unwrap();
    assert_eq!(policy.max_delegation_depth, 1);
    assert_eq!(policy.offline_max_invocations, 2);

    let permit = sample_permit(prefix);
    let stored = db
        .put_permit(&permit, &format!("{prefix}-issue"), "issuer")
        .unwrap();
    assert_eq!(stored.permit_id, permit.permit_id);
    // Replay same key returns stored permit.
    let again = db
        .put_permit(&permit, &format!("{prefix}-issue"), "issuer")
        .unwrap();
    assert_eq!(again.permit_id, permit.permit_id);
    assert_eq!(
        db.replay_permit(&permit.authorization_id, &format!("{prefix}-issue"))
            .unwrap()
            .unwrap()
            .permit_id,
        permit.permit_id
    );
    assert!(
        db.replay_permit(&permit.authorization_id, "other-key")
            .unwrap_err()
            .contains("idempotency")
    );

    assert!(
        db.revoke_permit(&permit.revocation_handle, "operator:test", "stop", 2_000)
            .unwrap()
    );
    let audit = db
        .get_decision(&format!("{}:audit:revoked", permit.revocation_handle))
        .unwrap()
        .expect("revocation audit");
    assert_eq!(audit.actor, "operator:test");
    assert_eq!(audit.reason, "stop");
    assert_eq!(audit.target_id, permit.revocation_handle);
    assert!(
        !db.revoke_permit(&permit.revocation_handle, "operator:test", "stop", 2_001)
            .unwrap()
    );

    assert!(
        db.set_permit_kill_switch("namespace", &scope, true, "halt", 3_000)
            .unwrap()
    );
    assert!(
        db.set_permit_kill_switch("namespace", &scope, false, "resume", 3_001)
            .unwrap()
    );
}

#[test]
fn sqlite_chisei_external_permit_conformance() {
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
fn postgres_chisei_external_permit_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .replay_permit(&format!("{prefix}-auth"), &format!("{prefix}-issue"))
            .unwrap()
            .is_some()
    );
}
