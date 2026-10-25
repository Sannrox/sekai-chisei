//! Shared SQLite/PostgreSQL conformance for external permit policy, redeem,
//! reconcile, and delegation-chain validation.

use ed25519_dalek::SigningKey;
use sekai_chisei::chisei::external_action::{
    ASSURANCE_VERSION, AssuranceDeclaration, AuthorizationClaim, AuthorizationRecord,
    DECISION_VERSION, ExternalActionDecision, ExternalActionRequest, PERMIT_VERSION,
    REQUEST_VERSION,
};
use sekai_chisei::chisei::external_permit::{
    Delegation, ExternalPermitPolicy, HostContext, Issuance, Permit, RedemptionTiming, delegate,
    issue, issue_offline,
};
use sekai_chisei::chisei_store::chisei_external_action::ChiseiExternalActionBackend;
use sekai_chisei::chisei_store::chisei_external_permit::ChiseiExternalPermitBackend;
use sekai_chisei::db::decision::DecisionBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

trait PermitHarness:
    ChiseiExternalPermitBackend + ChiseiExternalActionBackend + DecisionBackend
{
}
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

    exercise_redeem_reconcile_delegation(db, prefix);
}

fn authorization(prefix: &str, deadline_ms: i64, invocations: u32) -> AuthorizationRecord {
    let request = ExternalActionRequest {
        version: REQUEST_VERSION.into(),
        operation_id: format!("{prefix}-op"),
        parent_operation_id: String::new(),
        attempt_id: format!("{prefix}-attempt"),
        request_id: format!("{prefix}-request"),
        actor: format!("{prefix}-actor"),
        namespace: format!("{prefix}-ns"),
        requesting_harness: format!("{prefix}-harness"),
        intended_executor: format!("{prefix}-executor"),
        action_type: "repository.read/v1".into(),
        parameter_schema: "repository.read.params/v1".into(),
        canonical_arguments_digest: format!("sha256:{prefix}-args"),
        policy_summary: BTreeMap::from([("path".into(), "README.md".into())]),
        target_selectors: vec![format!("project:{prefix}-ns/README.md")],
        immutable_preconditions: BTreeMap::from([("resource_version".into(), "git:abc123".into())]),
        risk_class: "read".into(),
        expected_effects: vec!["read_file".into()],
        requested_invocation_count: invocations,
        deadline_ms,
        estimated_cost_micros: 10,
        estimated_volume: 1024,
        affected_resource_count: 1,
        rollback_capability: "not_applicable".into(),
        required_host_capabilities: vec![
            "exact_target_binding".into(),
            "resource_version_check".into(),
        ],
        idempotency_key: format!("{prefix}-authorize"),
        policy_project: format!("{prefix}-ns"),
    };
    let digest = request.canonical_digest().unwrap();
    AuthorizationRecord {
        request,
        decision: ExternalActionDecision {
            version: DECISION_VERSION.into(),
            authorization_id: format!("{prefix}-auth-life"),
            request_digest: digest,
            decision: "permit".into(),
            reason: "allowed".into(),
            approval_id: String::new(),
            policy_scope: format!("{prefix}-scope"),
            policy_version: "sha256:policy".into(),
            created_at_ms: 1_000,
            expires_at_ms: deadline_ms,
            cancelled_at_ms: 0,
            assurance: AssuranceDeclaration {
                version: ASSURANCE_VERSION.into(),
                authorization_only: true,
                host_must_verify_permit: true,
                host_must_enforce_constraints: true,
                physical_effect_verified: false,
            },
        },
        approval_status: String::new(),
        budget_reserved: true,
        blast_radius_reserved: true,
        decision_actor: format!("{prefix}-actor"),
        decision_updated_at_ms: 1_000,
    }
}

fn persist_authorization(db: &dyn PermitHarness, record: &AuthorizationRecord) {
    assert!(matches!(
        db.claim_external_action_authorization(
            &record.request,
            &record.decision.request_digest,
            &record.decision.authorization_id,
            1_000
        )
        .unwrap(),
        AuthorizationClaim::Claimed(_)
    ));
    db.put_external_action_authorization(record).unwrap();
}

fn signed(record: &AuthorizationRecord, permit_id: &str, nonce: &str) -> (Permit, SigningKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let permit = issue(
        record,
        &key,
        Issuance {
            approval_identities: vec![],
            issuer: "issuer:test",
            key_id: "key-1",
            permit_id: permit_id.into(),
            nonce: nonce.into(),
            now_ms: 2_000,
            site_id: "local",
        },
    )
    .unwrap();
    (permit, key)
}

fn host_context(permit: &Permit) -> HostContext {
    HostContext {
        executor: permit.executor.clone(),
        requesting_harness: permit.requesting_harness.clone(),
        canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
        target_selectors: permit.target_selectors.clone(),
        observed_preconditions: permit.immutable_preconditions.clone(),
        host_capabilities: permit.required_host_capabilities.clone(),
    }
}

fn exercise_redeem_reconcile_delegation(db: &dyn PermitHarness, prefix: &str) {
    let record = authorization(&format!("{prefix}-online"), 10_000, 1);
    let (permit, key) = signed(
        &record,
        &format!("{prefix}-online-permit"),
        &format!("{prefix}-n1"),
    );
    persist_authorization(db, &record);
    db.put_permit(
        &permit,
        &format!("{prefix}-online-issue"),
        &record.request.actor,
    )
    .unwrap();
    let first = db
        .redeem_permit(
            &permit,
            &host_context(&permit),
            &key.verifying_key(),
            &format!("{prefix}-redeem-1"),
            &format!("{prefix}-exec-1"),
            "local",
            3_000,
        )
        .unwrap();
    assert_eq!(first.invocation_ordinal, 1);
    let retry = db
        .redeem_permit(
            &permit,
            &host_context(&permit),
            &key.verifying_key(),
            &format!("{prefix}-redeem-1"),
            &format!("{prefix}-exec-1"),
            "local",
            3_001,
        )
        .unwrap();
    assert_eq!(first, retry);
    let refused = db
        .redeem_permit(
            &permit,
            &host_context(&permit),
            &key.verifying_key(),
            &format!("{prefix}-redeem-2"),
            &format!("{prefix}-exec-2"),
            "local",
            3_002,
        )
        .unwrap_err();
    assert!(refused.contains("invocation count exhausted"), "{refused}");
    assert!(
        db.validate_permit_state(&permit)
            .unwrap_err()
            .contains("exhausted")
    );

    let offline_prefix = format!("{prefix}-offline");
    let mut offline_record = authorization(&offline_prefix, 10_000, 9);
    offline_record.request.idempotency_key = format!("{offline_prefix}-authorize");
    offline_record.decision.authorization_id = format!("{offline_prefix}-auth");
    offline_record.decision.request_digest = offline_record.request.canonical_digest().unwrap();
    let policy = ExternalPermitPolicy {
        scope: offline_record.decision.policy_scope.clone(),
        offline_action_types: vec!["repository.read/v1".into()],
        offline_max_duration_ms: 2_000,
        offline_max_invocations: 2,
        permitted_delegators: vec![offline_record.request.actor.clone()],
        max_delegation_depth: 1,
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let offline = issue_offline(
        &offline_record,
        &policy,
        &key,
        Issuance {
            approval_identities: vec![],
            issuer: "issuer:test",
            key_id: "key-1",
            permit_id: format!("{offline_prefix}-permit"),
            nonce: format!("{offline_prefix}-nonce"),
            now_ms: 2_000,
            site_id: "local",
        },
    )
    .unwrap();
    persist_authorization(db, &offline_record);
    db.put_permit(
        &offline,
        &format!("{offline_prefix}-issue"),
        &offline_record.request.actor,
    )
    .unwrap();
    let reconciled = db
        .redeem_or_reconcile_permit(
            &offline,
            &host_context(&offline),
            &key.verifying_key(),
            &format!("{offline_prefix}-reconcile"),
            &format!("{offline_prefix}-exec"),
            "local",
            RedemptionTiming {
                invoked_at_ms: 3_000,
                reconciled_at_ms: 5_000,
            },
        )
        .unwrap();
    assert_eq!(reconciled.invocation_ordinal, 1);
    assert_eq!(
        db.replay_redemption(
            &offline,
            &format!("{offline_prefix}-reconcile"),
            &format!("{offline_prefix}-exec")
        )
        .unwrap()
        .unwrap(),
        reconciled
    );

    let del_prefix = format!("{prefix}-del");
    let del_record = authorization(&del_prefix, 10_000, 3);
    let (root, key) = signed(
        &del_record,
        &format!("{del_prefix}-root"),
        &format!("{del_prefix}-n"),
    );
    persist_authorization(db, &del_record);
    let del_policy = ExternalPermitPolicy {
        scope: del_record.decision.policy_scope.clone(),
        offline_action_types: vec!["repository.read/v1".into()],
        offline_max_duration_ms: 2_000,
        offline_max_invocations: 2,
        permitted_delegators: vec![del_record.request.actor.clone()],
        max_delegation_depth: 2,
    };
    db.set_external_permit_policy(&del_policy, 2_500).unwrap();
    db.put_permit(
        &root,
        &format!("{del_prefix}-issue"),
        &del_record.request.actor,
    )
    .unwrap();
    db.validate_permit_state(&root).unwrap();
    db.validate_permit_for_delegation(&root).unwrap();
    let child = delegate(
        &root,
        &del_policy,
        &key,
        Delegation {
            delegator: &del_record.request.actor,
            subject_actor: &format!("{del_prefix}-child"),
            permit_id: format!("{del_prefix}-child"),
            nonce: format!("{del_prefix}-child-n"),
            now_ms: 3_000,
            expires_at_ms: 8_000,
            target_selectors: root.target_selectors.clone(),
            allowed_effects: root.allowed_effects.clone(),
            budget_micros: 5,
            volume_limit: 512,
            blast_radius_limit: 1,
            max_invocations: 1,
            risk_class: &root.risk_class,
        },
    )
    .unwrap();
    db.put_delegated_permit(&child, &del_record.request.actor)
        .unwrap();
    db.validate_delegation_chain(&child).unwrap();
    assert!(
        db.validate_permit_for_delegation(&root)
            .unwrap_err()
            .contains("transferred")
    );
    let mut missing = child.clone();
    missing.parent_chain = vec![format!("{del_prefix}-missing")];
    missing.parent_permit_id = format!("{del_prefix}-missing");
    assert!(
        db.validate_delegation_chain(&missing)
            .unwrap_err()
            .contains("missing")
    );
    db.revoke_permit(
        &root.revocation_handle,
        "operator:test",
        "root revoked",
        3_100,
    )
    .unwrap();
    assert!(
        db.validate_delegation_chain(&child)
            .unwrap_err()
            .contains("revoked")
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
    let offline_permit_id = format!("{prefix}-offline-permit");
    let offline_json = restarted
        .replay_permit(
            &format!("{prefix}-offline-auth"),
            &format!("{prefix}-offline-issue"),
        )
        .unwrap()
        .expect("offline permit survives restart");
    assert_eq!(offline_json.permit_id, offline_permit_id);
    assert!(
        restarted
            .replay_redemption(
                &offline_json,
                &format!("{prefix}-offline-reconcile"),
                &format!("{prefix}-offline-exec")
            )
            .unwrap()
            .is_some()
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_redeem_and_delegate_cannot_split_authority() {
    let db = Arc::new(postgres());
    let prefix = format!("pg-split-{}", uuid::Uuid::new_v4().simple());
    let record = authorization(&prefix, 10_000, 1);
    let (root, key) = signed(&record, &format!("{prefix}-root"), &format!("{prefix}-n"));
    persist_authorization(db.as_ref(), &record);
    let policy = ExternalPermitPolicy {
        scope: record.decision.policy_scope.clone(),
        offline_action_types: vec!["repository.read/v1".into()],
        offline_max_duration_ms: 2_000,
        offline_max_invocations: 2,
        permitted_delegators: vec![record.request.actor.clone()],
        max_delegation_depth: 1,
    };
    db.set_external_permit_policy(&policy, 2_500).unwrap();
    db.put_permit(&root, &format!("{prefix}-issue"), &record.request.actor)
        .unwrap();
    let child = delegate(
        &root,
        &policy,
        &key,
        Delegation {
            delegator: &record.request.actor,
            subject_actor: &format!("{prefix}-child"),
            permit_id: format!("{prefix}-child"),
            nonce: format!("{prefix}-child-n"),
            now_ms: 3_000,
            expires_at_ms: 8_000,
            target_selectors: root.target_selectors.clone(),
            allowed_effects: root.allowed_effects.clone(),
            budget_micros: 5,
            volume_limit: 512,
            blast_radius_limit: 1,
            max_invocations: 1,
            risk_class: &root.risk_class,
        },
    )
    .unwrap();
    let redeem_db = Arc::clone(&db);
    let delegate_db = Arc::clone(&db);
    let redeem_permit = root.clone();
    let redeem_ctx = host_context(&root);
    let redeem_key = key.verifying_key();
    let redeem_idem = format!("{prefix}-redeem");
    let redeem_exec = format!("{prefix}-exec");
    let child_actor = record.request.actor.clone();
    let redeem = thread::spawn(move || {
        redeem_db.redeem_permit(
            &redeem_permit,
            &redeem_ctx,
            &redeem_key,
            &redeem_idem,
            &redeem_exec,
            "local",
            3_000,
        )
    });
    let delegated = thread::spawn(move || delegate_db.put_delegated_permit(&child, &child_actor));
    let redeemed = redeem.join().expect("redeem thread");
    let transferred = delegated.join().expect("delegate thread");
    assert!(
        redeemed.is_ok() ^ transferred.is_ok(),
        "parent must be consumed or delegated, not both: redeem={redeemed:?} delegate={transferred:?}"
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_redeems_serialize_ordinal_and_replay() {
    let db = Arc::new(postgres());
    let prefix = format!("pg-ord-{}", uuid::Uuid::new_v4().simple());
    let record = authorization(&prefix, 10_000, 1);
    let (permit, key) = signed(&record, &format!("{prefix}-permit"), &format!("{prefix}-n"));
    persist_authorization(db.as_ref(), &record);
    db.put_permit(&permit, &format!("{prefix}-issue"), &record.request.actor)
        .unwrap();
    let ctx = host_context(&permit);
    let verifying = key.verifying_key();
    let workers = (0..2)
        .map(|index| {
            let worker = Arc::clone(&db);
            let worker_permit = permit.clone();
            let worker_ctx = ctx.clone();
            let worker_key = verifying;
            let idem = format!("{prefix}-redeem-{index}");
            let exec = format!("{prefix}-exec-{index}");
            thread::spawn(move || {
                worker.redeem_permit(
                    &worker_permit,
                    &worker_ctx,
                    &worker_key,
                    &idem,
                    &exec,
                    "local",
                    3_000,
                )
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("redeem thread"))
        .collect::<Vec<_>>();
    let ok = results.iter().filter(|result| result.is_ok()).count();
    let exhausted = results
        .iter()
        .filter(|result| {
            result
                .as_ref()
                .err()
                .is_some_and(|error| error.contains("invocation count exhausted"))
        })
        .count();
    assert_eq!(ok, 1, "exactly one redeem must succeed: {results:?}");
    assert_eq!(exhausted, 1, "the other redeem must exhaust: {results:?}");

    let replay_prefix = format!("pg-replay-{}", uuid::Uuid::new_v4().simple());
    let replay_record = authorization(&replay_prefix, 10_000, 1);
    let (replay_permit, replay_key) = signed(
        &replay_record,
        &format!("{replay_prefix}-permit"),
        &format!("{replay_prefix}-n"),
    );
    persist_authorization(db.as_ref(), &replay_record);
    db.put_permit(
        &replay_permit,
        &format!("{replay_prefix}-issue"),
        &replay_record.request.actor,
    )
    .unwrap();
    let replay_ctx = host_context(&replay_permit);
    let replay_verifying = replay_key.verifying_key();
    let replay_idem = format!("{replay_prefix}-redeem");
    let replay_exec = format!("{replay_prefix}-exec");
    let replay_a = Arc::clone(&db);
    let replay_b = Arc::clone(&db);
    let first = {
        let permit = replay_permit.clone();
        let ctx = replay_ctx.clone();
        let idem = replay_idem.clone();
        let exec = replay_exec.clone();
        thread::spawn(move || {
            replay_a.redeem_permit(
                &permit,
                &ctx,
                &replay_verifying,
                &idem,
                &exec,
                "local",
                4_000,
            )
        })
    };
    let second = thread::spawn(move || {
        replay_b.redeem_permit(
            &replay_permit,
            &replay_ctx,
            &replay_verifying,
            &replay_idem,
            &replay_exec,
            "local",
            4_001,
        )
    });
    let first = first.join().expect("replay thread").expect("first replay");
    let second = second
        .join()
        .expect("replay thread")
        .expect("second replay");
    assert_eq!(first, second);
}
