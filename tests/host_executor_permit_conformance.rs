//! Host-executor permit conformance suite (#296).
//!
//! Profile: `tests/fixtures/host_executor_permit_conformance/v1.json`
//! Doc: `docs/host-executor-permit-conformance.md`

use ed25519_dalek::SigningKey;
use sekai_chisei::chisei::external_action::AuthorizationClaim;
use sekai_chisei::chisei::external_action::{
    ASSURANCE_VERSION, AssuranceDeclaration, AuthorizationRecord, ExternalActionDecision,
    ExternalActionRequest, PERMIT_VERSION, REQUEST_VERSION,
};
use sekai_chisei::chisei::external_permit::{
    HostContext, Issuance, Permit, REDEMPTION_MODE, SIGNATURE_ALGORITHM, issue,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::execution_evidence::{
    EXECUTION_EVIDENCE_SCHEMA, ExecutionEvidence, ExecutionLifecycleState, verify_for_executor,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const PROFILE_JSON: &str = include_str!("fixtures/host_executor_permit_conformance/v1.json");

#[derive(Debug, Deserialize)]
struct ConformanceCase {
    id: String,
    class: String,
    summary: String,
}

#[derive(Debug, Deserialize)]
struct ConformanceProfile {
    version: String,
    parent_issue: u64,
    required_cases: Vec<ConformanceCase>,
    reference_executors: Vec<String>,
}

fn profile() -> ConformanceProfile {
    let profile: ConformanceProfile =
        serde_json::from_str(PROFILE_JSON).expect("parse conformance profile");
    assert_eq!(profile.version, "sekai.host-executor-permit-conformance/v1");
    assert_eq!(profile.parent_issue, 296);
    assert!(!profile.required_cases.is_empty());
    profile
}

fn signed_permit(executor: &str, capability: &str) -> (Permit, SigningKey) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut permit = Permit {
        version: PERMIT_VERSION.into(),
        permit_id: format!("permit-{executor}"),
        authorization_id: "authorization-1".into(),
        request_digest: "request-digest".into(),
        issuer: "issuer:test".into(),
        subject_actor: "agent:test".into(),
        namespace: "local".into(),
        operation_id: "operation-1".into(),
        requesting_harness: "harness:v1".into(),
        executor: executor.into(),
        action_type: "write_file".into(),
        parameter_schema: "write-file/v1".into(),
        canonical_arguments_digest: "arguments-digest".into(),
        target_selectors: vec!["workspace/file.txt".into()],
        immutable_preconditions: BTreeMap::from([("etag".into(), "v1".into())]),
        allowed_effects: vec!["file_updated".into()],
        required_host_capabilities: vec![capability.into()],
        constraints: vec![format!("host_capability:{capability}")],
        risk_class: "write".into(),
        budget_micros: 100,
        volume_limit: 1,
        blast_radius_limit: 1,
        max_invocations: 2,
        not_before_ms: 1_000,
        expires_at_ms: 10_000,
        redemption_mode: REDEMPTION_MODE.into(),
        approval_identities: vec![],
        policy_version: "policy/v1".into(),
        policy_scope: "project:test".into(),
        schema_version: "write-file/v1".into(),
        capability_version: "write_file/v1".into(),
        pricing_version: "pricing/v1".into(),
        nonce: "nonce".into(),
        delegation_depth: 0,
        parent_permit_id: String::new(),
        parent_chain: Vec::new(),
        initiating_actor: "agent:test".into(),
        revocation_handle: format!("revoke-{executor}"),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        key_id: "key-1".into(),
        public_key: String::new(),
        issued_at_ms: 1_000,
        revocation_latency_ms: 0,
        offline_revocation_unavailable: false,
        signed_digest: String::new(),
        signature: vec![],
    };
    permit.sign(&key).unwrap();
    (permit, key)
}

fn host_context(permit: &Permit, capabilities: Vec<String>) -> HostContext {
    HostContext {
        executor: permit.executor.clone(),
        requesting_harness: permit.requesting_harness.clone(),
        canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
        target_selectors: permit.target_selectors.clone(),
        observed_preconditions: permit.immutable_preconditions.clone(),
        host_capabilities: capabilities,
    }
}

/// Deliberately broken harness used only to prove negatives are not vacuous.
struct BrokenHarness;

impl BrokenHarness {
    fn verify_for_executor(
        _permit: &Permit,
        _trusted_key: &ed25519_dalek::VerifyingKey,
        _trusted_issuer: &str,
        _trusted_key_id: &str,
        _context: &HostContext,
        _now_ms: i64,
    ) -> Result<(), String> {
        // Always accepts — must fail every negative conformance case.
        Ok(())
    }

    /// Always reports success even for revoked permits (unsafe host path).
    fn redeem_permit(
        _permit: &Permit,
        _context: &HostContext,
        _trusted_key: &ed25519_dalek::VerifyingKey,
        _idempotency_key: &str,
        _execution_id: &str,
        _now_ms: i64,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn profile_fixture_is_complete_and_on_disk() {
    let profile = profile();
    // Exact (id, class) set supported by this suite. Reject missing, extra,
    // duplicate, or class-drifted fixture entries so the versioned profile
    // cannot claim untested requirements.
    let expected: &[(&str, &str)] = &[
        ("verify_ok_with_capabilities", "positive"),
        ("verify_rejects_missing_capability", "negative"),
        ("verify_rejects_bad_signature", "negative"),
        ("verify_rejects_outside_validity_window", "negative"),
        ("verify_rejects_executor_mismatch", "negative"),
        ("verify_rejects_harness_mismatch", "negative"),
        ("verify_rejects_arguments_digest_mismatch", "negative"),
        ("verify_rejects_target_mismatch", "negative"),
        ("verify_rejects_precondition_mismatch", "negative"),
        ("verify_rejects_untrusted_issuer", "negative"),
        ("verify_rejects_untrusted_key_id", "negative"),
        ("redeem_is_idempotent", "positive"),
        ("redeem_after_revoke_fails", "negative"),
        ("execution_evidence_shape", "positive"),
        ("broken_harness_must_fail_each_negative", "meta"),
    ];
    let actual: Vec<(&str, &str)> = profile
        .required_cases
        .iter()
        .map(|c| (c.id.as_str(), c.class.as_str()))
        .collect();
    assert_eq!(
        actual.len(),
        expected.len(),
        "fixture case count drifted (duplicates or extras)"
    );
    let mut seen = std::collections::BTreeSet::new();
    for case in &profile.required_cases {
        assert!(
            seen.insert(case.id.as_str()),
            "duplicate case id {}",
            case.id
        );
        assert!(
            expected
                .iter()
                .any(|(id, class)| *id == case.id && *class == case.class),
            "unexpected or class-drifted case {}/{}",
            case.id,
            case.class
        );
        assert!(!case.summary.is_empty(), "empty summary for {}", case.id);
    }
    for (id, class) in expected {
        assert!(
            actual.iter().any(|(a_id, a_class)| a_id == id && a_class == class),
            "missing expected case {id}/{class}"
        );
    }
    assert!(Path::new("docs/host-executor-permit-conformance.md").exists());
    assert!(Path::new("tests/fixtures/host_executor_permit_conformance/v1.json").exists());
    assert_eq!(
        profile.reference_executors,
        vec![
            "executor:filesystem/atomic_rename".to_string(),
            "executor:http/conditional_request".to_string(),
        ],
        "profile reference_executors must match the pairs exercised by the suite"
    );
}

/// Parse `executor:<name>/<capability>` entries from the versioned profile.
fn reference_executor_pairs(profile: &ConformanceProfile) -> Vec<(String, String)> {
    profile
        .reference_executors
        .iter()
        .map(|entry| {
            let (executor, capability) = entry
                .rsplit_once('/')
                .unwrap_or_else(|| panic!("malformed reference executor {entry}"));
            assert!(
                executor.starts_with("executor:"),
                "expected executor: prefix in {entry}"
            );
            assert!(!capability.is_empty(), "empty capability in {entry}");
            (executor.to_string(), capability.to_string())
        })
        .collect()
}

#[test]
fn reference_executors_pass_verify_with_capabilities() {
    let pairs = reference_executor_pairs(&profile());
    assert_eq!(pairs.len(), 2);
    for (executor, capability) in pairs {
        let (permit, key) = signed_permit(&executor, &capability);
        verify_for_executor(
            &permit,
            &key.verifying_key(),
            "issuer:test",
            "key-1",
            &host_context(&permit, vec![capability.clone()]),
            1_500,
        )
        .unwrap();
    }
}

#[test]
fn verify_rejects_missing_capability() {
    let (permit, key) = signed_permit("executor:filesystem", "atomic_rename");
    let err = verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &host_context(&permit, vec![]),
        1_500,
    )
    .unwrap_err();
    assert!(
        err.to_lowercase().contains("cannot enforce") || err.to_lowercase().contains("capability"),
        "unexpected: {err}"
    );
}

#[test]
fn verify_rejects_bad_signature() {
    let (mut permit, key) = signed_permit("executor:http", "conditional_request");
    permit.signature[0] ^= 0xff;
    let err = verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &host_context(&permit, vec!["conditional_request".into()]),
        1_500,
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn verify_rejects_outside_validity_window() {
    let (permit, key) = signed_permit("executor:filesystem", "atomic_rename");
    let context = host_context(&permit, vec!["atomic_rename".into()]);
    let before = verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &context,
        999,
    )
    .unwrap_err();
    assert!(!before.is_empty(), "must reject before not_before_ms");
    // Inclusive lower bound: not_before_ms is valid.
    verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &context,
        permit.not_before_ms,
    )
    .unwrap();
    // Exclusive upper bound: expires_at_ms is already expired.
    let at_expiry = verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &context,
        permit.expires_at_ms,
    )
    .unwrap_err();
    assert!(!at_expiry.is_empty(), "must reject at expires_at_ms");
    let after = verify_for_executor(
        &permit,
        &key.verifying_key(),
        "issuer:test",
        "key-1",
        &context,
        50_000,
    )
    .unwrap_err();
    assert!(!after.is_empty(), "must reject after expires_at_ms");
}

fn authorization(deadline_ms: i64, invocations: u32) -> AuthorizationRecord {
    let request = ExternalActionRequest {
        version: REQUEST_VERSION.into(),
        operation_id: "op-1".into(),
        parent_operation_id: String::new(),
        attempt_id: "attempt-1".into(),
        request_id: "request-1".into(),
        actor: "agent:test".into(),
        namespace: "test".into(),
        requesting_harness: "harness:test".into(),
        intended_executor: "executor:filesystem".into(),
        action_type: "repository.write/v1".into(),
        parameter_schema: "repository.write.params/v1".into(),
        canonical_arguments_digest: "sha256:args".into(),
        policy_summary: BTreeMap::from([("path".into(), "README.md".into())]),
        target_selectors: vec!["project:test/README.md".into()],
        immutable_preconditions: BTreeMap::from([("resource_version".into(), "git:abc123".into())]),
        risk_class: "write".into(),
        expected_effects: vec!["file_updated".into()],
        requested_invocation_count: invocations,
        deadline_ms,
        estimated_cost_micros: 10,
        estimated_volume: 1024,
        affected_resource_count: 1,
        rollback_capability: "not_applicable".into(),
        required_host_capabilities: vec!["atomic_rename".into()],
        idempotency_key: "authorize-1".into(),
        policy_project: "test".into(),
    };
    let digest = request.canonical_digest().unwrap();
    AuthorizationRecord {
        request,
        decision: ExternalActionDecision {
            version: "external-action.decision/v1".into(),
            authorization_id: "auth-1".into(),
            request_digest: digest,
            decision: "permit".into(),
            reason: "allowed".into(),
            approval_id: String::new(),
            policy_scope: "project:test".into(),
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
        decision_actor: "agent:test".into(),
        decision_updated_at_ms: 1_000,
    }
}

fn persist_and_issue(db: &RuntimeDb, record: &AuthorizationRecord) -> (Permit, SigningKey) {
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
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let permit = issue(
        record,
        &key,
        Issuance {
            approval_identities: vec![],
            issuer: "issuer:test",
            key_id: "key-1",
            permit_id: "permit-1".into(),
            nonce: "nonce-1".into(),
            now_ms: 2_000,
        },
    )
    .unwrap();
    db.put_permit(&permit, "issue-1", "agent:test").unwrap();
    (permit, key)
}

fn assert_verify_fails(permit: &Permit, key: &SigningKey, context: HostContext, now_ms: i64) {
    assert_verify_fails_with_trust(permit, key, "issuer:test", "key-1", context, now_ms);
}

fn assert_verify_fails_with_trust(
    permit: &Permit,
    key: &SigningKey,
    trusted_issuer: &str,
    trusted_key_id: &str,
    context: HostContext,
    now_ms: i64,
) {
    assert!(
        BrokenHarness::verify_for_executor(
            permit,
            &key.verifying_key(),
            trusted_issuer,
            trusted_key_id,
            &context,
            now_ms,
        )
        .is_ok()
    );
    assert!(
        verify_for_executor(
            permit,
            &key.verifying_key(),
            trusted_issuer,
            trusted_key_id,
            &context,
            now_ms,
        )
        .is_err()
    );
}

#[test]
fn verify_rejects_host_context_and_trust_binding_mismatches() {
    let (permit, key) = signed_permit("executor:filesystem", "atomic_rename");
    let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
    ctx.executor = "executor:other".into();
    assert_verify_fails(&permit, &key, ctx, 1_500);

    let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
    ctx.requesting_harness = "harness:other".into();
    assert_verify_fails(&permit, &key, ctx, 1_500);

    let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
    ctx.canonical_arguments_digest = "wrong-digest".into();
    assert_verify_fails(&permit, &key, ctx, 1_500);

    let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
    ctx.target_selectors = vec!["other-target".into()];
    assert_verify_fails(&permit, &key, ctx, 1_500);

    let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
    ctx.observed_preconditions = BTreeMap::from([("etag".into(), "wrong".into())]);
    assert_verify_fails(&permit, &key, ctx, 1_500);

    // Issuer trust boundary (valid key_id, wrong issuer).
    let ctx = host_context(&permit, vec!["atomic_rename".into()]);
    assert_verify_fails_with_trust(&permit, &key, "issuer:evil", "key-1", ctx, 1_500);

    // Key-id trust boundary (valid issuer, wrong key_id) — must not collapse into
    // issuer-only checks or the suite would stay green if trusted_key_id is ignored.
    let ctx = host_context(&permit, vec!["atomic_rename".into()]);
    assert_verify_fails_with_trust(&permit, &key, "issuer:test", "key-evil", ctx, 1_500);
}

#[test]
fn redeem_is_idempotent_across_retries() {
    // One-invocation permit: a double-consuming retry would exhaust the slot
    // and either diverge or block a same-key retry / free a second distinct key.
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let record = authorization(10_000, 1);
    let (permit, key) = persist_and_issue(&db, &record);
    assert_eq!(permit.max_invocations, 1);
    let context = host_context(&permit, permit.required_host_capabilities.clone());
    let first = db
        .redeem_permit(
            &permit,
            &context,
            &key.verifying_key(),
            "idem-1",
            "execution-1",
            3_000,
        )
        .unwrap();
    assert_eq!(first.invocation_ordinal, 1);
    let retry = db
        .redeem_permit(
            &permit,
            &context,
            &key.verifying_key(),
            "idem-1",
            "execution-1",
            3_001,
        )
        .unwrap();
    assert_eq!(first, retry, "same idempotency key must return the same redemption");
    // Distinct key after the only slot is consumed must fail — proves the retry
    // did not leave an extra unconsumed slot, and also that the first redeem
    // did consume the single invocation.
    let exhausted = db
        .redeem_permit(
            &permit,
            &context,
            &key.verifying_key(),
            "idem-2",
            "execution-2",
            3_002,
        )
        .unwrap_err();
    assert!(
        exhausted.to_lowercase().contains("exhaust")
            || exhausted.to_lowercase().contains("invocation"),
        "expected exhaustion after single consume + idempotent retry, got: {exhausted}"
    );
}

#[test]
fn redeem_after_revoke_fails() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let record = authorization(10_000, 2);
    let (permit, key) = persist_and_issue(&db, &record);
    db.revoke_permit(&permit.revocation_handle, "operator revoked", 3_500)
        .unwrap();
    let err = db
        .redeem_permit(
            &permit,
            &host_context(&permit, permit.required_host_capabilities.clone()),
            &key.verifying_key(),
            "idem-revoked",
            "execution-revoked",
            4_000,
        )
        .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn execution_evidence_shape_validates_terminal_report() {
    let report = ExecutionEvidence {
        version: EXECUTION_EVIDENCE_SCHEMA.into(),
        permit_id: "permit-1".into(),
        redemption_id: "redemption-1".into(),
        execution_id: "execution-1".into(),
        host_identity: "executor:filesystem".into(),
        lifecycle_state: ExecutionLifecycleState::Completed,
        observed_at_ms: 1_500,
        started_at_ms: Some(1_200),
        finished_at_ms: Some(1_400),
        enforced_preconditions: BTreeMap::new(),
        normalized_effects: vec![],
        affected_resource_references: vec![],
        cost_micros: 0,
        resource_use: BTreeMap::new(),
        artifact_hashes: vec![],
        exit_classification: "ok".into(),
        error_classification: String::new(),
        compensation_evidence_hashes: vec![],
        host_schema_version: "host-evidence/v1".into(),
        host_software_version: "executor/1.0".into(),
    };
    report.validate().unwrap();
}

#[test]
fn broken_harness_fails_every_negative_case() {
    let profile = profile();
    let negatives: Vec<_> = profile
        .required_cases
        .iter()
        .filter(|c| c.class == "negative")
        .collect();
    assert!(!negatives.is_empty());

    // For each negative id, the broken harness must produce a *passing*
    // verify (incorrectly). The suite then asserts that is unacceptable.
    for case in negatives {
        let (permit, key) = signed_permit("executor:filesystem", "atomic_rename");
        let context = match case.id.as_str() {
            "verify_rejects_missing_capability" => host_context(&permit, vec![]),
            "verify_rejects_executor_mismatch" => {
                let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
                ctx.executor = "executor:other".into();
                ctx
            }
            "verify_rejects_harness_mismatch" => {
                let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
                ctx.requesting_harness = "harness:other".into();
                ctx
            }
            "verify_rejects_arguments_digest_mismatch" => {
                let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
                ctx.canonical_arguments_digest = "wrong".into();
                ctx
            }
            "verify_rejects_target_mismatch" => {
                let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
                ctx.target_selectors = vec!["other".into()];
                ctx
            }
            "verify_rejects_precondition_mismatch" => {
                let mut ctx = host_context(&permit, vec!["atomic_rename".into()]);
                ctx.observed_preconditions = BTreeMap::from([("etag".into(), "x".into())]);
                ctx
            }
            "verify_rejects_untrusted_issuer" => {
                assert_verify_fails_with_trust(
                    &permit,
                    &key,
                    "issuer:evil",
                    "key-1",
                    host_context(&permit, vec!["atomic_rename".into()]),
                    1_500,
                );
                continue;
            }
            "verify_rejects_untrusted_key_id" => {
                // Keep issuer trusted; only the key id is wrong.
                assert_verify_fails_with_trust(
                    &permit,
                    &key,
                    "issuer:test",
                    "key-evil",
                    host_context(&permit, vec!["atomic_rename".into()]),
                    1_500,
                );
                continue;
            }
            "verify_rejects_bad_signature" => {
                let mut bad = permit.clone();
                if !bad.signature.is_empty() {
                    bad.signature[0] ^= 0xff;
                }
                // Broken harness ignores tamper and still Ok.
                let ok = BrokenHarness::verify_for_executor(
                    &bad,
                    &key.verifying_key(),
                    "issuer:test",
                    "key-1",
                    &host_context(&bad, vec!["atomic_rename".into()]),
                    1_500,
                );
                assert!(
                    ok.is_ok(),
                    "broken harness must incorrectly accept {}",
                    case.id
                );
                // Reference harness must reject.
                assert!(
                    verify_for_executor(
                        &bad,
                        &key.verifying_key(),
                        "issuer:test",
                        "key-1",
                        &host_context(&bad, vec!["atomic_rename".into()]),
                        1_500,
                    )
                    .is_err()
                );
                continue;
            }
            "verify_rejects_outside_validity_window" => {
                host_context(&permit, vec!["atomic_rename".into()])
            }
            "redeem_after_revoke_fails" => {
                let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
                let record = authorization(10_000, 2);
                let (permit, key) = persist_and_issue(&db, &record);
                db.revoke_permit(&permit.revocation_handle, "operator revoked", 3_500)
                    .unwrap();
                let context = host_context(&permit, permit.required_host_capabilities.clone());
                assert!(
                    BrokenHarness::redeem_permit(
                        &permit,
                        &context,
                        &key.verifying_key(),
                        "idem-broken-revoke",
                        "execution-broken-revoke",
                        4_000,
                    )
                    .is_ok(),
                    "broken harness incorrectly redeems after revoke"
                );
                assert!(
                    db.redeem_permit(
                        &permit,
                        &context,
                        &key.verifying_key(),
                        "idem-broken-revoke",
                        "execution-broken-revoke",
                        4_000,
                    )
                    .is_err(),
                    "reference path must refuse revoked permits"
                );
                continue;
            }
            other => panic!("unmapped negative case {other}"),
        };

        let ok = BrokenHarness::verify_for_executor(
            &permit,
            &key.verifying_key(),
            "issuer:test",
            "key-1",
            &context,
            if case.id == "verify_rejects_outside_validity_window" {
                50_000
            } else {
                1_500
            },
        );
        assert!(
            ok.is_ok(),
            "broken harness must incorrectly accept {}",
            case.id
        );
        assert!(
            verify_for_executor(
                &permit,
                &key.verifying_key(),
                "issuer:test",
                "key-1",
                &context,
                if case.id == "verify_rejects_outside_validity_window" {
                    50_000
                } else {
                    1_500
                },
            )
            .is_err(),
            "reference harness must reject {}",
            case.id
        );
    }
}
