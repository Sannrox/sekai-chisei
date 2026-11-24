//! Agent autonomy over the API (#3086): a namespace admin reads and changes
//! whether an agent's submits of one Action type park for review or apply,
//! and `SubmitActionInstance` follows the change.

use super::*;
use crate::sekai::action_instance::{DECISION_GRANT, RULE_AGENT_PROPOSE_ONLY, STATUS_ADMITTED};
use crate::sekai::agent_autonomy::{ACTION_GRANT, ACTION_REVOKE, DEFAULT_MIN_REVIEWS};
use crate::sekai::autonomous_envelope::{
    AutonomousEnvelope, AutonomousPins, ENVELOPE_CONTRACT, PROFILE_SIMULATE, PROFILE_VERSION,
    RECEIPT_CURRENT, STATUS_LIVE, admit_envelope, envelope_digest_for,
};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "acme";
const AGENT: &str = "agent:bot";
const TYPE_ID: &str = "review.intake";
const ENVELOPE: &str = "auto:intake";

/// A team namespace with an admin, a member, and the agent; the intake type
/// under an allow-all policy; and a live envelope owned by the agent.
async fn autonomy_service() -> SekaiServiceImpl {
    let svc = service();
    for (principal, role) in [
        ("alice", security::Role::Admin),
        ("bob", security::Role::Editor),
        (AGENT, security::Role::Editor),
    ] {
        grant_source_namespace(&svc, NAMESPACE, principal, role);
    }
    grant_source_namespace(&svc, "other-team", "mallory", security::Role::Admin);
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("")),
            request_id: "put-intake".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy::allow_all(format!(
            "project:{NAMESPACE}"
        )))
        .unwrap();
    admit_envelope(svc.db.runtime(), AGENT, &signed_envelope(), 1_000).unwrap();
    svc
}

fn signed_envelope() -> AutonomousEnvelope {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let digest = |tag: u8| format!("sha256:{tag:02x}{}", "ab".repeat(31));
    let mut envelope = AutonomousEnvelope {
        contract_version: ENVELOPE_CONTRACT.into(),
        envelope_id: ENVELOPE.into(),
        namespace: NAMESPACE.into(),
        owner: AGENT.into(),
        adapter_id: PROFILE_SIMULATE.into(),
        adapter_version: PROFILE_VERSION.into(),
        pins: AutonomousPins {
            state_digest: digest(1),
            policy_digest: digest(2),
            model_digest: digest(3),
            prompt_digest: digest(4),
            evidence_digest: digest(5),
            simulation_digest: digest(6),
            budget_digest: digest(7),
            lease_digest: digest(8),
        },
        signer_id: "signer:ops".into(),
        signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
        public_key_hex: hex(&public_key),
        signature_hex: String::new(),
        envelope_digest: String::new(),
        receipt_digest: String::new(),
        receipt_status: RECEIPT_CURRENT.into(),
        status: STATUS_LIVE.into(),
        predecessor_id: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    envelope.envelope_digest = envelope_digest_for(&envelope).unwrap();
    envelope.signature_hex = hex(&signing_key
        .sign(envelope.envelope_digest.as_bytes())
        .to_bytes());
    envelope
}

/// Reviewed submits the agent earned auto-apply with.
fn record_reviews(svc: &SekaiServiceImpl, count: u32) {
    for index in 0..count {
        let mut instance = action_read_fixture(NAMESPACE);
        instance.instance_id = format!("earned-{index}");
        instance.idempotency_key = format!("earned-key-{index}");
        instance.operation_id = format!("earned-op-{index}");
        instance.principal = AGENT.into();
        instance.type_id = TYPE_ID.into();
        instance.status = STATUS_ADMITTED.into();
        instance.approval_decision = DECISION_GRANT.into();
        instance.decided_by = "alice".into();
        svc.db.runtime().put_action_instance(&instance).unwrap();
    }
}

fn get(principal: &str) -> Request<GetAgentAutonomyRequest> {
    with_named_principal(
        GetAgentAutonomyRequest {
            namespace: NAMESPACE.into(),
            principal: AGENT.into(),
            type_id: TYPE_ID.into(),
        },
        principal,
    )
}

fn set(principal: &str, mode: &str) -> Request<SetAgentAutonomyRequest> {
    with_named_principal(
        SetAgentAutonomyRequest {
            namespace: NAMESPACE.into(),
            principal: AGENT.into(),
            type_id: TYPE_ID.into(),
            mode: mode.into(),
            envelope_id: if mode == "apply" { ENVELOPE } else { "" }.into(),
            reason: String::new(),
        },
        principal,
    )
}

async fn submit(svc: &SekaiServiceImpl, key: &str) -> ActionInstance {
    svc.submit_action_instance(with_named_principal(
        SubmitActionInstanceRequest {
            namespace: NAMESPACE.into(),
            type_id: TYPE_ID.into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"summary":"ship it"}"#.into(),
            idempotency_key: key.into(),
            evidence_submission_ids: vec![],
            request_id: format!("req-{key}"),
            ontology_digest: String::new(),
            offline: None,
        },
        AGENT,
    ))
    .await
    .unwrap()
    .into_inner()
    .instance
    .unwrap()
}

fn receipts(svc: &SekaiServiceImpl, action: &str) -> Vec<crate::sekai::audit::Decision> {
    svc.db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some(action.into()),
            limit: 100,
            ..Default::default()
        })
        .unwrap()
}

#[tokio::test]
async fn admin_moves_an_agent_between_propose_and_apply() {
    let svc = autonomy_service().await;

    let proposed = submit(&svc, "before").await;
    assert_eq!(proposed.status, "parked");
    assert_eq!(
        proposed
            .approval
            .as_ref()
            .map(|approval| approval.rule.as_str()),
        Some(RULE_AGENT_PROPOSE_ONLY)
    );

    let refused = svc
        .set_agent_autonomy(set("alice", "apply"))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("0 reviews, 0 approved unchanged, 0 incidents"),
        "{}",
        refused.message()
    );
    assert!(receipts(&svc, ACTION_GRANT).is_empty());

    record_reviews(&svc, DEFAULT_MIN_REVIEWS);
    let offered = svc
        .get_agent_autonomy(get("bob"))
        .await
        .unwrap()
        .into_inner();
    let offered = offered.autonomy.unwrap();
    assert_eq!(offered.mode, "propose");
    assert_eq!(offered.reviews, DEFAULT_MIN_REVIEWS);
    assert!(offered.eligible);

    let applied = svc
        .set_agent_autonomy(set("alice", "apply"))
        .await
        .unwrap()
        .into_inner()
        .autonomy
        .unwrap();
    assert_eq!(
        (applied.mode.as_str(), applied.envelope_id.as_str()),
        ("apply", ENVELOPE)
    );
    let granted = receipts(&svc, ACTION_GRANT);
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].actor, "alice");
    assert_eq!(submit(&svc, "applied").await.status, STATUS_ADMITTED);

    let back = svc
        .set_agent_autonomy(set("alice", "propose"))
        .await
        .unwrap()
        .into_inner()
        .autonomy
        .unwrap();
    assert_eq!(back.mode, "propose");
    let revoked = receipts(&svc, ACTION_REVOKE);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].actor, "alice");
    let reparked = submit(&svc, "after").await;
    assert_eq!(reparked.status, "parked");
    assert_eq!(
        reparked
            .approval
            .as_ref()
            .map(|approval| approval.rule.as_str()),
        Some(RULE_AGENT_PROPOSE_ONLY)
    );
}

#[tokio::test]
async fn autonomy_changes_need_namespace_admin_and_hide_other_namespaces() {
    let svc = autonomy_service().await;
    record_reviews(&svc, DEFAULT_MIN_REVIEWS);

    let member = svc
        .set_agent_autonomy(set("bob", "apply"))
        .await
        .unwrap_err();
    assert_eq!(member.code(), tonic::Code::PermissionDenied);
    let agent = svc
        .set_agent_autonomy(set(AGENT, "apply"))
        .await
        .unwrap_err();
    assert_eq!(agent.code(), tonic::Code::PermissionDenied);
    assert!(receipts(&svc, ACTION_GRANT).is_empty());

    let read = svc.get_agent_autonomy(get("mallory")).await.unwrap_err();
    assert_eq!(read.code(), tonic::Code::NotFound);
    let change = svc
        .set_agent_autonomy(set("mallory", "apply"))
        .await
        .unwrap_err();
    assert_eq!(change.code(), tonic::Code::NotFound);

    let unknown_mode = svc
        .set_agent_autonomy(set("alice", "shadow"))
        .await
        .unwrap_err();
    assert_eq!(unknown_mode.code(), tonic::Code::InvalidArgument);
}
