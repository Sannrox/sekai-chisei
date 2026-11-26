//! Interactive agent turns over gRPC (ADR 0173): only a member with write
//! access admits a turn, for themself, and an admitted turn is not
//! claimable until the claim slice lands.

use super::*;
use crate::sekai::agent_promotion::{AgentDefinitionCertification, STATUS_PASS};
use crate::sekai::security::Role;

const NS: &str = "desk";

/// A service with a published, certified revision whose agent member is
/// `triage`, an editor `alice` and a viewer `bob` of the namespace.
/// Returns the revision digest. The revision goes through a certified
/// proposal merge, since agent revisions are never published directly.
async fn service_with_revision() -> (SekaiServiceImpl, String) {
    let svc = service();
    grant_source_namespace(&svc, NS, "alice", Role::Editor);
    grant_source_namespace(&svc, NS, "bob", Role::Viewer);
    let parent = seed_definition_parent(&svc, NS).revision_digest;
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: NS.into(),
            branch_id: "agents".into(),
            parent_revision_digest: parent.clone(),
            idempotency_key: "create".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let candidate = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: NS.into(),
                branch_id: "agents".into(),
                expected_head_digest: parent.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "agent".into(),
                    member_id: "triage".into(),
                    member_digest: String::new(),
                    definition_json: serde_json::json!({
                        "contract_version": "sekai.agent-definition/v1",
                        "name": "Triage",
                        "task_class": "lookup",
                        "instructions": "Inspect records.",
                        "allowed_action_types": ["Ticket.inspect"]
                    })
                    .to_string(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    let now = now_millis();
    svc.db
        .runtime()
        .put_agent_definition_certification(&AgentDefinitionCertification {
            namespace: NS.into(),
            revision_digest: candidate.clone(),
            suite_id: "suite".into(),
            certification_id: "cert".into(),
            baseline_status: STATUS_PASS.into(),
            latest_status: STATUS_PASS.into(),
            expires_at_ms: now + 86_400_000,
            revoked_at_ms: 0,
            bound_by: "reviewer".into(),
            bound_at_ms: now,
            mean_score_milli: None,
        })
        .unwrap();
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: NS.into(),
            branch_id: "agents".into(),
            proposal_id: "p1".into(),
            base_digest: parent.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "propose".into(),
            major_revision: false,
            migration_plan_digest: String::new(),
            dataset_proposals: Vec::new(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: NS.into(),
            proposal_id: "p1".into(),
            idempotency_key: "approve".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let published = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: NS.into(),
                proposal_id: "p1".into(),
                expected_published_digest: parent,
                idempotency_key: "merge".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .published_revision
        .unwrap()
        .revision_digest;
    (svc, published)
}

fn request(digest: &str) -> AdmitInteractiveAgentTurnRequest {
    AdmitInteractiveAgentTurnRequest {
        namespace: NS.into(),
        definition_revision_digest: digest.into(),
        agent_member: "triage".into(),
        request_id: "req-1".into(),
        trace_id: "trace-1".into(),
    }
}

/// The turn acts as the caller, names the revision, agent member and trace
/// id, has no instance, and is not offered to workers.
#[tokio::test]
async fn a_member_admits_a_turn_that_acts_as_them() {
    let (svc, digest) = service_with_revision().await;
    let turn = svc
        .admit_interactive_agent_turn(with_named_principal(request(&digest), "alice"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    assert!(turn.turn_id.starts_with("iturn-"), "{}", turn.turn_id);
    assert_eq!(turn.cause, "interactive");
    assert_eq!(turn.principal_id, "alice");
    assert_eq!(turn.admitted_by, "alice");
    assert!(turn.instance_id.is_empty());
    assert_eq!(turn.definition_revision_digest, digest);
    assert_eq!(turn.agent_member, "triage");
    assert_eq!(turn.trace_id, "trace-1");
    assert_eq!(turn.cause_ref, "req-1");
    assert_eq!(turn.status, "pending");
    let retried = svc
        .admit_interactive_agent_turn(with_named_principal(request(&digest), "alice"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    assert_eq!(retried.turn_id, turn.turn_id);
    let claimable = svc
        .list_claimable_agent_turns(with_named_principal(
            ListClaimableAgentTurnsRequest {
                namespace: NS.into(),
                limit: 10,
                accepts_continuation: true,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .turns;
    assert!(claimable.is_empty(), "{claimable:?}");
}

/// Agents, registered service principals, several principals at once and a
/// namespace viewer are refused; an uncertified binding is invalid.
#[tokio::test]
async fn only_a_member_with_write_access_admits() {
    let (svc, digest) = service_with_revision().await;
    svc.db
        .runtime()
        .put_service_principal(
            &crate::sekai::service_principal::ServicePrincipalRegistration {
                capabilities: Vec::new(),
                principal: "worker-svc".into(),
                tenant_id: String::new(),
                namespaces: vec![NS.into()],
                action_types: vec!["Ticket.inspect".into()],
                registered_by: "local".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
    grant_source_namespace(&svc, NS, "worker-svc", Role::Editor);
    grant_source_namespace(&svc, NS, "agent:helper", Role::Editor);
    for (principal, code) in [
        ("agent:helper", tonic::Code::PermissionDenied),
        ("worker-svc", tonic::Code::PermissionDenied),
        ("alice,bob", tonic::Code::PermissionDenied),
        ("bob", tonic::Code::PermissionDenied),
        ("anonymous", tonic::Code::Unauthenticated),
    ] {
        let status = svc
            .admit_interactive_agent_turn(with_named_principal(request(&digest), principal))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code, "{principal}: {status:?}");
    }
    let mut foreign = request(&digest);
    foreign.agent_member = "ticket".into();
    let status = svc
        .admit_interactive_agent_turn(with_named_principal(foreign, "alice"))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
    assert!(
        status.message().contains("not an agent member"),
        "{status:?}"
    );
}
