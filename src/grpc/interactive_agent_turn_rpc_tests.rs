//! Interactive agent turns over gRPC (ADR 0173): only a member with write
//! access admits a turn, for themself; a worker that opts in claims it and
//! gets a token that acts as the member, within the revision's Action types
//! and the member's live access.

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
    let digest = publish_revision(&svc).await;
    (svc, digest)
}

/// [`service_with_revision`] on an existing service.
async fn publish_revision(svc: &SekaiServiceImpl) -> String {
    grant_source_namespace(svc, NS, "alice", Role::Editor);
    grant_source_namespace(svc, NS, "bob", Role::Viewer);
    let parent = seed_definition_parent(svc, NS).revision_digest;
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
    svc.merge_definition_proposal(with_named_principal(
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
    .revision_digest
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
/// id, has no instance, and is not offered to workers that do not opt in.
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
                accepts_interactive: false,
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

/// A service that signs turn tokens, and the boundary that admits them.
struct Plane {
    svc: SekaiServiceImpl,
    interceptor: crate::grpc::TokenAuthInterceptor,
    authority: Arc<crate::identity_assertion::AssertionAuthority>,
}

async fn token_plane() -> (Plane, String) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
    let clerk = crate::composition::cross_store_admission::CrossStoreAdmission::new(
        crate::chisei_store::ChiseiStore::from_shared_runtime(db),
        store.clone(),
        None,
    );
    let authority = Arc::new(crate::identity_assertion::AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"runtime-token-key",
    ));
    let svc = SekaiServiceImpl::new(store.clone())
        .with_runtime_token_authority(Some(authority.clone()))
        .with_cross_store_admission(Arc::new(clerk));
    let digest = publish_revision(&svc).await;
    let interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store,
        Some(authority.clone()),
    );
    (
        Plane {
            svc,
            interceptor,
            authority,
        },
        digest,
    )
}

/// `body` from `worker` as a machine credential under tenant `tenant-w`.
fn as_worker<T>(worker: &str, body: T) -> Request<T> {
    let mut request = with_named_principal(body, worker);
    let mut context = crate::enterprise::AuthenticatedContext::machine(
        crate::enterprise::AuthenticatedPrincipal {
            subject: worker.into(),
            credential_id: "credential-w".into(),
        },
    );
    context.tenant = Some(crate::enterprise::TenantContext {
        tenant_id: "tenant-w".into(),
        subject: worker.into(),
    });
    request.extensions_mut().insert(context);
    request
}

/// `body` with `token` through the authentication boundary for `method`.
fn with_token<T>(plane: &Plane, token: &str, method: &'static str, body: T) -> Request<T> {
    use tonic::service::Interceptor as _;
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
    let (metadata, extensions, ()) = plane
        .interceptor
        .clone()
        .call(request)
        .unwrap()
        .into_parts();
    Request::from_parts(metadata, extensions, body)
}

fn claim_request(turn_id: &str, accepts_interactive: bool) -> ClaimAgentTurnRequest {
    ClaimAgentTurnRequest {
        namespace: NS.into(),
        runtime_id: "runner".into(),
        turn_id: turn_id.into(),
        ttl_ms: 60_000,
        accepts_continuation: true,
        accepts_interactive,
    }
}

/// Only a worker that opts in lists and claims the turn, never the member
/// itself. The token acts as the member with no `act`, renews on
/// heartbeat, submits only the revision's Action types, is classified as
/// an agent for write freezes, and ends with the turn's ack.
#[tokio::test]
async fn an_opted_in_worker_runs_the_turn_as_the_member() {
    let (plane, digest) = token_plane().await;
    let svc = &plane.svc;
    let turn_id = svc
        .admit_interactive_agent_turn(with_named_principal(request(&digest), "alice"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap()
        .turn_id;
    let list = |accepts_interactive| {
        svc.list_claimable_agent_turns(as_worker(
            "local",
            ListClaimableAgentTurnsRequest {
                namespace: NS.into(),
                limit: 10,
                accepts_continuation: true,
                accepts_interactive,
            },
        ))
    };
    assert!(list(false).await.unwrap().into_inner().turns.is_empty());
    let listed = list(true).await.unwrap().into_inner().turns;
    assert_eq!(
        listed
            .iter()
            .map(|turn| turn.turn_id.as_str())
            .collect::<Vec<_>>(),
        [turn_id.as_str()]
    );

    let refused = svc
        .claim_agent_turn(as_worker("local", claim_request(&turn_id, false)))
        .await
        .unwrap_err();
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    let not_offered = svc
        .claim_agent_turn(as_worker("local", claim_request("", false)))
        .await
        .unwrap_err();
    assert_eq!(not_offered.code(), tonic::Code::NotFound, "{not_offered:?}");
    // The member's own credential never runs its turn, and claiming the
    // next due turn skips the caller's own.
    grant_source_namespace(svc, NS, "local", Role::Editor);
    let mut own = request(&digest);
    own.request_id = "req-own".into();
    let own = svc
        .admit_interactive_agent_turn(with_named_principal(own, "local"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    let as_member = svc
        .claim_agent_turn(as_worker("local", claim_request(&own.turn_id, true)))
        .await
        .unwrap_err();
    assert_eq!(
        as_member.code(),
        tonic::Code::PermissionDenied,
        "{as_member:?}"
    );
    assert!(
        as_member.message().contains("turn's member"),
        "{as_member:?}"
    );

    let claimed = svc
        .claim_agent_turn(as_worker("local", claim_request("", true)))
        .await
        .unwrap()
        .into_inner();
    let turn = claimed.turn.unwrap();
    assert_eq!(
        (turn.turn_id.as_str(), turn.status.as_str()),
        (turn_id.as_str(), "claimed")
    );
    assert!(claimed.continuation.is_none());
    let claims = crate::runtime_token::RuntimeTokenClaims::verify(
        &plane.authority,
        &claimed.runtime_token,
        now_millis(),
    )
    .unwrap();
    assert_eq!(claims.subject, "alice");
    assert_eq!(claims.act, None);
    assert_eq!(claims.worker.as_deref(), Some("local"));

    let renewed = svc
        .heartbeat_agent_turn_claim(with_token(
            &plane,
            &claimed.runtime_token,
            "HeartbeatAgentTurnClaim",
            HeartbeatAgentTurnClaimRequest {
                turn_id: turn_id.clone(),
                runtime_id: turn.claim_owner.clone(),
                claim_generation: turn.claim_generation,
                fencing_token: turn.fencing_token.clone(),
                ttl_ms: 60_000,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!renewed.runtime_token.is_empty());
    let token = renewed.runtime_token;

    let submission = |type_id: &str| {
        let request = with_token(&plane, &token, "SubmitActionInstance", ());
        svc.authorize_turn_submission(&request, NS, type_id)
            .map(|_| ())
            .map_err(|status| status.code())
    };
    assert_eq!(submission("Ticket.inspect"), Ok(()));
    assert_eq!(
        submission("Ticket.close"),
        Err(tonic::Code::PermissionDenied)
    );
    let request = with_token(&plane, &token, "SubmitActionInstance", ());
    let context = request_tenant_context(svc.db.runtime(), &request).unwrap();
    assert!(freeze_actor_is_agent(svc.db.runtime(), "alice", context.as_ref()).unwrap());

    let ack = |outcome: &str| {
        svc.ack_agent_turn(with_token(
            &plane,
            &token,
            "AckAgentTurn",
            AckAgentTurnRequest {
                turn_id: turn_id.clone(),
                runtime_id: turn.claim_owner.clone(),
                claim_generation: turn.claim_generation,
                fencing_token: turn.fencing_token.clone(),
                outcome: outcome.into(),
                reason: "answered".into(),
                parked_action_instance_id: String::new(),
            },
        ))
    };
    let parked = ack("parked").await.unwrap_err();
    assert_eq!(parked.code(), tonic::Code::FailedPrecondition, "{parked:?}");
    let done = ack("completed").await.unwrap().into_inner().turn.unwrap();
    assert_eq!(
        (done.status.as_str(), done.reason.as_str()),
        ("completed", "answered")
    );
    // A lost response is retried; the token then covers nothing else.
    assert_eq!(
        ack("completed").await.unwrap().into_inner().turn.unwrap(),
        done
    );
    assert_eq!(
        submission("Ticket.inspect"),
        Err(tonic::Code::PermissionDenied)
    );
}

/// Revoking the member's namespace access refuses the token's next call
/// and fails the turn with that reason.
#[tokio::test]
async fn revoking_the_member_fails_the_turn() {
    let (plane, digest) = token_plane().await;
    let svc = &plane.svc;
    let (_, grants) = svc
        .db
        .runtime()
        .ensure_team_namespace(NS, "alice", Role::Editor, "local")
        .unwrap();
    let turn_id = svc
        .admit_interactive_agent_turn(with_named_principal(request(&digest), "alice"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap()
        .turn_id;
    let token = svc
        .claim_agent_turn(as_worker("local", claim_request(&turn_id, true)))
        .await
        .unwrap()
        .into_inner()
        .runtime_token;
    for grant in grants.iter().filter(|grant| grant.principal == "alice") {
        svc.db.runtime().delete_grant(&grant.id).unwrap();
    }
    let request = with_token(&plane, &token, "SubmitActionInstance", ());
    let refused = svc
        .authorize_turn_submission(&request, NS, "Ticket.inspect")
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");
    let turn = crate::sekai::interactive_agent_turn::get(svc.db.runtime(), &turn_id)
        .unwrap()
        .unwrap();
    assert_eq!(turn.status, "failed");
    assert!(
        turn.reason.starts_with("member access revoked"),
        "{}",
        turn.reason
    );
}

/// An Action the turn's token submits commits under the interactive turn's
/// claim, as the member, and its receipt names the revision, agent member
/// and trace id.
#[tokio::test]
async fn an_interactive_turn_action_names_its_revision_on_the_receipt() {
    let (plane, digest) = token_plane().await;
    let svc = &plane.svc;
    svc.put_governed_action_type(with_named_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            namespace: NS.into(),
            type_id: "Ticket.inspect".into(),
            version: "1.0.0".into(),
            description: "Inspect a ticket".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"note":{"type":"string"}},"required":["note"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["runtime_dispatch".into()],
            enabled: true,
            ..Default::default()
        }),
        request_id: "put-type".into(),
    }, "root"))
    .await
    .unwrap();
    let turn_id = svc
        .admit_interactive_agent_turn(with_named_principal(request(&digest), "alice"))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap()
        .turn_id;
    let token = svc
        .claim_agent_turn(as_worker("local", claim_request(&turn_id, true)))
        .await
        .unwrap()
        .into_inner()
        .runtime_token;
    let instance = svc
        .submit_action_instance(with_token(
            &plane,
            &token,
            "SubmitActionInstance",
            SubmitActionInstanceRequest {
                namespace: NS.into(),
                type_id: "Ticket.inspect".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"note":"look"}"#.into(),
                idempotency_key: "inspect-1".into(),
                evidence_submission_ids: Vec::new(),
                request_id: "req-inspect".into(),
                ontology_digest: String::new(),
                offline: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(instance.status, "admitted", "{instance:?}");
    assert_eq!(instance.principal, "alice");
    assert_eq!(
        instance.agent_turn,
        Some(ActionAgentTurn {
            turn_id,
            definition_revision_digest: digest,
            agent_member: "triage".into(),
            trace_id: "trace-1".into(),
        })
    );
}
