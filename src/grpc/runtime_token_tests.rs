//! Runtime tokens on Action work claims (#1507): issued on claim, admitted at
//! the authentication boundary for that claim only, refused once expired or
//! for another tenant or namespace.

use super::*;
use crate::db::sekai::SekaiDb;
use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, EnterpriseExtension, ExtensionError,
    NamespaceAction, TenantContext,
};
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{ClaimActionWorkRequest, HeartbeatActionClaimRequest};
use crate::identity_assertion::AssertionAuthority;
use crate::runtime_token::RuntimeTokenClaims;
use crate::sekai::action_effect::plan_effects_for_admit;
use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use crate::sekai::security::Role;
use std::collections::HashMap;
use tonic::Response;
use tonic::service::Interceptor as _;

const WORKER: &str = "worker";

/// Each namespace `ns-<x>` belongs to tenant `tenant-<x>`.
struct NamespaceTenants;

impl EnterpriseExtension for NamespaceTenants {
    fn authenticate_bearer(&self, _: &str) -> Result<AuthenticatedPrincipal, ExtensionError> {
        Err(ExtensionError::CredentialNotFound)
    }

    fn authenticate_context(&self, _: &str) -> Result<AuthenticatedContext, ExtensionError> {
        Err(ExtensionError::CredentialNotFound)
    }

    fn tenant_context(&self, _: &AuthenticatedPrincipal) -> Result<TenantContext, ExtensionError> {
        Err(ExtensionError::Unauthenticated)
    }

    fn authorize_namespace(
        &self,
        context: &TenantContext,
        namespace: &str,
        _: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        (namespace.strip_prefix("ns-") == context.tenant_id.strip_prefix("tenant-"))
            .then_some(())
            .ok_or(ExtensionError::PermissionDenied)
    }

    fn authorize_unscoped_namespace(
        &self,
        _: &AuthenticatedPrincipal,
        _: &str,
        _: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        Err(ExtensionError::PermissionDenied)
    }
}

struct Plane {
    service: sekai_service::SekaiServiceImpl,
    interceptor: TokenAuthInterceptor,
    authority: Arc<AssertionAuthority>,
}

fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(NamespaceTenants)))
            .unwrap(),
    )));
    for suffix in ["a", "b"] {
        seed_effect(&db, suffix);
    }
    let store = crate::db::store::SekaiStore::from_shared_runtime(db);
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"runtime-token-key",
    ));
    Plane {
        service: sekai_service::SekaiServiceImpl::new(store.clone())
            .with_runtime_token_authority(Some(authority.clone())),
        interceptor: TokenAuthInterceptor::from_runtime(
            Arc::new(PrincipalCredentialStore::new()),
            store,
            Some(authority.clone()),
        ),
        authority,
    }
}

/// One ready runtime_dispatch effect `effect-<suffix>` in `ns-<suffix>`.
fn seed_effect(db: &RuntimeDb, suffix: &str) {
    let namespace = format!("ns-{suffix}");
    db.ensure_team_namespace(&namespace, WORKER, Role::Admin, WORKER)
        .unwrap();
    let mut effect = plan_effects_for_admit(
        &format!("instance-{suffix}"),
        &namespace,
        &format!("operation-{suffix}"),
        &["runtime_dispatch".into()],
        "{}",
        10,
        false,
    )
    .unwrap()
    .remove(0);
    effect.effect_id = format!("effect-{suffix}");
    db.put_action_instance(&ActionInstance {
        agent_turn: None,
        instance_id: effect.instance_id.clone(),
        namespace,
        type_id: "dispatch".into(),
        version: "1".into(),
        principal: WORKER.into(),
        delegating_actor: None,
        parameters_json: "{}".into(),
        request_digest: "digest".into(),
        idempotency_key: format!("idem-{suffix}"),
        operation_id: effect.operation_id.clone(),
        status: STATUS_ADMITTED.into(),
        deny_reason: String::new(),
        evidence_submission_ids: Vec::new(),
        policy_decision: "allow".into(),
        budget_decision: "allow".into(),
        created_at_ms: 10,
        decided_at_ms: 10,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
        review: Default::default(),
        agent_action: false,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
        marking: String::new(),
        conflict: None,
        approval: None,
        offline: None,
        admission_lease: None,
        admission_ontology_digest: None,
        admission_budget_already_reserved: false,
    })
    .unwrap();
    db.put_action_effects(&[effect]).unwrap();
}

/// A tenant-bound context as the boundary hands it to the claim handler.
fn tenant_context(tenant_id: &str) -> AuthenticatedContext {
    let mut context = AuthenticatedContext::machine(AuthenticatedPrincipal {
        subject: WORKER.into(),
        credential_id: "credential-w".into(),
    });
    context.tenant = Some(TenantContext {
        tenant_id: tenant_id.into(),
        subject: WORKER.into(),
    });
    context
}

async fn claim(plane: &Plane, suffix: &str) -> crate::grpc::pb::sekai::ClaimActionWorkResponse {
    claim_as(plane, suffix, "runner-a", 60_000).await
}

async fn claim_as(
    plane: &Plane,
    suffix: &str,
    runtime_id: &str,
    ttl_ms: i64,
) -> crate::grpc::pb::sekai::ClaimActionWorkResponse {
    let mut request = Request::new(ClaimActionWorkRequest {
        effect_id: format!("effect-{suffix}"),
        runtime_id: runtime_id.into(),
        request_id: format!("claim-{suffix}-{runtime_id}"),
        ttl_ms,
    });
    request
        .extensions_mut()
        .insert(tenant_context(&format!("tenant-{suffix}")));
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(WORKER));
    plane
        .service
        .claim_action_work(request)
        .await
        .unwrap()
        .into_inner()
}

/// Run `token` through the authentication boundary for `method`.
fn authenticate(plane: &Plane, token: &str, method: &'static str) -> Result<Request<()>, Status> {
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
    plane.interceptor.clone().call(request)
}

async fn heartbeat_with(
    plane: &Plane,
    token: &str,
    claimed: &crate::grpc::pb::sekai::ActionEffect,
) -> Result<crate::grpc::pb::sekai::HeartbeatActionClaimResponse, Status> {
    let (metadata, extensions, ()) =
        authenticate(plane, token, "HeartbeatActionClaim")?.into_parts();
    let request = Request::from_parts(
        metadata,
        extensions,
        HeartbeatActionClaimRequest {
            effect_id: claimed.effect_id.clone(),
            runtime_id: claimed.claim_owner.clone(),
            claim_generation: claimed.claim_generation,
            fencing_token: claimed.claim_fencing_token.clone(),
            ttl_ms: 60_000,
        },
    );
    plane
        .service
        .heartbeat_action_claim(request)
        .await
        .map(Response::into_inner)
}

/// Claims bound to `claimed`, for a test to alter and sign with the plane key.
fn forged(plane: &Plane, claimed: &crate::grpc::pb::sekai::ActionEffect) -> RuntimeTokenClaims {
    RuntimeTokenClaims {
        contract_version: crate::runtime_token::RUNTIME_TOKEN_VERSION.into(),
        issuer: plane.authority.issuer.clone(),
        audience: plane.authority.audience.clone(),
        subject: WORKER.into(),
        act: None,
        space: None,
        space_role: None,
        tenant_id: "tenant-a".into(),
        namespace: claimed.namespace.clone(),
        effect_id: claimed.effect_id.clone(),
        turn_id: String::new(),
        runtime_id: claimed.claim_owner.clone(),
        claim_generation: claimed.claim_generation,
        expires_at_ms: claimed.claim_expires_at_ms,
        authority_expires_at_ms: i64::MAX,
        service_principal: false,
        jti: "forged".into(),
    }
}

#[tokio::test]
async fn claim_returns_a_token_that_authenticates_its_heartbeat() {
    let plane = plane();
    let claimed = claim(&plane, "a").await;
    let effect = claimed.effect.unwrap();
    assert!(crate::runtime_token::is_runtime_token(
        &claimed.runtime_token
    ));
    assert!(claimed.runtime_token_expires_at_ms > 0);
    assert!(claimed.runtime_token_expires_at_ms <= effect.claim_expires_at_ms);

    let refreshed = heartbeat_with(&plane, &claimed.runtime_token, &effect)
        .await
        .unwrap();
    let extended = refreshed.effect.unwrap();
    assert!(crate::runtime_token::is_runtime_token(
        &refreshed.runtime_token
    ));
    assert!(refreshed.runtime_token_expires_at_ms <= extended.claim_expires_at_ms);
}

#[tokio::test]
async fn claim_without_tenant_stays_compatible_and_issues_no_token() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    seed_effect(&db, "a");
    let service =
        sekai_service::SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
            .with_runtime_token_authority(Some(plane().authority));
    let mut request = Request::new(ClaimActionWorkRequest {
        effect_id: "effect-a".into(),
        runtime_id: "runner-a".into(),
        request_id: "claim-a".into(),
        ttl_ms: 60_000,
    });
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(WORKER));
    let claimed = service
        .claim_action_work(request)
        .await
        .unwrap()
        .into_inner();
    assert!(claimed.effect.is_some());
    assert!(claimed.runtime_token.is_empty());
    assert_eq!(claimed.runtime_token_expires_at_ms, 0);
}

#[tokio::test]
async fn expired_token_is_refused() {
    let plane = plane();
    let effect = claim(&plane, "a").await.effect.unwrap();
    let mut expired = forged(&plane, &effect);
    expired.expires_at_ms = chrono::Utc::now().timestamp_millis();
    let token = expired.sign(&plane.authority).unwrap();
    let status = heartbeat_with(&plane, &token, &effect).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn token_for_another_tenant_or_namespace_is_refused() {
    let plane = plane();
    let effect = claim(&plane, "a").await.effect.unwrap();

    let mut other_tenant = forged(&plane, &effect);
    other_tenant.tenant_id = "tenant-b".into();
    let token = other_tenant.sign(&plane.authority).unwrap();
    let status = heartbeat_with(&plane, &token, &effect).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    // The token issued for ns-b's claim cannot touch ns-a's claim.
    let other_namespace = claim(&plane, "b").await.runtime_token;
    let status = heartbeat_with(&plane, &other_namespace, &effect)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    // The forged baseline itself is accepted, so the refusals above are the binding.
    let token = forged(&plane, &effect).sign(&plane.authority).unwrap();
    heartbeat_with(&plane, &token, &effect).await.unwrap();
}

#[tokio::test]
async fn token_for_an_earlier_claim_generation_is_refused() {
    let plane = plane();
    let first = claim_as(&plane, "a", "runner-a", 1).await.effect.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let second = claim_as(&plane, "a", "runner-b", 60_000)
        .await
        .effect
        .unwrap();
    assert!(second.claim_generation > first.claim_generation);
    let mut stale = forged(&plane, &first);
    stale.expires_at_ms = second.claim_expires_at_ms;
    let token = stale.sign(&plane.authority).unwrap();
    let status = heartbeat_with(&plane, &token, &first).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[test]
fn token_admits_only_calls_for_its_claim() {
    let plane = plane();
    let claims = forged(
        &plane,
        &crate::grpc::pb::sekai::ActionEffect {
            namespace: "ns-a".into(),
            effect_id: "effect-a".into(),
            claim_owner: "runner-a".into(),
            claim_generation: 1,
            claim_expires_at_ms: i64::MAX,
            ..Default::default()
        },
    );
    let token = claims.sign(&plane.authority).unwrap();
    for method in [
        "AckActionWork",
        "ReportActionClaimEvent",
        "HeartbeatActionClaim",
    ] {
        assert!(authenticate(&plane, &token, method).is_ok(), "{method}");
    }
    for method in ["ClaimActionWork", "GetObject", "ListClaimableActionWork"] {
        let status = authenticate(&plane, &token, method).unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{method}");
    }
}

/// A site agent instance `line-<suffix>` in `ns-<suffix>`, acting as
/// `agent:line-<suffix>`, with one pending manual turn.
fn seed_turn(plane: &Plane, suffix: &str) -> String {
    let db = plane.service.db.runtime();
    // The instance's principal acts in its namespace, as its Actions do.
    db.ensure_team_namespace(
        &format!("ns-{suffix}"),
        &format!("agent:line-{suffix}"),
        Role::Admin,
        "root",
    )
    .unwrap();
    db.create_object(&crate::domain::Object {
        id: format!("line-{suffix}"),
        kind: crate::sekai::site_agent_instance::KIND.into(),
        name: format!("line-{suffix}"),
        namespace: format!("ns-{suffix}"),
        external_id: String::new(),
        properties: HashMap::from([
            ("principal_id".to_string(), format!("agent:line-{suffix}")),
            ("frozen".to_string(), "false".to_string()),
        ]),
        created: 1,
        updated: 1,
    })
    .unwrap();
    crate::sekai::agent_turn::admit(
        db,
        crate::sekai::agent_turn::Wake {
            namespace: format!("ns-{suffix}"),
            instance_id: format!("line-{suffix}"),
            cause: crate::sekai::agent_turn::Cause::Manual,
            cause_ref: format!("wake-{suffix}"),
            due_at_ms: 1,
        },
        "root",
        1,
    )
    .unwrap()
    .turn_id
}

/// The worker identity turn claims are made with: credential admin, under
/// tenant `tenant-<suffix>` (scoped turn workers are #2006).
const TURN_WORKER: &str = "local";

/// Claim `turn_id` as credential admin under tenant `tenant-<suffix>`.
async fn claim_turn(
    plane: &Plane,
    suffix: &str,
    turn_id: &str,
) -> crate::grpc::pb::sekai::ClaimAgentTurnResponse {
    let mut request = Request::new(crate::grpc::pb::sekai::ClaimAgentTurnRequest {
        namespace: format!("ns-{suffix}"),
        runtime_id: "runner-a".into(),
        turn_id: turn_id.into(),
        ttl_ms: 60_000,
    });
    let mut context = tenant_context(&format!("tenant-{suffix}"));
    context.principal.subject = TURN_WORKER.into();
    request.extensions_mut().insert(context);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(TURN_WORKER));
    plane
        .service
        .claim_agent_turn(request)
        .await
        .unwrap()
        .into_inner()
}

/// `body` sent with `token` through the boundary for `method`.
fn with_token<T>(plane: &Plane, token: &str, method: &'static str, body: T) -> Request<T> {
    let (metadata, extensions, ()) = authenticate(plane, token, method).unwrap().into_parts();
    Request::from_parts(metadata, extensions, body)
}

#[tokio::test]
async fn a_turn_claim_returns_a_token_acting_as_the_instance() {
    let plane = plane();
    let turn_id = seed_turn(&plane, "a");
    let claimed = claim_turn(&plane, "a", &turn_id).await;
    let turn = claimed.turn.unwrap();
    assert!(
        claimed
            .runtime_token
            .starts_with(crate::runtime_token::RUNTIME_TOKEN_PREFIX)
    );
    assert!(claimed.runtime_token_expires_at_ms <= turn.claim_expires_at_ms);
    let claims = RuntimeTokenClaims::verify(
        &plane.authority,
        &claimed.runtime_token,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    assert_eq!(claims.subject, "agent:line-a");
    assert_eq!(claims.act.as_deref(), Some(TURN_WORKER));
    assert_eq!(
        (claims.turn_id.as_str(), claims.effect_id.as_str()),
        (turn_id.as_str(), "")
    );

    // Admitted only for the turn's follow-up calls and its submissions.
    for method in [
        "HeartbeatAgentTurnClaim",
        "AckAgentTurn",
        "SubmitActionInstance",
    ] {
        assert!(
            authenticate(&plane, &claimed.runtime_token, method).is_ok(),
            "{method}"
        );
    }
    for method in [
        "HeartbeatActionClaim",
        "ClaimAgentTurn",
        "DecideActionInstance",
    ] {
        assert_eq!(
            authenticate(&plane, &claimed.runtime_token, method)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied,
            "{method}"
        );
    }

    // A heartbeat renews it as the same principal and worker.
    let renewed = plane
        .service
        .heartbeat_agent_turn_claim(with_token(
            &plane,
            &claimed.runtime_token,
            "HeartbeatAgentTurnClaim",
            crate::grpc::pb::sekai::HeartbeatAgentTurnClaimRequest {
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
    let renewed_claims = RuntimeTokenClaims::verify(
        &plane.authority,
        &renewed.runtime_token,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    assert_eq!(
        (
            renewed_claims.subject.as_str(),
            renewed_claims.act.as_deref()
        ),
        ("agent:line-a", Some(TURN_WORKER))
    );
    assert_ne!(renewed_claims.jti, claims.jti);
}

#[tokio::test]
async fn a_turn_token_submits_only_for_its_live_claim() {
    let plane = plane();
    let turn_id = seed_turn(&plane, "a");
    let claimed = claim_turn(&plane, "a", &turn_id).await;
    let turn = claimed.turn.unwrap();
    let token = claimed.runtime_token;
    let submission = |namespace: &str| {
        let request = with_token(&plane, &token, "SubmitActionInstance", ());
        plane
            .service
            .authorize_turn_submission(&request, namespace)
            .map_err(|status| status.code())
    };
    assert_eq!(submission("ns-a"), Ok(()));
    assert_eq!(submission("ns-b"), Err(tonic::Code::PermissionDenied));

    // A frozen instance submits nothing.
    let db = plane.service.db.runtime();
    let mut instance = db.get_object("line-a").unwrap().unwrap();
    instance.properties.insert("frozen".into(), "true".into());
    instance.updated += 1;
    db.update_object(&instance).unwrap();
    assert_eq!(submission("ns-a"), Err(tonic::Code::FailedPrecondition));
    instance.properties.insert("frozen".into(), "false".into());
    instance.updated += 1;
    db.update_object(&instance).unwrap();
    assert_eq!(submission("ns-a"), Ok(()));

    // Once the claim ends, the token covers nothing but a retry of its ack.
    let ack = |outcome: &str| {
        plane.service.ack_agent_turn(with_token(
            &plane,
            &token,
            "AckAgentTurn",
            crate::grpc::pb::sekai::AckAgentTurnRequest {
                parked_action_instance_id: String::new(),
                turn_id: turn_id.clone(),
                runtime_id: turn.claim_owner.clone(),
                claim_generation: turn.claim_generation,
                fencing_token: turn.fencing_token.clone(),
                outcome: outcome.into(),
                reason: String::new(),
            },
        ))
    };
    ack("completed").await.unwrap();
    // A lost response is retried with the same token and outcome.
    assert_eq!(
        ack("completed")
            .await
            .unwrap()
            .into_inner()
            .turn
            .unwrap()
            .status,
        "completed"
    );
    assert!(ack("failed").await.is_err());
    assert_eq!(submission("ns-a"), Err(tonic::Code::PermissionDenied));
    let after = plane
        .service
        .heartbeat_agent_turn_claim(with_token(
            &plane,
            &token,
            "HeartbeatAgentTurnClaim",
            crate::grpc::pb::sekai::HeartbeatAgentTurnClaimRequest {
                turn_id,
                runtime_id: turn.claim_owner,
                claim_generation: turn.claim_generation,
                fencing_token: turn.fencing_token,
                ttl_ms: 60_000,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(after.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn a_parked_turn_resumes_with_its_continuation_once_decided() {
    let plane = plane();
    let turn_id = seed_turn(&plane, "a");
    let claimed = claim_turn(&plane, "a", &turn_id).await;
    let turn = claimed.turn.unwrap();
    assert!(claimed.continuation.is_none());
    // The turn's Action, submitted under this claim, awaits approval.
    let db = plane.service.db.runtime();
    db.put_action_instance(&ActionInstance {
        agent_turn: Some(crate::sekai::action_instance::AgentTurnFence {
            turn_id: turn_id.clone(),
            claim_generation: u64::try_from(turn.claim_generation).unwrap(),
        }),
        instance_id: "parked-a".into(),
        namespace: "ns-a".into(),
        type_id: "dispatch".into(),
        version: "1".into(),
        principal: "agent:line-a".into(),
        delegating_actor: None,
        parameters_json: "{}".into(),
        request_digest: "digest".into(),
        idempotency_key: "idem-parked-a".into(),
        operation_id: "operation-parked-a".into(),
        status: crate::sekai::action_instance::STATUS_PARKED.into(),
        deny_reason: String::new(),
        evidence_submission_ids: Vec::new(),
        policy_decision: "require_approval".into(),
        budget_decision: "allow".into(),
        created_at_ms: 10,
        decided_at_ms: 0,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
        review: Default::default(),
        agent_action: true,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
        marking: String::new(),
        conflict: None,
        approval: None,
        offline: None,
        admission_lease: None,
        admission_ontology_digest: None,
        admission_budget_already_reserved: false,
    })
    .unwrap();
    let parked = plane
        .service
        .ack_agent_turn(with_token(
            &plane,
            &claimed.runtime_token,
            "AckAgentTurn",
            crate::grpc::pb::sekai::AckAgentTurnRequest {
                turn_id: turn_id.clone(),
                runtime_id: turn.claim_owner.clone(),
                claim_generation: turn.claim_generation,
                fencing_token: turn.fencing_token.clone(),
                outcome: "parked".into(),
                reason: "awaiting approval".into(),
                parked_action_instance_id: "parked-a".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    assert_eq!(
        (
            parked.status.as_str(),
            parked.park_count,
            parked.reason.as_str()
        ),
        ("parked", 1, "awaiting approval")
    );

    // Undecided, the turn is not reclaimed.
    let mut retry = Request::new(crate::grpc::pb::sekai::ClaimAgentTurnRequest {
        namespace: "ns-a".into(),
        runtime_id: "runner-a".into(),
        turn_id: turn_id.clone(),
        ttl_ms: 60_000,
    });
    let mut context = tenant_context("tenant-a");
    context.principal.subject = TURN_WORKER.into();
    retry.extensions_mut().insert(context);
    retry
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(TURN_WORKER));
    assert_eq!(
        plane
            .service
            .claim_agent_turn(retry)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    // Decided and recorded, the next claim carries the continuation.
    db.put_operation_receipt(&sekai_domain::receipt::OperationReceipt {
        version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
        operation_id: "operation-parked-a".into(),
        parent_operation_id: None,
        namespace: "ns-a".into(),
        operation_class: "action_instance".into(),
        initiating_actor: "approver".into(),
        schema_version: "v1".into(),
        policy_version: "v1".into(),
        started_at_ms: 1,
        completed_at_ms: None,
        events: vec![sekai_domain::receipt::OperationReceiptEvent {
            event_id: "parked-a-decided".into(),
            operation_id: "operation-parked-a".into(),
            parent_event_id: None,
            timestamp_ms: 1,
            kind: sekai_domain::receipt::ReceiptEventKind::ApprovalDecided,
            surface: sekai_domain::receipt::ReceiptSurface::Approval,
            actor: "approver".into(),
            references: Vec::new(),
            attributes: Default::default(),
        }],
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
        ontology_digest: None,
        artifact: None,
    })
    .unwrap();
    if let RuntimeDb::Sqlite(store) = db {
        store
            .conn()
            .execute(
                "UPDATE sekai_action_instances
                 SET status = 'admitted', body_json = json_set(body_json, '$.status', 'admitted',
                     '$.approval_decision', 'grant')
                 WHERE instance_id = 'parked-a'",
                [],
            )
            .unwrap();
    }
    let resumed = claim_turn(&plane, "a", &turn_id).await;
    let continuation = resumed.continuation.unwrap();
    assert_eq!(
        (
            continuation.action_instance_id.as_str(),
            continuation.status.as_str(),
            continuation.approval_decision.as_str()
        ),
        ("parked-a", "admitted", "grant")
    );
    assert_eq!(
        resumed.turn.unwrap().claim_generation,
        turn.claim_generation + 1
    );
}
