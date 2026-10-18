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
