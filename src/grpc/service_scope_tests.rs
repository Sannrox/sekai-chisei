//! Service-principal scope enforcement (#1511): a service token is refused
//! outside its registered namespaces, Action types and marking ceiling, and
//! the per-claim runtime token stays within the same scope.

use super::*;
use crate::db::sekai::SekaiDb;
use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, EnterpriseExtension, ExtensionError,
    NamespaceAction, TenantContext,
};
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    ClaimActionWorkRequest, ClaimActionWorkResponse, DiscoverCapabilitiesRequest, GetObjectRequest,
    GovernedActionType, HeartbeatActionClaimRequest, PutGovernedActionTypeRequest,
    SubmitActionInstanceRequest,
};
use crate::identity_assertion::AssertionAuthority;
use crate::sekai::action_effect::plan_effects_for_admit;
use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use crate::sekai::markings;
use crate::sekai::security::{Grant, Role};
use crate::sekai::service_principal::ServicePrincipalRegistration;
use crate::service_token::ServiceTokenClaims;
use std::collections::HashMap;
use tonic::Response;
use tonic::service::Interceptor as _;

const WORKER: &str = "worker-a";
/// Allowlisted namespace of tenant `tenant-a`.
const IN_SCOPE: &str = "a-in";
/// Namespace of tenant `tenant-a` that the registration does not list.
const OUT_OF_SCOPE: &str = "a-out";

/// Tenant `tenant-<x>` owns every namespace `<x>-*`.
struct PrefixTenants;

impl EnterpriseExtension for PrefixTenants {
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
        let owner = namespace.split('-').next().unwrap_or_default();
        (context.tenant_id.strip_prefix("tenant-") == Some(owner))
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
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(PrefixTenants))).unwrap(),
    )));
    db.put_service_principal(&registration()).unwrap().unwrap();
    seed_effect(&db, "effect-ok", IN_SCOPE, "dispatch");
    seed_effect(&db, "effect-type", IN_SCOPE, "other");
    seed_effect(&db, "effect-ns", OUT_OF_SCOPE, "dispatch");
    let store = crate::db::store::SekaiStore::from_shared_runtime(db);
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"service-scope-key",
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

fn registration() -> ServicePrincipalRegistration {
    ServicePrincipalRegistration {
        capabilities: Vec::new(),
        principal: WORKER.into(),
        tenant_id: "tenant-a".into(),
        namespaces: vec![IN_SCOPE.into()],
        action_types: vec!["dispatch".into()],
        registered_by: "root".into(),
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

/// A ready runtime_dispatch effect for an admitted instance of `type_id`.
fn seed_effect(db: &RuntimeDb, effect_id: &str, namespace: &str, type_id: &str) {
    db.ensure_team_namespace(namespace, WORKER, Role::Admin, WORKER)
        .unwrap();
    let mut effect = plan_effects_for_admit(
        &format!("instance-{effect_id}"),
        namespace,
        &format!("operation-{effect_id}"),
        &["runtime_dispatch".into()],
        "{}",
        10,
        false,
    )
    .unwrap()
    .remove(0);
    effect.effect_id = effect_id.into();
    db.put_action_instance(&ActionInstance {
        agent_turn: None,
        instance_id: effect.instance_id.clone(),
        namespace: namespace.into(),
        type_id: type_id.into(),
        version: "1".into(),
        principal: WORKER.into(),
        delegating_actor: None,
        parameters_json: "{}".into(),
        request_digest: "digest".into(),
        idempotency_key: format!("idem-{effect_id}"),
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

fn service_token(plane: &Plane) -> String {
    let now = chrono::Utc::now().timestamp_millis();
    ServiceTokenClaims::for_grant(
        &plane.authority,
        &registration(),
        "cred-worker-a",
        now + 60_000,
        now,
    )
    .unwrap()
    .sign(&plane.authority)
    .unwrap()
}

/// Authenticate `token` for `method` and attach `message`.
fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

fn authenticated<T>(
    plane: &Plane,
    token: &str,
    method: &'static str,
    message: T,
) -> Result<Request<T>, Status> {
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
    let (metadata, extensions, ()) = plane.interceptor.clone().call(request)?.into_parts();
    Ok(Request::from_parts(metadata, extensions, message))
}

async fn claim(plane: &Plane, effect_id: &str) -> Result<ClaimActionWorkResponse, Status> {
    let request = authenticated(
        plane,
        &service_token(plane),
        "ClaimActionWork",
        ClaimActionWorkRequest {
            effect_id: effect_id.into(),
            runtime_id: "runner-a".into(),
            request_id: format!("claim-{effect_id}"),
            ttl_ms: 60_000,
        },
    )?;
    plane
        .service
        .claim_action_work(request)
        .await
        .map(Response::into_inner)
}

async fn heartbeat(
    plane: &Plane,
    claimed: &ClaimActionWorkResponse,
) -> Result<crate::grpc::pb::sekai::HeartbeatActionClaimResponse, Status> {
    let effect = claimed.effect.as_ref().unwrap();
    let request = authenticated(
        plane,
        &claimed.runtime_token,
        "HeartbeatActionClaim",
        HeartbeatActionClaimRequest {
            effect_id: effect.effect_id.clone(),
            runtime_id: effect.claim_owner.clone(),
            claim_generation: effect.claim_generation,
            fencing_token: effect.claim_fencing_token.clone(),
            ttl_ms: 60_000,
        },
    )?;
    plane
        .service
        .heartbeat_action_claim(request)
        .await
        .map(Response::into_inner)
}

fn assert_scope_refusal(status: &Status, dimension: &str) {
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
    assert!(
        status
            .message()
            .contains(&format!("{dimension} outside the service principal scope")),
        "{status:?}"
    );
}

#[tokio::test]
async fn claim_inside_every_scope_derives_a_scoped_runtime_token() {
    let plane = plane();
    let claimed = claim(&plane, "effect-ok").await.unwrap();
    assert!(crate::runtime_token::is_runtime_token(
        &claimed.runtime_token
    ));
    heartbeat(&plane, &claimed).await.unwrap();

    // Narrowing the registration's Action types applies to follow-up calls.
    let mut narrowed = registration();
    narrowed.action_types = vec!["other".into()];
    let db = plane.service.db.runtime();
    db.put_service_principal(&narrowed).unwrap().unwrap();
    let status = heartbeat(&plane, &claimed).await.unwrap_err();
    assert_scope_refusal(&status, "action type");
    db.put_service_principal(&registration()).unwrap().unwrap();
    heartbeat(&plane, &claimed).await.unwrap();

    // Removing the registration revokes the derived runtime token as well.
    plane
        .service
        .db
        .runtime()
        .delete_service_principal(WORKER, "tenant-a")
        .unwrap();
    let status = heartbeat(&plane, &claimed).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn namespace_outside_the_allowlist_is_refused() {
    let plane = plane();
    let status = claim(&plane, "effect-ns").await.unwrap_err();
    assert_scope_refusal(&status, "namespace");
}

#[tokio::test]
async fn action_type_outside_the_registration_is_refused_on_claim_and_submit() {
    let plane = plane();
    let status = claim(&plane, "effect-type").await.unwrap_err();
    assert_scope_refusal(&status, "action type");

    let submit = |type_id: &str| SubmitActionInstanceRequest {
        namespace: IN_SCOPE.into(),
        type_id: type_id.into(),
        version: "1".into(),
        parameters_json: "{}".into(),
        idempotency_key: format!("idem-submit-{type_id}"),
        request_id: format!("req-submit-{type_id}"),
        ..Default::default()
    };
    let token = service_token(&plane);
    let request = authenticated(&plane, &token, "SubmitActionInstance", submit("other")).unwrap();
    let status = plane
        .service
        .submit_action_instance(request)
        .await
        .unwrap_err();
    assert_scope_refusal(&status, "action type");
    // A registered type passes the scope check; this unseeded type then
    // fails admission for its own reason.
    let request =
        authenticated(&plane, &token, "SubmitActionInstance", submit("dispatch")).unwrap();
    if let Err(status) = plane.service.submit_action_instance(request).await {
        assert!(
            !status.message().contains("service principal scope"),
            "{status:?}"
        );
    }
}

#[tokio::test]
async fn capability_discovery_lists_only_registered_service_principal_action_types() {
    let plane = plane();
    let put = |type_id: &str| {
        PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            namespace: IN_SCOPE.into(),
            type_id: type_id.into(),
            version: "1.0.0".into(),
            description: type_id.into(),
            parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["runtime_dispatch".into()],
            enabled: true,
            ..Default::default()
        }),
        request_id: format!("put-{type_id}"),
    }
    };
    plane
        .service
        .put_governed_action_type(with_named_principal(put("dispatch"), "local"))
        .await
        .unwrap();
    plane
        .service
        .put_governed_action_type(with_named_principal(put("other"), "local"))
        .await
        .unwrap();
    let token = service_token(&plane);
    let discovered = plane
        .service
        .discover_capabilities(
            authenticated(
                &plane,
                &token,
                "DiscoverCapabilities",
                DiscoverCapabilitiesRequest {
                    namespace: IN_SCOPE.into(),
                    page_size: 200,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .into_inner();
    let names: Vec<&str> = discovered
        .capabilities
        .iter()
        .filter(|entry| entry.name.starts_with("sekai.actions."))
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(names, vec!["sekai.actions.dispatch"]);
}

#[tokio::test]
async fn object_above_the_profile_marking_ceiling_is_refused() {
    let plane = plane();
    let db = plane.service.db.runtime();
    let object = |id: &str, kind: &str, properties: &[(&str, &str)]| crate::domain::Object {
        id: id.into(),
        kind: kind.into(),
        name: id.into(),
        namespace: IN_SCOPE.into(),
        external_id: String::new(),
        properties: properties
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
        created: 0,
        updated: 0,
    };
    let mut profile = object(
        "profile-worker-a",
        markings::PRINCIPAL_PROFILE_KIND,
        &[
            (
                markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY,
                "internal",
            ),
            (markings::PRINCIPAL_PROFILE_SEALED_PROPERTY, "true"),
        ],
    );
    profile.external_id = markings::principal_profile_external_id(WORKER);
    db.create_object(&profile).unwrap();
    db.create_grant(&Grant {
        id: "grant-profile".into(),
        object_id: "profile-worker-a".into(),
        principal: "root".into(),
        role: Role::Admin,
        created: 0,
        ..Default::default()
    })
    .unwrap();
    for (id, marking) in [
        ("doc-internal", "internal"),
        ("doc-confidential", "confidential"),
    ] {
        db.create_object(&object(
            id,
            "document",
            &[(markings::OBJECT_CLASSIFICATION_PROPERTY, marking)],
        ))
        .unwrap();
    }

    let token = service_token(&plane);
    let get = |id: &str| GetObjectRequest { id: id.into() };
    let request = authenticated(&plane, &token, "GetObject", get("doc-internal")).unwrap();
    plane.service.get_object(request).await.unwrap();
    let request = authenticated(&plane, &token, "GetObject", get("doc-confidential")).unwrap();
    let status = plane.service.get_object(request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

/// A site agent instance acting as `agent:<namespace>` with one pending
/// manual turn in `namespace`.
fn seed_turn(plane: &Plane, namespace: &str) -> String {
    let db = plane.service.db.runtime();
    let principal = format!("agent:{namespace}");
    db.ensure_team_namespace(namespace, &principal, Role::Admin, "root")
        .unwrap();
    db.create_object(&crate::domain::Object {
        id: format!("line-{namespace}"),
        kind: crate::sekai::site_agent_instance::KIND.into(),
        name: format!("line-{namespace}"),
        namespace: namespace.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("principal_id".to_string(), principal),
            ("frozen".to_string(), "false".to_string()),
        ]),
        created: 1,
        updated: 1,
    })
    .unwrap();
    crate::sekai::agent_turn::admit(
        db,
        crate::sekai::agent_turn::Wake {
            namespace: namespace.into(),
            instance_id: format!("line-{namespace}"),
            cause: crate::sekai::agent_turn::Cause::Manual,
            cause_ref: format!("wake-{namespace}"),
            due_at_ms: 1,
        },
        "root",
        1,
    )
    .unwrap()
    .turn_id
}

async fn claim_turn(
    plane: &Plane,
    namespace: &str,
    turn_id: &str,
) -> Result<crate::grpc::pb::sekai::ClaimAgentTurnResponse, Status> {
    let request = authenticated(
        plane,
        &service_token(plane),
        "ClaimAgentTurn",
        crate::grpc::pb::sekai::ClaimAgentTurnRequest {
            namespace: namespace.into(),
            runtime_id: "runner-a".into(),
            turn_id: turn_id.into(),
            ttl_ms: 60_000,
        },
    )?;
    plane
        .service
        .claim_agent_turn(request)
        .await
        .map(Response::into_inner)
}

#[tokio::test]
async fn a_registered_turn_worker_works_turns_in_its_namespaces_only() {
    let plane = plane();
    let in_scope = seed_turn(&plane, IN_SCOPE);
    let out_of_scope = seed_turn(&plane, OUT_OF_SCOPE);

    // Without the capability a service principal is no turn worker.
    assert_eq!(
        claim_turn(&plane, IN_SCOPE, &in_scope)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    plane
        .service
        .db
        .runtime()
        .put_service_principal(&ServicePrincipalRegistration {
            capabilities: vec![crate::sekai::service_principal::AGENT_TURN_WORKER.into()],
            ..registration()
        })
        .unwrap()
        .unwrap();
    let listed = plane
        .service
        .list_claimable_agent_turns(
            authenticated(
                &plane,
                &service_token(&plane),
                "ListClaimableAgentTurns",
                crate::grpc::pb::sekai::ListClaimableAgentTurnsRequest {
                    namespace: IN_SCOPE.into(),
                    limit: 10,
                },
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .into_inner()
        .turns;
    assert_eq!(listed.len(), 1);
    let claimed = claim_turn(&plane, IN_SCOPE, &in_scope).await.unwrap();
    let turn = claimed.turn.unwrap();
    // Its turn token acts as the instance, with the worker as actor.
    let token = verified_token(&plane, &claimed.runtime_token);
    assert_eq!(
        (token.subject.as_str(), token.act.as_deref()),
        ("agent:a-in", Some(WORKER))
    );
    assert!(!token.service_principal);
    plane
        .service
        .ack_agent_turn(
            authenticated(
                &plane,
                &service_token(&plane),
                "AckAgentTurn",
                crate::grpc::pb::sekai::AckAgentTurnRequest {
                    turn_id: in_scope,
                    runtime_id: turn.claim_owner,
                    claim_generation: turn.claim_generation,
                    fencing_token: turn.fencing_token,
                    outcome: "completed".into(),
                    reason: String::new(),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Outside its registered namespaces it is refused.
    assert_scope_refusal(
        &claim_turn(&plane, OUT_OF_SCOPE, &out_of_scope)
            .await
            .unwrap_err(),
        "namespace",
    );
}

fn verified_token(plane: &Plane, token: &str) -> crate::runtime_token::RuntimeTokenClaims {
    crate::runtime_token::RuntimeTokenClaims::verify(
        &plane.authority,
        token,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap()
}
