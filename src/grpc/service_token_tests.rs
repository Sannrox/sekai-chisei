//! Client-credentials service tokens (#1510): issued through an identity
//! extension hook, sealed with the #1507 assertion key, admitted as the
//! registered service principal.

use super::*;
use crate::db::sekai::SekaiDb;
use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, EnterpriseExtension,
    ExtensionError, NamespaceAction, ServicePrincipalTokenGrant, ServicePrincipalTokenRequest,
    TenantContext,
};
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    IssueServicePrincipalTokenRequest, PutServicePrincipalRequest, ServicePrincipal,
};
use crate::identity_assertion::AssertionAuthority;
use crate::sekai::security::{Grant, Role};
use tonic::service::Interceptor as _;

struct NamespaceTenants {
    secret: String,
}

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

    fn issue_service_principal_token(
        &self,
        request: ServicePrincipalTokenRequest,
    ) -> Result<ServicePrincipalTokenGrant, ExtensionError> {
        if request.principal == "worker-a" && request.client_secret.expose() == self.secret {
            Ok(ServicePrincipalTokenGrant {
                credential_id: "cred-worker-a".into(),
                expires_at_ms: chrono::Utc::now().timestamp_millis() + 60_000,
            })
        } else {
            Err(ExtensionError::CredentialNotFound)
        }
    }
}

struct Plane {
    service: sekai_service::SekaiServiceImpl,
    interceptor: TokenAuthInterceptor,
    authority: Arc<AssertionAuthority>,
}

fn plane(with_extension: bool) -> Plane {
    let extension = with_extension.then(|| {
        Arc::new(NamespaceTenants {
            secret: "secret-ok".into(),
        }) as Arc<dyn EnterpriseExtension>
    });
    let db = if let Some(extension) = extension {
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap()
    } else {
        SekaiDb::new(":memory:").unwrap()
    };
    let store = crate::db::store::SekaiStore::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(
        Arc::new(db),
    )));
    let grant = Grant {
        id: "grant-registry-admin".into(),
        object_id: "service_principals".into(),
        principal: "tenant-admin".into(),
        role: Role::Admin,
        created: 0,
        ..Default::default()
    };
    store.runtime().create_grant(&grant).unwrap();
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"service-token-key",
    ));
    let service = sekai_service::SekaiServiceImpl::new(store.clone())
        .with_runtime_token_authority(Some(authority.clone()));
    service.security.add_grant(&grant);
    Plane {
        interceptor: TokenAuthInterceptor::from_runtime(
            Arc::new(PrincipalCredentialStore::new()),
            store,
            Some(authority.clone()),
        ),
        service,
        authority,
    }
}

fn admin_context() -> AuthenticatedContext {
    let mut context = AuthenticatedContext::machine(AuthenticatedPrincipal {
        subject: "tenant-admin".into(),
        credential_id: "credential-admin".into(),
    });
    context.tenant = Some(TenantContext {
        tenant_id: "tenant-a".into(),
        subject: "tenant-admin".into(),
    });
    context
}

async fn register(plane: &Plane) {
    let mut request = Request::new(PutServicePrincipalRequest {
        service_principal: Some(ServicePrincipal {
            principal: "worker-a".into(),
            tenant_id: "tenant-a".into(),
            namespaces: vec!["ns-a".into()],
            action_types: vec!["dispatch".into()],
            ..Default::default()
        }),
    });
    request.extensions_mut().insert(admin_context());
    plane.service.put_service_principal(request).await.unwrap();
}

async fn issue(plane: &Plane, principal: &str, secret: &str) -> Result<String, Status> {
    let response = plane
        .service
        .issue_service_principal_token(Request::new(IssueServicePrincipalTokenRequest {
            principal: principal.into(),
            client_secret: secret.into(),
        }))
        .await?
        .into_inner();
    assert!(crate::service_token::is_service_token(&response.token));
    assert!(response.expires_at_ms > 0);
    Ok(response.token)
}

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

#[tokio::test]
async fn valid_credentials_issue_a_token_that_authenticates_as_the_service_principal() {
    let plane = plane(true);
    register(&plane).await;
    let token = issue(&plane, "worker-a", "secret-ok").await.unwrap();
    let request = authenticate(&plane, &token, "GetObject").unwrap();
    let context = request.extensions().get::<AuthenticatedContext>().unwrap();
    assert_eq!(context.principal.subject, "worker-a");
    assert_eq!(context.credential_kind, CredentialKind::Machine);
    assert_eq!(
        context
            .tenant
            .as_ref()
            .map(|tenant| tenant.tenant_id.as_str()),
        Some("tenant-a")
    );
    assert_ne!(context.credential_kind, CredentialKind::HumanSession);
}

#[tokio::test]
async fn invalid_credentials_are_refused() {
    let plane = plane(true);
    register(&plane).await;
    let status = issue(&plane, "worker-a", "wrong").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn unregistered_principal_is_refused() {
    let plane = plane(true);
    let status = issue(&plane, "worker-a", "secret-ok").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn issuance_without_an_extension_is_refused() {
    let plane = plane(false);
    let status = issue(&plane, "worker-a", "secret-ok").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn expired_token_is_refused() {
    let plane = plane(true);
    register(&plane).await;
    let registration = plane
        .service
        .db
        .runtime()
        .get_service_principal("worker-a")
        .unwrap()
        .unwrap();
    let mut claims = crate::service_token::ServiceTokenClaims::for_grant(
        &plane.authority,
        &registration,
        "cred-worker-a",
        chrono::Utc::now().timestamp_millis() + 60_000,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    claims.expires_at_ms = chrono::Utc::now().timestamp_millis();
    let token = claims.sign(&plane.authority).unwrap();
    let status = authenticate(&plane, &token, "GetObject").unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[test]
fn issue_rpc_is_admitted_without_a_bearer() {
    let plane = plane(true);
    let mut request = Request::new(());
    request.extensions_mut().insert(tonic::GrpcMethod::new(
        "sekai.SekaiService",
        "IssueServicePrincipalToken",
    ));
    assert!(plane.interceptor.clone().call(request).is_ok());
}
