//! Service-principal scope registry RPCs (#1508): administrators only, and
//! only within the caller's tenant authority.

use super::*;
use crate::db::sekai::SekaiDb;
use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, EnterpriseExtension, ExtensionError,
    NamespaceAction, TenantContext,
};
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    DeleteServicePrincipalRequest, GetServicePrincipalRequest, PutServicePrincipalRequest,
    ServicePrincipal,
};
use crate::sekai::markings;
use crate::sekai::security::{Grant, Role};
use std::collections::HashMap;

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

fn service(extension: bool) -> sekai_service::SekaiServiceImpl {
    let db = if extension {
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(NamespaceTenants)))
    } else {
        SekaiDb::new(":memory:")
    };
    let store = crate::db::store::SekaiStore::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(
        Arc::new(db.unwrap()),
    )));
    let service = sekai_service::SekaiServiceImpl::new(store);
    let grant = Grant {
        id: "grant-registry-admin".into(),
        object_id: "service_principals".into(),
        principal: "tenant-admin".into(),
        role: Role::Admin,
        created: 0,
        ..Default::default()
    };
    service.db.runtime().create_grant(&grant).unwrap();
    service.security.add_grant(&grant);
    service
}

/// A request as the boundary hands it on: `subject`, optionally tenant-bound.
fn request<T>(message: T, subject: &str, tenant: Option<&str>) -> Request<T> {
    let mut context = AuthenticatedContext::machine(AuthenticatedPrincipal {
        subject: subject.into(),
        credential_id: format!("credential-{subject}"),
    });
    context.tenant = tenant.map(|tenant_id| TenantContext {
        tenant_id: tenant_id.into(),
        subject: subject.into(),
    });
    let mut request = Request::new(message);
    request.extensions_mut().insert(context);
    request
}

fn put(tenant_id: &str, namespaces: &[&str]) -> PutServicePrincipalRequest {
    PutServicePrincipalRequest {
        service_principal: Some(ServicePrincipal {
            principal: "worker-a".into(),
            tenant_id: tenant_id.into(),
            namespaces: namespaces
                .iter()
                .map(|namespace| namespace.to_string())
                .collect(),
            action_types: vec!["dispatch".into()],
            ..Default::default()
        }),
    }
}

fn get() -> GetServicePrincipalRequest {
    GetServicePrincipalRequest {
        principal: "worker-a".into(),
    }
}

#[tokio::test]
async fn admin_registers_reads_and_removes_with_profile_ceiling() {
    let service = service(false);
    service
        .db
        .runtime()
        .create_object(&crate::domain::Object {
            id: "profile-worker-a".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "worker-a".into(),
            namespace: "ns-a".into(),
            external_id: markings::principal_profile_external_id("worker-a"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "internal".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let profile_grant = Grant {
        id: "grant-profile".into(),
        object_id: "profile-worker-a".into(),
        principal: "root".into(),
        role: Role::Admin,
        created: 0,
        ..Default::default()
    };
    service.db.runtime().create_grant(&profile_grant).unwrap();

    let stored = service
        .put_service_principal(request(put("", &["ns-a"]), "root", None))
        .await
        .unwrap()
        .into_inner()
        .service_principal
        .unwrap();
    assert_eq!(stored.registered_by, "root");
    assert_eq!(stored.classification_ceiling, "internal");
    let read = service
        .get_service_principal(request(get(), "root", None))
        .await
        .unwrap()
        .into_inner()
        .service_principal
        .unwrap();
    assert_eq!(read, stored);
    let deleted = service
        .delete_service_principal(request(
            DeleteServicePrincipalRequest {
                principal: "worker-a".into(),
            },
            "root",
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(deleted.deleted);
}

#[tokio::test]
async fn only_an_administrator_may_register() {
    let service = service(false);
    let status = service
        .put_service_principal(request(put("", &["ns-a"]), "alice", None))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn registration_outside_the_caller_tenant_is_refused() {
    let service = service(true);
    // A tenant the caller does not hold, or no tenant at all.
    for tenant_id in ["tenant-b", ""] {
        let status = service
            .put_service_principal(request(
                put(tenant_id, &["ns-a"]),
                "tenant-admin",
                Some("tenant-a"),
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{tenant_id}");
    }
    // A namespace owned by another tenant.
    let status = service
        .put_service_principal(request(
            put("tenant-a", &["ns-a", "ns-b"]),
            "tenant-admin",
            Some("tenant-a"),
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    service
        .put_service_principal(request(
            put("tenant-a", &["ns-a"]),
            "tenant-admin",
            Some("tenant-a"),
        ))
        .await
        .unwrap();
    // Another tenant can neither read nor take over the registration.
    let status = service
        .get_service_principal(request(get(), "tenant-admin", Some("tenant-b")))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    let status = service
        .put_service_principal(request(
            put("tenant-b", &["ns-b"]),
            "tenant-admin",
            Some("tenant-b"),
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}
