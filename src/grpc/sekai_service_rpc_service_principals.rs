//! Service-principal scope registry RPCs (#1508, ADR 0099).
//!
//! Administrators register a worker's allowed Action types and tenant and
//! namespace allowlist. A caller registers only within its own tenant
//! authority, and each namespace must pass the usual tenant check.

use super::*;
use crate::sekai::service_principal::ServicePrincipalRegistration;

/// Registry admin: `root`/`local` or an admin grant on `service_principals`.
fn require_service_principal_admin(
    security: &SecurityChecker,
    principals: &[String],
) -> Result<(), Status> {
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("service_principals", &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied(
        "service principal admin required",
    ))
}

/// The only tenant the caller may register for: its authenticated tenant,
/// or empty when it has none. Never taken from the request.
fn caller_tenant(tenant_context: Option<&RequestEnterpriseContext>) -> &str {
    tenant_context
        .and_then(|context| context.tenant.as_ref())
        .map_or("", |tenant| tenant.tenant_id.as_str())
}

/// The caller's view of `principal`; another tenant's registration reads as absent.
fn visible_registration(
    service: &SekaiServiceImpl,
    principal: &str,
    tenant_id: &str,
) -> Result<Option<ServicePrincipalRegistration>, Status> {
    Ok(service
        .db
        .runtime()
        .get_service_principal(principal)
        .map_err(Status::internal)?
        .filter(|registration| registration.tenant_id == tenant_id))
}

/// The principal profile's marking ceiling; an ambiguous or invalid profile
/// is a precondition failure.
fn classification_ceiling(service: &SekaiServiceImpl, principal: &str) -> Result<String, Status> {
    Ok(service
        .db
        .principal_classification_ceiling(principal)
        .map_err(Status::failed_precondition)?
        .unwrap_or_default())
}

fn to_proto_service_principal(
    registration: ServicePrincipalRegistration,
    classification_ceiling: String,
) -> ServicePrincipal {
    ServicePrincipal {
        principal: registration.principal,
        tenant_id: registration.tenant_id,
        namespaces: registration.namespaces,
        action_types: registration.action_types,
        classification_ceiling,
        registered_by: registration.registered_by,
        created_at_ms: registration.created_at_ms,
        updated_at_ms: registration.updated_at_ms,
    }
}

pub(super) async fn put_service_principal(
    service: &SekaiServiceImpl,
    req: Request<PutServicePrincipalRequest>,
) -> Result<Response<PutServicePrincipalResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    require_service_principal_admin(&service.security, &principals)?;
    let input = req
        .into_inner()
        .service_principal
        .ok_or_else(|| Status::invalid_argument("service_principal required"))?;
    let tenant_id = caller_tenant(tenant_context.as_ref());
    if input.tenant_id != tenant_id {
        return Err(Status::permission_denied(
            "service principal tenant is outside the caller's tenant authority",
        ));
    }
    let now = now_millis();
    let registration = ServicePrincipalRegistration {
        principal: input.principal,
        tenant_id: input.tenant_id,
        namespaces: input.namespaces,
        action_types: input.action_types,
        registered_by: principals.first().cloned().unwrap_or_default(),
        created_at_ms: now,
        updated_at_ms: now,
    }
    .normalized()
    .map_err(Status::invalid_argument)?;
    // Resolve the profile first so a bad profile refuses before any write.
    let ceiling = classification_ceiling(service, &registration.principal)?;
    for namespace in &registration.namespaces {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            tenant_context.as_ref(),
            namespace,
            true,
        )?;
    }
    let stored = service
        .db
        .runtime()
        .put_service_principal(&registration)
        .map_err(Status::internal)?
        // Another tenant's registration of the same principal is not replaceable.
        .ok_or_else(|| {
            Status::permission_denied("service principal is registered under another tenant")
        })?;
    Ok(Response::new(PutServicePrincipalResponse {
        service_principal: Some(to_proto_service_principal(stored, ceiling)),
    }))
}

pub(super) async fn get_service_principal(
    service: &SekaiServiceImpl,
    req: Request<GetServicePrincipalRequest>,
) -> Result<Response<GetServicePrincipalResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    require_service_principal_admin(&service.security, &principals)?;
    let principal = req.into_inner().principal;
    let registration =
        visible_registration(service, &principal, caller_tenant(tenant_context.as_ref()))?
            .ok_or_else(|| Status::not_found("service principal not found"))?;
    let ceiling = classification_ceiling(service, &registration.principal)?;
    Ok(Response::new(GetServicePrincipalResponse {
        service_principal: Some(to_proto_service_principal(registration, ceiling)),
    }))
}

pub(super) async fn delete_service_principal(
    service: &SekaiServiceImpl,
    req: Request<DeleteServicePrincipalRequest>,
) -> Result<Response<DeleteServicePrincipalResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    require_service_principal_admin(&service.security, &principals)?;
    let principal = req.into_inner().principal;
    let deleted = service
        .db
        .runtime()
        .delete_service_principal(&principal, caller_tenant(tenant_context.as_ref()))
        .map_err(Status::internal)?;
    Ok(Response::new(DeleteServicePrincipalResponse { deleted }))
}
