pub mod chisei_service;
pub use sekai_admin_client::client;
mod provider_execution;
pub mod remote_sekai;
pub mod rpc_identity;
pub mod sekai_service;
mod visible_page;

pub mod pb {
    pub use sekai_proto::{chisei, sekai};
}

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::chisei::budget::BudgetTracker;
use crate::combined_stores::CombinedStoreLayout;
use crate::config::{Config, GrpcTcpMode};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::PrincipalCredential;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::obs::grpc_layer::MetricsLayer;
use crate::plane::ProcessPlane;
use crate::rpc_maturity::RpcMaturityLayer;
use crate::sekai::credentials::PrincipalCredentialStore;
use axum::response::IntoResponse;
use sekai_domain::gateway_keys::hash_gateway_key;
use std::convert::Infallible;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::server::NamedService;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Status, metadata::MetadataValue};
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;
use tower::Layer;

const AUTH_SOURCE_HEADER: &str = "x-sekai-auth-source";
const CREDENTIAL_ID_HEADER: &str = "x-sekai-credential-id";
const TENANT_CONTEXT_HEADER: &str = "x-sekai-tenant-id";
/// Caller metadata that the community authentication boundary accepts as
/// authority-bearing. Tenant hints are stripped and therefore absent here.
pub const COMMUNITY_ACCEPTED_AUTHORITY_METADATA_KEYS: &[&str] = &["authorization", "x-principal"];

pub(crate) fn write_freeze_status(err: crate::sekai::write_freeze::WriteFreezeError) -> Status {
    match err {
        crate::sekai::write_freeze::WriteFreezeError::Frozen(reason) => {
            Status::failed_precondition(reason)
        }
        crate::sekai::write_freeze::WriteFreezeError::Internal(error) => Status::internal(error),
    }
}

#[derive(Clone)]
pub struct TokenAuthInterceptor {
    store: Arc<PrincipalCredentialStore>,
    db: crate::db::store::SekaiStore,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    actor_rate_gate: crate::chisei::actor_limit::ActorRateGate,
}

impl TokenAuthInterceptor {
    pub fn new(store: Arc<PrincipalCredentialStore>, db: crate::db::store::SekaiStore) -> Self {
        Self {
            store,
            db,
            assertion_authority: None,
            actor_rate_gate: crate::chisei::actor_limit::ActorRateGate::disabled(),
        }
    }

    pub fn with_assertion_authority(
        mut self,
        assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        self.assertion_authority = assertion_authority;
        self
    }

    pub fn with_actor_rate_gate(
        mut self,
        actor_rate_gate: crate::chisei::actor_limit::ActorRateGate,
    ) -> Self {
        self.actor_rate_gate = actor_rate_gate;
        self
    }

    pub fn from_runtime(
        store: Arc<PrincipalCredentialStore>,
        db: crate::db::store::SekaiStore,
        assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        Self::new(store, db).with_assertion_authority(assertion_authority)
    }

    pub fn from_config(
        store: Arc<PrincipalCredentialStore>,
        db: crate::db::store::SekaiStore,
        config: &Config,
    ) -> Result<Self, String> {
        Ok(
            Self::from_runtime(store, db, config.assertion_authority()?.map(Arc::new))
                .with_actor_rate_gate(crate::chisei::actor_limit::ActorRateGate::from_config(
                    config,
                )),
        )
    }

    /// Resolve a raw bearer token to an active principal credential.
    ///
    /// Rechecks durable state on every call so rotation/revocation cannot be
    /// bypassed by a stale process-local cache. Used by gRPC interceptors and
    /// the authenticated operator console.
    pub fn resolve_credential(&self, token: &str) -> Option<PrincipalCredential> {
        self.store.maybe_reload(self.db.runtime());
        let token_hash = hash_gateway_key(token);

        // Recheck durable state for every authentication. The cache accelerates
        // startup discovery but never extends a rotated or revoked credential.
        match self.db.runtime().get_principal_credential(&token_hash) {
            Ok(Some(credential)) if credential.status == "active" => {
                self.store.load_credential(&credential);
                Some(credential)
            }
            Ok(Some(_)) | Ok(None) => None,
            Err(_) => None,
        }
    }

    fn parse_bearer_token(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
        let raw = metadata.get("authorization")?.to_str().ok()?.trim();
        if raw.is_empty() {
            return None;
        }
        Some(
            raw.strip_prefix("Bearer ")
                .unwrap_or(raw)
                .trim()
                .to_string(),
        )
    }
}

/// Record a refused request at the authentication boundary.
///
/// The reason stays `Unauthorized` for every path here. Distinguishing a
/// missing header from an invalid token would let an observer of the metrics
/// endpoint probe which tokens exist, which is the kind of inference the
/// bounded-label rule in Issue #98 exists to prevent.
fn reject_unauthorized() {
    crate::obs::signals::record_rejected_work(
        crate::obs::labels::Subsystem::Grpc,
        crate::obs::labels::RejectionReason::Unauthorized,
    );
}

fn assertion_reject_status(reject: crate::identity_assertion::AssertionReject) -> Status {
    match reject {
        crate::identity_assertion::AssertionReject::CallerTenantHeader => {
            Status::failed_precondition("caller-selected tenant header")
        }
        crate::identity_assertion::AssertionReject::Issuer => {
            Status::unauthenticated("invalid assertion issuer")
        }
        crate::identity_assertion::AssertionReject::Audience => {
            Status::unauthenticated("invalid assertion audience")
        }
        crate::identity_assertion::AssertionReject::Signature => {
            Status::unauthenticated("invalid assertion signature")
        }
        crate::identity_assertion::AssertionReject::Expiry => {
            Status::unauthenticated("assertion expired")
        }
        crate::identity_assertion::AssertionReject::Replay => {
            Status::unauthenticated("assertion replay")
        }
        crate::identity_assertion::AssertionReject::ScopeEscalation => {
            Status::permission_denied("assertion scope escalation")
        }
        crate::identity_assertion::AssertionReject::Device => {
            Status::unauthenticated("invalid assertion device claim")
        }
    }
}

/// Request metadata carrying a device proof (ADR 0126).
pub(crate) const DEVICE_PROOF_HEADER: &str = "x-sekai-device-proof";

/// RPCs (`Service/Method`) that check device proofs with
/// [`require_device_proof`]. Every other RPC refuses a device-bound
/// assertion outright, so a copied one never authenticates where no proof
/// is checked. Each entry calls the hook over its own request.
const DEVICE_PROOF_RPCS: &[&str] = &[
    // Offline governed Actions (#1580).
    "sekai.SekaiService/SubmitActionInstance",
    // Offline sync (#1634).
    "sekai.SekaiService/PutSyncScope",
    "sekai.SekaiService/ReadSyncSnapshot",
    "sekai.SekaiService/ReadSyncDeltas",
];

/// RPCs a device the issuer revoked may still call: the sync reads, which
/// answer it only with a wipe instruction (#1634).
const DEVICE_WIPE_RPCS: &[&str] = &[
    "sekai.SekaiService/ReadSyncSnapshot",
    "sekai.SekaiService/ReadSyncDeltas",
];

/// Whether `rpc` (`Service/Method`) checks device proofs.
fn checks_device_proof(rpc: &str) -> bool {
    DEVICE_PROOF_RPCS.contains(&rpc)
}

/// The device-proof hook for a protected RPC: a request authenticated by a
/// device-bound assertion must carry the device's proof over this request
/// (`method` and the encoded message) in [`DEVICE_PROOF_HEADER`]. With
/// `device_required`, an unbound context is refused too.
pub(crate) fn require_device_proof<T: prost::Message>(
    request: &tonic::Request<T>,
    method: &str,
    device_required: bool,
) -> Result<(), Status> {
    // No authenticated context is an unbound one: it passes unless the RPC
    // requires a device.
    let Some(context) = request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    else {
        return if device_required {
            reject_unauthorized();
            Err(Status::unauthenticated(
                "device proof refused: device_unbound",
            ))
        } else {
            Ok(())
        };
    };
    let digest =
        crate::identity_assertion::request_digest(method, &request.get_ref().encode_to_vec());
    let proof = request
        .metadata()
        .get(DEVICE_PROOF_HEADER)
        .map(|value| value.to_str().unwrap_or_default());
    crate::identity_assertion::verify_device_proof(context, &digest, proof, device_required)
        .map_err(|reject| {
            reject_unauthorized();
            Status::unauthenticated(format!("device proof refused: {}", reject.as_str()))
        })
}

/// Catalog metadata RPCs a discover-only space role may call.
fn is_discover_rpc(method: &str) -> bool {
    let name = method.rsplit('/').next().unwrap_or(method);
    matches!(
        name,
        "ListSchemaTypes"
            | "ListDatasets"
            | "ListDatasetVersions"
            | "ListDatasetHealthChecks"
            | "DescribeObjectAction"
            | "DiscoverCapabilities"
            | "Search"
            | "GetCatalogEntryLineage"
            | "ListCatalogCriticalityOutbox"
    )
}

fn rpc_namespace_action(method: &str) -> crate::enterprise::NamespaceAction {
    let name = method.rsplit('/').next().unwrap_or(method);
    if crate::store_relocate::is_mutating_rpc(name)
        && !matches!(
            name,
            "FindByExternalId"
                | "FindByProperty"
                | "Traverse"
                | "QueryRows"
                | "ResolveInvariantSet"
                | "RetrieveContext"
                | "DiscoverCapabilities"
                | "ExplainDerivation"
                | "CompareDefinitionRevisions"
                | "QueryObjectPolicyAudit"
                // Offline sync (#1836) needs namespace read: a scope is the
                // caller's own definition, not namespace data.
                | "PutSyncScope"
                | "ReadSyncSnapshot"
                | "ReadSyncDeltas"
        )
    {
        crate::enterprise::NamespaceAction::Write
    } else if is_discover_rpc(name) {
        crate::enterprise::NamespaceAction::Discover
    } else {
        crate::enterprise::NamespaceAction::Read
    }
}

/// [`finish_authenticated`], auditing a guest rejected before any namespace
/// decision. The denial stands even if the audit write fails.
fn finish_authenticated_audited(
    db: &crate::db::runtime_db::RuntimeDb,
    req: Request<()>,
    authenticated_context: crate::enterprise::AuthenticatedContext,
    enterprise_scoped: bool,
    actor_rate_gate: &crate::chisei::actor_limit::ActorRateGate,
) -> Result<Request<()>, Status> {
    let guest = authenticated_context
        .guest_home_tenant()
        .is_some()
        .then(|| authenticated_context.clone());
    let rpc = rpc_identity::request_rpc_method(&req)
        .map(|(service, method)| format!("{service}/{method}"))
        .unwrap_or_default();
    if let Some(chain) = authenticated_context.actor_chain() {
        actor_rate_gate.admit(&chain).map_err(actor_rate_status)?;
    }
    let result = finish_authenticated(req, authenticated_context, enterprise_scoped);
    if let (Some(context), Err(_)) = (&guest, &result) {
        let _ = record_guest_access(db, context, &rpc, "rpc", false);
    }
    result
}

fn actor_rate_status(error: crate::chisei::actor_limit::ActorRateError) -> Status {
    match error {
        crate::chisei::actor_limit::ActorRateError::Exhausted { retry_after_ms, .. } => {
            let mut status = Status::resource_exhausted(error.to_string());
            if let Ok(value) = retry_after_ms.to_string().parse() {
                status.metadata_mut().insert("retry-after-ms", value);
            }
            status
        }
        crate::chisei::actor_limit::ActorRateError::Unavailable => {
            Status::unavailable(error.to_string())
        }
    }
}

/// One `tenant.guest_access` audit record for a guest decision (#1432), with
/// the principal, home and acting tenant, space, target, and operation.
pub(crate) fn record_guest_access(
    db: &crate::db::runtime_db::RuntimeDb,
    context: &crate::enterprise::AuthenticatedContext,
    target_id: &str,
    operation: &str,
    allowed: bool,
) -> Result<(), String> {
    let tenant_id = |tenant: Option<&str>| tenant.unwrap_or_default().to_string();
    db.record_decision(&crate::sekai::audit::Decision {
        id: format!("guest-access:{}", uuid::Uuid::new_v4().as_simple()),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: context.principal.subject.clone(),
        action: "tenant.guest_access".into(),
        reason: "cross-tenant access".into(),
        target_id: target_id.into(),
        outcome: if allowed { "allowed" } else { "denied" }.into(),
        evidence: std::collections::HashMap::from([
            ("home_tenant".into(), tenant_id(context.guest_home_tenant())),
            (
                "acting_tenant".into(),
                tenant_id(
                    context
                        .tenant
                        .as_ref()
                        .map(|tenant| tenant.tenant_id.as_str()),
                ),
            ),
            ("space".into(), context.space.clone().unwrap_or_default()),
            ("operation".into(), operation.into()),
        ]),
    })
}

/// One `tenant.shared_space_access` audit record for a cross-tenant space
/// decision (#1434), with the principal, home tenant, resource tenant, space,
/// target, and operation.
pub(crate) fn record_shared_space_access(
    db: &crate::db::runtime_db::RuntimeDb,
    context: &crate::enterprise::AuthenticatedContext,
    resource_tenant: &str,
    target_id: &str,
    operation: &str,
    allowed: bool,
) -> Result<(), String> {
    let tenant_id = |tenant: Option<&str>| tenant.unwrap_or_default().to_string();
    db.record_decision(&crate::sekai::audit::Decision {
        id: format!("shared-space-access:{}", uuid::Uuid::new_v4().as_simple()),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: context.principal.subject.clone(),
        action: "tenant.shared_space_access".into(),
        reason: "cross-tenant shared space".into(),
        target_id: target_id.into(),
        outcome: if allowed { "allowed" } else { "denied" }.into(),
        evidence: std::collections::HashMap::from([
            ("home_tenant".into(), tenant_id(context.home_tenant_id())),
            ("resource_tenant".into(), resource_tenant.into()),
            ("space".into(), context.space.clone().unwrap_or_default()),
            ("operation".into(), operation.into()),
        ]),
    })
}

/// One `tenant.discovery` audit record for a cross-tenant find (#1435).
pub(crate) fn record_discovery(
    db: &crate::db::runtime_db::RuntimeDb,
    context: &crate::enterprise::AuthenticatedContext,
    owner_tenant: &str,
    target_id: &str,
    operation: &str,
    allowed: bool,
) -> Result<(), String> {
    let tenant_id = |tenant: Option<&str>| tenant.unwrap_or_default().to_string();
    db.record_decision(&crate::sekai::audit::Decision {
        id: format!("discovery:{}", uuid::Uuid::new_v4().as_simple()),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: context.principal.subject.clone(),
        action: "tenant.discovery".into(),
        reason: "cross-tenant discovery".into(),
        target_id: target_id.into(),
        outcome: if allowed { "allowed" } else { "denied" }.into(),
        evidence: std::collections::HashMap::from([
            ("home_tenant".into(), tenant_id(context.guest_home_tenant())),
            ("owner_tenant".into(), owner_tenant.into()),
            ("space".into(), context.space.clone().unwrap_or_default()),
            ("operation".into(), operation.into()),
        ]),
    })
}

fn finish_authenticated(
    mut req: Request<()>,
    authenticated_context: crate::enterprise::AuthenticatedContext,
    enterprise_scoped: bool,
) -> Result<Request<()>, Status> {
    if enterprise_scoped && authenticated_context.tenant.is_none() {
        reject_unauthorized();
        return Err(Status::unauthenticated(
            "enterprise tenant context required",
        ));
    }
    authenticated_context
        .authorize_space(crate::enterprise::NamespaceAction::Discover)
        .map_err(|_| Status::unauthenticated("invalid space authority"))?;
    // Guests reach only RPCs whose handlers make a per-namespace guest
    // decision (#1432); everything else, approval included, stays denied.
    if authenticated_context.guest_home_tenant().is_some()
        && rpc_identity::request_rpc_method(&req)
            .is_none_or(|(service, method)| !guest_namespace_rpc(service, method))
    {
        return Err(Status::permission_denied("enterprise authorization denied"));
    }
    if let Some((_, method)) = rpc_identity::request_rpc_method(&req) {
        // Deciding a parked Action or a whole plan is approval, not write.
        if matches!(method, "DecideActionInstance" | "DecidePlanReview") {
            authenticated_context
                .authorize_space_approval()
                .map_err(|_| Status::permission_denied("space approval denied"))?;
            authenticated_context
                .authorize_credential_scope(crate::enterprise::NamespaceAction::Read)
                .map_err(|_| Status::permission_denied("space read denied"))?;
        } else {
            let action = rpc_namespace_action(method);
            if action != crate::enterprise::NamespaceAction::Discover {
                authenticated_context.authorize_space(action).map_err(|_| {
                    if action == crate::enterprise::NamespaceAction::Write {
                        Status::permission_denied("space write denied")
                    } else {
                        Status::permission_denied("space read denied")
                    }
                })?;
            }
            authenticated_context
                .authorize_credential_scope(action)
                .map_err(|_| Status::permission_denied("credential scope denied"))?;
        }
    } else if authenticated_context.space.is_some() {
        return Err(Status::permission_denied(
            "space-scoped RPC identity required",
        ));
    }
    let principal = authenticated_context.principal.subject.clone();
    let credential_id = authenticated_context.principal.credential_id.clone();
    if !valid_single_principal(&principal) {
        reject_unauthorized();
        return Err(Status::unauthenticated("invalid principal identity"));
    }

    while req.metadata_mut().remove("x-principal").is_some() {}
    while req.metadata_mut().remove(AUTH_SOURCE_HEADER).is_some() {}
    while req.metadata_mut().remove(CREDENTIAL_ID_HEADER).is_some() {}
    while req.metadata_mut().remove(TENANT_CONTEXT_HEADER).is_some() {}
    req.metadata_mut().insert(
        "x-principal",
        MetadataValue::from_str(&principal).map_err(|_| {
            reject_unauthorized();
            Status::unauthenticated("invalid principal metadata value")
        })?,
    );
    req.metadata_mut().insert(
        AUTH_SOURCE_HEADER,
        MetadataValue::from_static(if enterprise_scoped {
            "enterprise"
        } else {
            "token"
        }),
    );
    req.metadata_mut().insert(
        CREDENTIAL_ID_HEADER,
        MetadataValue::from_str(&credential_id)
            .map_err(|_| Status::unauthenticated("invalid credential identity"))?,
    );
    if enterprise_scoped {
        if let Some(tenant) = authenticated_context.tenant.as_ref() {
            req.metadata_mut().insert(
                TENANT_CONTEXT_HEADER,
                MetadataValue::from_str(&tenant.tenant_id)
                    .map_err(|_| Status::unauthenticated("invalid tenant identity"))?,
            );
        }
        let method = rpc_identity::request_rpc_method(&req);
        if method.is_none_or(|(service, method)| !enterprise_namespace_rpc(service, method)) {
            return Err(Status::permission_denied(
                "RPC is not available to enterprise-scoped credentials",
            ));
        }
    }
    req.extensions_mut().insert(authenticated_context);
    Ok(req)
}

impl TokenAuthInterceptor {
    /// Admit a runtime token (#1507) for the follow-up calls on its claim only.
    /// Handlers then check the claim binding and the namespace's tenant.
    fn authenticate_runtime_token(
        &self,
        req: Request<()>,
        token: &str,
    ) -> Result<Request<()>, Status> {
        let refuse = |status: Status| {
            reject_unauthorized();
            status
        };
        let Some(authority) = &self.assertion_authority else {
            return Err(refuse(Status::unauthenticated("invalid token")));
        };
        if req.metadata().get(TENANT_CONTEXT_HEADER).is_some() {
            return Err(refuse(assertion_reject_status(
                crate::identity_assertion::AssertionReject::CallerTenantHeader,
            )));
        }
        let claims = crate::runtime_token::RuntimeTokenClaims::verify(
            authority,
            token,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|reject| refuse(assertion_reject_status(reject)))?;
        let claimed_work_rpc =
            rpc_identity::request_rpc_method(&req).is_some_and(|(service, method)| {
                service == "sekai.SekaiService"
                    && crate::runtime_token::RUNTIME_TOKEN_METHODS.contains(&method)
            });
        if !claimed_work_rpc {
            return Err(Status::permission_denied(
                "runtime token admits only calls for its claimed work",
            ));
        }
        let mut req = finish_authenticated_audited(
            self.db.runtime(),
            req,
            claims.authenticated_context(),
            true,
            &self.actor_rate_gate,
        )?;
        req.extensions_mut().insert(claims);
        Ok(req)
    }

    /// Admit a service-principal token (#1510) as the registered machine
    /// identity. Scope enforcement on Action RPCs is #1511.
    fn authenticate_service_token(
        &self,
        req: Request<()>,
        token: &str,
    ) -> Result<Request<()>, Status> {
        let refuse = |status: Status| {
            reject_unauthorized();
            status
        };
        let Some(authority) = &self.assertion_authority else {
            return Err(refuse(Status::unauthenticated("invalid token")));
        };
        if req.metadata().get(TENANT_CONTEXT_HEADER).is_some() {
            return Err(refuse(assertion_reject_status(
                crate::identity_assertion::AssertionReject::CallerTenantHeader,
            )));
        }
        let claims = crate::service_token::ServiceTokenClaims::verify(
            authority,
            token,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|reject| refuse(assertion_reject_status(reject)))?;
        let registration = self
            .db
            .runtime()
            .get_service_principal(&claims.subject)
            .map_err(|_| refuse(Status::unauthenticated("invalid token")))?
            .filter(|registration| registration.tenant_id == claims.tenant_id);
        if registration.is_none() {
            return Err(refuse(Status::unauthenticated("invalid token")));
        }
        let context = claims.authenticated_context();
        if context.credential_kind != crate::enterprise::CredentialKind::Machine {
            return Err(refuse(Status::unauthenticated("invalid token")));
        }
        finish_authenticated_audited(self.db.runtime(), req, context, true, &self.actor_rate_gate)
    }
}

impl tonic::service::Interceptor for TokenAuthInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let issue_service_token =
            rpc_identity::request_rpc_method(&req).is_some_and(|(service, method)| {
                service == "sekai.SekaiService" && method == "IssueServicePrincipalToken"
            });
        if issue_service_token {
            // Client credentials in the request body are the authentication.
            return Ok(req);
        }
        let Some(token) = Self::parse_bearer_token(req.metadata()) else {
            reject_unauthorized();
            return Err(Status::unauthenticated("missing authorization"));
        };
        if crate::runtime_token::is_runtime_token(&token) {
            return self.authenticate_runtime_token(req, &token);
        }
        if crate::service_token::is_service_token(&token) {
            return self.authenticate_service_token(req, &token);
        }
        if crate::identity_assertion::is_assertion_token(&token) {
            let tenant_header = req
                .metadata()
                .get(TENANT_CONTEXT_HEADER)
                .map(|value| value.to_str().unwrap_or("invalid"));
            match &self.assertion_authority {
                Some(authority) => {
                    let now = chrono::Utc::now().timestamp();
                    let authenticated_context = authority
                        .verify(&token, now, tenant_header)
                        .map_err(|reject| {
                            reject_unauthorized();
                            assertion_reject_status(reject)
                        })?;
                    if authenticated_context.device.is_some() {
                        let rpc = rpc_identity::request_rpc_method(&req)
                            .map(|(service, method)| format!("{service}/{method}"))
                            .unwrap_or_default();
                        if !checks_device_proof(&rpc) {
                            reject_unauthorized();
                            return Err(Status::unauthenticated(
                                "device-bound assertions are accepted only by RPCs that check device proofs",
                            ));
                        }
                        if authenticated_context
                            .device
                            .as_ref()
                            .is_some_and(|device| device.wipe)
                            && !DEVICE_WIPE_RPCS.contains(&rpc.as_str())
                        {
                            reject_unauthorized();
                            return Err(Status::permission_denied(
                                "the device was revoked and must wipe",
                            ));
                        }
                    }
                    let enterprise_scoped = self.db.runtime().enterprise_extension().is_some()
                        || authenticated_context.tenant.is_some();
                    return finish_authenticated_audited(
                        self.db.runtime(),
                        req,
                        authenticated_context,
                        enterprise_scoped,
                        &self.actor_rate_gate,
                    );
                }
                None if tenant_header.is_some() => {
                    reject_unauthorized();
                    return Err(Status::failed_precondition("caller-selected tenant header"));
                }
                None => {}
            }
        }

        let enterprise_result = self
            .db
            .runtime()
            .enterprise_extension()
            .map(|extension| extension.authenticate_context(&token));
        let (authenticated_context, enterprise_scoped) = match enterprise_result {
            Some(Ok(context)) => {
                let extension_version = self
                    .db
                    .runtime()
                    .enterprise_extension()
                    .expect("enterprise authentication requires an installed extension")
                    .contract_version();
                if extension_version != crate::enterprise::IDENTITY_EXTENSION_VERSION
                    || context.contract_version != extension_version
                {
                    reject_unauthorized();
                    return Err(Status::failed_precondition(
                        "unsupported enterprise identity contract version",
                    ));
                }
                if context.expires_at <= chrono::Utc::now().timestamp() {
                    reject_unauthorized();
                    return Err(Status::unauthenticated(
                        "enterprise authenticated context expired",
                    ));
                }
                (context, true)
            }
            None => {
                let credential = self.resolve_credential(&token).ok_or_else(|| {
                    reject_unauthorized();
                    Status::unauthenticated("invalid token")
                })?;
                let principal = crate::enterprise::AuthenticatedPrincipal {
                    subject: credential.principal,
                    credential_id: credential.id,
                };
                (
                    crate::enterprise::AuthenticatedContext::machine(principal),
                    false,
                )
            }
            Some(Err(crate::enterprise::ExtensionError::Unavailable(message))) => {
                return Err(Status::unavailable(message));
            }
            Some(Err(_)) => {
                reject_unauthorized();
                return Err(Status::unauthenticated("invalid token"));
            }
        };
        finish_authenticated_audited(
            self.db.runtime(),
            req,
            authenticated_context,
            enterprise_scoped,
            &self.actor_rate_gate,
        )
    }
}

fn valid_single_principal(principal: &str) -> bool {
    !principal.is_empty() && principal.trim() == principal && !principal.contains(',')
}

fn guest_namespace_rpc(service: &str, method: &str) -> bool {
    service == "sekai.SekaiService"
        && matches!(
            method,
            "GetObject"
                | "ListObjects"
                | "CreateObject"
                | "UpdateObject"
                | "DeleteObject"
                | "DiscoverCapabilities"
        )
}

fn enterprise_namespace_rpc(service: &str, method: &str) -> bool {
    let chisei = matches!(
        method,
        "PlanExecution"
            | "ExecutePlanStream"
            | "PlanContentExecution"
            | "ExecuteContentPlanStream"
            | "GetOperationReceipt"
            | "GetQualityTrend"
    );
    let expected = if chisei {
        "chisei.ChiseiService"
    } else {
        "sekai.SekaiService"
    };
    service == expected && enterprise_namespace_method(method)
}

fn enterprise_namespace_method(method: &str) -> bool {
    matches!(
        method,
        "AcquireLease"
            | "GetLease"
            | "RefreshLease"
            | "ReleaseLease"
            | "TakeoverExpiredLease"
            | "CreateObject"
            | "GetObject"
            | "UpdateObject"
            | "DeleteObject"
            | "ListObjects"
            | "FindByExternalId"
            | "FindByProperty"
            | "CreateLink"
            | "DeleteLink"
            | "GetLinks"
            | "GetLinkedObjects"
            | "Traverse"
            | "ExpandNeighborhood"
            | "FindPaths"
            | "ListObjectChanges"
            | "ExplainValue"
            | "GetPublishedDefinitionRevision"
            | "ListPublishedDefinitionRevisions"
            | "GetDefinitionMember"
            | "GetOntologyLintReport"
            // Governed export (#1627): the handlers check the export grant and
            // namespace administration per namespace.
            | "GrantNamespaceExport"
            | "RevokeNamespaceExport"
            // Federated aggregate allowances (#1921): namespace admin per call.
            | "PublishFederatedAggregateAllowance"
            | "WithdrawFederatedAggregateAllowance"
            | "GetFederatedAggregateAllowance"
            | "ExportObjectSet"
            | "ExportDatasetVersion"
            | "GetExportReceipt"
            | "PutExportFingerprintPolicy"
            | "GetExportFingerprintPolicy"
            | "TraceExport"
            | "PutExportDefinition"
            | "GetExportDefinition"
            | "DeleteExportDefinition"
            | "RunExportDefinition"
            | "ListDeliverableExportArtifacts"
            | "FetchExportArtifact"
            | "AcknowledgeExportDelivery"
            | "GetOntologyHealth"
            | "RecordOntologyHealthSnapshot"
            | "ListOntologyHealthTrend"
            | "GetDefinitionCertificationGate"
            | "PutDefinitionCertification"
            | "DryRunAgent"
            | "RunAgentShadow"
            | "GetAgentShadowReport"
            | "GetCatalogEntryLineage"
            | "ListCatalogCriticalityOutbox"
            | "GetDefinitionBranch"
            | "CreateDefinitionBranch"
            | "ApplyDefinitionBranchEdit"
            | "GetDefinitionProposal"
            | "CreateDefinitionProposal"
            | "ApproveDefinitionProposal"
            | "MergeDefinitionProposal"
            // Rollback and package import open proposals under the same
            // namespace and member grants; export reads like a member read.
            | "ProposeDefinitionRollback"
            | "ExportDefinitionPackage"
            | "ImportDefinitionPackage"
            | "ImportDefinitionTree"
            | "GetGovernedFactVersion"
            | "ResolveInvariantSet"
            | "SubmitActionInstance"
            | "DecideActionInstance"
            // Offline sync (#1836): each call enforces the caller's tenant on
            // the scope's namespace, and a device-bound context still needs
            // its device's proof (ADR 0126).
            | "PutSyncScope"
            | "ReadSyncSnapshot"
            | "ReadSyncDeltas"
            // Plans (#1675) and their review (#1678): handlers enforce the
            // tenant context per namespace.
            | "CreatePlanIntent"
            | "ProposePlan"
            | "SimulatePlan"
            | "GetPlan"
            | "SubmitPlanReview"
            | "DecidePlanReview"
            | "ExecuteActionPlan"
            | "GetActionInstance"
            | "ListActionInstances"
            | "GetActionEffect"
            | "ListActionEffects"
            | "ListClaimableActionWork"
            | "ClaimActionWork"
            | "HeartbeatActionClaim"
            | "AckActionWork"
            | "ReportActionClaimEvent"
            | "PutServicePrincipal"
            | "GetServicePrincipal"
            | "DeleteServicePrincipal"
            | "IssueServicePrincipalToken"
            | "PlanExecution"
            | "ExecutePlanStream"
            | "PlanContentExecution"
            | "ExecuteContentPlanStream"
            // Admitted for tenant assertions (#1770): the trend authorizes the
            // request's namespace, and a receipt outside the tenant's
            // namespaces reads as not found.
            | "GetOperationReceipt"
            | "GetQualityTrend"
            | "ListSchemaTypes"
            | "ListGovernedTransforms"
            | "ListGovernedTransformRuns"
            | "GetGovernedTransformRun"
            | "PreviewGovernedTransform"
            | "PutGovernedTransform"
            | "ListDatasets"
            | "ListDatasetVersions"
            | "GetDatasetVersion"
            | "RollbackDataset"
            | "CreateDatasetBranch"
            | "ListDatasetBranches"
            | "DeleteDatasetBranch"
            | "CompareDatasetBranch"
            | "ProposeDatasetBranchMerge"
            | "MergeDatasetBranch"
            | "PutDatasetHealthCheck"
            | "ListDatasetHealthChecks"
            | "ListDatasetHealthResults"
            | "RunDatasetHealthChecks"
            | "ListDatasetAlerts"
            | "ListConsumerViolationNotifications"
            | "AcknowledgeConsumerViolationNotification"
            | "DescribeObjectAction"
            // Admitted for tenant assertions (#1777); each handler authorizes
            // the request's namespace against the assertion's tenant.
            | "PreviewObjectAction"
            | "ListGovernedActionTypes"
            | "ExplainDerivation"
            | "EvaluateObjectSet"
            | "GetSourceSyncState"
            | "ReadObjectChangeSubscription"
            | "CompareDefinitionRevisions"
            | "QueryObjectPolicyAudit"
            | "DiscoverCapabilities"
            | "Search"
            | "GetSearchIndexStatus"
    )
}

#[derive(Clone)]
pub struct LocalInterceptor {
    overwrite_principal: bool,
}

impl LocalInterceptor {
    pub fn new(overwrite_principal: bool) -> Self {
        Self {
            overwrite_principal,
        }
    }
}

impl Default for LocalInterceptor {
    fn default() -> Self {
        Self::new(true)
    }
}

#[derive(Clone)]
struct LocalOrTokenAuthInterceptor {
    local: LocalInterceptor,
    token: TokenAuthInterceptor,
}

impl tonic::service::Interceptor for LocalOrTokenAuthInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        if req.metadata().get("authorization").is_some()
            || self.token.db.runtime().enterprise_extension().is_some()
        {
            self.token.call(req)
        } else {
            self.local.call(req)
        }
    }
}

#[derive(Clone)]
struct PlaneAwareInterceptor<I> {
    plane: ProcessPlane,
    served: ProcessPlane,
    inner: I,
}

fn with_plane<I>(plane: ProcessPlane, served: ProcessPlane, inner: I) -> PlaneAwareInterceptor<I> {
    PlaneAwareInterceptor {
        plane,
        served,
        inner,
    }
}

#[derive(Clone)]
struct RestoreFenceInterceptor<I> {
    stores: Arc<CombinedStoreLayout>,
    inner: I,
}

fn with_restore_fence<I>(stores: Arc<CombinedStoreLayout>, inner: I) -> RestoreFenceInterceptor<I> {
    RestoreFenceInterceptor { stores, inner }
}

impl<I: tonic::service::Interceptor> tonic::service::Interceptor for PlaneAwareInterceptor<I> {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let allowed = match self.served {
            ProcessPlane::Sekai => self.plane.serves_sekai(),
            ProcessPlane::Chisei => self.plane.serves_chisei(),
            ProcessPlane::Combined => true,
        };
        if !allowed {
            return Err(Status::failed_precondition(
                crate::plane::wrong_plane_message(self.plane),
            ));
        }
        self.inner.call(req)
    }
}

impl<I: tonic::service::Interceptor> tonic::service::Interceptor for RestoreFenceInterceptor<I> {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        if request_is_mutating_rpc(&req) {
            crate::db::off_runtime(|| {
                crate::store_relocate::refuse_mutating_if_generation_mismatch(&self.stores)
            })
            .map_err(Status::failed_precondition)?;
        }
        self.inner.call(req)
    }
}

fn request_is_mutating_rpc<T>(req: &Request<T>) -> bool {
    rpc_identity::request_rpc_method(req)
        .map(|(_, method)| crate::store_relocate::is_mutating_rpc(method))
        .unwrap_or(false)
}

#[cfg(test)]
fn local_or_token_interceptor(
    credential_store: Arc<PrincipalCredentialStore>,
    db: Arc<RuntimeDb>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
) -> LocalOrTokenAuthInterceptor {
    local_or_token_interceptor_with_rate_gate(
        credential_store,
        db,
        assertion_authority,
        crate::chisei::actor_limit::ActorRateGate::disabled(),
    )
}

fn local_or_token_interceptor_with_rate_gate(
    credential_store: Arc<PrincipalCredentialStore>,
    db: Arc<RuntimeDb>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    actor_rate_gate: crate::chisei::actor_limit::ActorRateGate,
) -> LocalOrTokenAuthInterceptor {
    LocalOrTokenAuthInterceptor {
        local: LocalInterceptor::new(true),
        token: TokenAuthInterceptor::from_runtime(
            credential_store,
            crate::db::store::SekaiStore::from_shared_runtime(db),
            assertion_authority,
        )
        .with_actor_rate_gate(actor_rate_gate),
    }
}

impl tonic::service::Interceptor for LocalInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        while req.metadata_mut().remove(AUTH_SOURCE_HEADER).is_some() {}
        while req.metadata_mut().remove(CREDENTIAL_ID_HEADER).is_some() {}
        while req.metadata_mut().remove(TENANT_CONTEXT_HEADER).is_some() {}
        req.metadata_mut()
            .insert(AUTH_SOURCE_HEADER, MetadataValue::from_static("local"));
        if self.overwrite_principal {
            while req.metadata_mut().remove("x-principal").is_some() {}
            req.metadata_mut()
                .insert("x-principal", MetadataValue::from_static("local"));
            return Ok(req);
        }

        if req.metadata().get("x-principal").is_none() {
            req.metadata_mut()
                .insert("x-principal", MetadataValue::from_static("local"));
        }
        Ok(req)
    }
}

pub fn tls_policy(bind_addr: &str, config: &Config) -> Result<Option<(String, String)>, String> {
    let cert = config
        .tls_cert
        .clone()
        .filter(|value| !value.trim().is_empty());
    let key = config
        .tls_key
        .clone()
        .filter(|value| !value.trim().is_empty());

    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (Some(_), None) | (None, Some(_)) => {
            Err("both SEKAI_TLS_CERT and SEKAI_TLS_KEY are required for TLS".to_string())
        }
        (None, None) => {
            if bind_addr == "0.0.0.0" && !config.allow_plaintext {
                Err("0.0.0.0 requires TLS certificates; set SEKAI_TLS_CERT, SEKAI_TLS_KEY, or SEKAI_ALLOW_PLAINTEXT=1".to_string())
            } else {
                Ok(None)
            }
        }
    }
}

pub fn run(
    config: Config,
    stores: Arc<CombinedStoreLayout>,
    active_credentials: Vec<PrincipalCredential>,
    tcp_mode: GrpcTcpMode,
) -> Result<
    impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
    Box<dyn std::error::Error>,
> {
    run_for_plane(
        config,
        stores,
        active_credentials,
        tcp_mode,
        ProcessPlane::Combined,
    )
}

pub fn run_for_plane(
    config: Config,
    stores: Arc<CombinedStoreLayout>,
    active_credentials: Vec<PrincipalCredential>,
    tcp_mode: GrpcTcpMode,
    plane: ProcessPlane,
) -> Result<
    impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
    Box<dyn std::error::Error>,
> {
    // This setup deliberately executes when `run` is called, before the
    // returned future is polled. The PostgreSQL backend uses synchronous
    // clients, so service construction must not acquire or release them from
    // inside Tokio.
    let (
        db,
        chisei_db,
        provider_registry_state_path,
        credential_store,
        assertion_authority,
        (sekai_svc, chisei_svc),
    ) = (|| -> Result<_, std::io::Error> {
        stores
            .validate_required_surfaces()
            .map_err(std::io::Error::other)?;
        let db = match plane {
            ProcessPlane::Chisei => stores.chisei_runtime(),
            ProcessPlane::Combined | ProcessPlane::Sekai => stores.sekai_runtime(),
        };
        let chisei_db = stores.chisei_runtime();
        let registry_anchor = stores
            .registry_anchor_path()
            .unwrap_or(config.db_path.as_str());
        let provider_registry_state_path =
            crate::provider_profile::provider_registry_state_path(registry_anchor);
        let credential_store = Arc::new(PrincipalCredentialStore::new());
        credential_store.load(&active_credentials);

        if let Some(socket_path) = config.sekai_socket.as_deref()
            && plane.serves_sekai()
        {
            ensure_local_gateway_credential(socket_path, &db)?;
        }
        let assertion_authority = config
            .assertion_authority()
            .map_err(std::io::Error::other)?
            .map(Arc::new);
        let services =
            build_services_for_plane(&config, &stores, plane).map_err(std::io::Error::other)?;
        Ok((
            db,
            chisei_db,
            provider_registry_state_path,
            credential_store,
            assertion_authority,
            services,
        ))
    })()?;

    let evidence_db = execution_evidence_runtime(&stores);
    Ok(async move {
        spawn_service_background_tasks(&config, evidence_db, &sekai_svc, &chisei_svc, plane);
        let actor_rate_gate = crate::chisei::actor_limit::ActorRateGate::from_config(&config);

        if let Some(ops_port) = config.ops_port {
            crate::obs::ops::bind_and_spawn(
                &config.ops_bind,
                ops_port,
                db.clone(),
                Some(chisei_db.clone()),
                plane.serves_sekai().then(|| db.clone()),
                provider_registry_state_path.clone(),
                credential_store.clone(),
                assertion_authority.clone(),
            )
            .await?;
        }

        if plane == ProcessPlane::Combined
            && crate::http_projection::should_bind(&config, &tcp_mode)
        {
            let http_port = config
                .http_port
                .expect("HTTP projection bind requires SEKAI_HTTP_PORT");
            crate::http_projection::validate_bind(&config.http_bind, &config)
                .map_err(std::io::Error::other)?;
            if tcp_mode.token_auth_mode {
                crate::http_projection::bind_and_spawn(
                    &config.http_bind,
                    http_port,
                    sekai_svc.clone(),
                    chisei_svc.clone(),
                    TokenAuthInterceptor::from_runtime(
                        credential_store.clone(),
                        crate::db::store::SekaiStore::from_shared_runtime(db.clone()),
                        assertion_authority.clone(),
                    )
                    .with_actor_rate_gate(actor_rate_gate.clone()),
                    stores.clone(),
                )
                .await?;
            } else {
                crate::http_projection::bind_and_spawn(
                    &config.http_bind,
                    http_port,
                    sekai_svc.clone(),
                    chisei_svc.clone(),
                    local_or_token_interceptor_with_rate_gate(
                        credential_store.clone(),
                        db.clone(),
                        assertion_authority.clone(),
                        actor_rate_gate.clone(),
                    ),
                    stores.clone(),
                )
                .await?;
            }
        }

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        spawn_health_reporter(health_reporter, db.clone(), provider_registry_state_path);

        if let Some(socket_path) = config.sekai_socket.clone() {
            let uds_server = serve_uds(
                socket_path,
                sekai_svc.clone(),
                chisei_svc.clone(),
                local_or_token_interceptor_with_rate_gate(
                    credential_store.clone(),
                    db.clone(),
                    assertion_authority.clone(),
                    actor_rate_gate.clone(),
                ),
                health_service.clone(),
                plane,
                stores.clone(),
            );

            if tcp_mode.auth_configured || config.insecure {
                let tcp_server = run_tcp(
                    config.grpc_port,
                    &config,
                    sekai_svc,
                    chisei_svc,
                    &tcp_mode,
                    credential_store,
                    db,
                    assertion_authority,
                    actor_rate_gate,
                    health_service,
                    plane,
                    stores,
                );
                return tokio::select! {
                    result = tcp_server => result,
                    result = uds_server => result,
                };
            }

            return uds_server.await;
        }

        if !tcp_mode.token_auth_mode && !config.insecure {
            return Err(std::io::Error::other(
                "create a principal credential before enabling TCP, or set SEKAI_INSECURE=1 for local development",
            )
            .into());
        }

        run_tcp(
            config.grpc_port,
            &config,
            sekai_svc,
            chisei_svc,
            &tcp_mode,
            credential_store,
            db,
            assertion_authority,
            actor_rate_gate,
            health_service,
            plane,
            stores,
        )
        .await
    })
}

fn ensure_local_gateway_credential(
    socket_path: &str,
    db: &RuntimeDb,
) -> Result<(), std::io::Error> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let token_path = format!("{socket_path}.gateway-token");
    if let Ok(token) = std::fs::read_to_string(&token_path) {
        let token = token.trim();
        if !token.is_empty()
            && db
                .get_principal_credential(&hash_gateway_key(token))
                .map_err(std::io::Error::other)?
                .is_some_and(|credential| credential.principal == "chisei-gateway")
        {
            return Ok(());
        }
    }

    if let Some(parent) = std::path::Path::new(&token_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let token = format!("sekai-gateway-{}", uuid::Uuid::new_v4().simple());
    db.rotate_principal_credential("chisei-gateway", &hash_gateway_key(&token))
        .map_err(std::io::Error::other)?;
    let temporary = format!("{token_path}.tmp-{}", uuid::Uuid::new_v4().simple());
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(temporary, token_path)
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp<H>(
    port: u16,
    config: &Config,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    tcp_mode: &GrpcTcpMode,
    credential_store: Arc<PrincipalCredentialStore>,
    db: Arc<RuntimeDb>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    actor_rate_gate: crate::chisei::actor_limit::ActorRateGate,
    health_service: H,
    plane: ProcessPlane,
    stores: Arc<CombinedStoreLayout>,
) -> Result<(), Box<dyn std::error::Error>>
where
    H: tower::Service<http::Request<tonic::body::Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    H::Response: IntoResponse,
    H::Future: Send + 'static,
{
    let bind_addr = tcp_mode.bind_addr.as_str();

    if tcp_mode.token_auth_mode {
        serve_tcp_listener(
            bind_addr,
            port,
            config,
            sekai_svc,
            chisei_svc,
            TokenAuthInterceptor::from_runtime(
                credential_store,
                crate::db::store::SekaiStore::from_shared_runtime(db),
                assertion_authority,
            )
            .with_actor_rate_gate(actor_rate_gate.clone()),
            health_service,
            plane,
            stores,
        )
        .await
    } else {
        serve_tcp_listener(
            bind_addr,
            port,
            config,
            sekai_svc,
            chisei_svc,
            local_or_token_interceptor_with_rate_gate(
                credential_store,
                db,
                assertion_authority,
                actor_rate_gate,
            ),
            health_service,
            plane,
            stores,
        )
        .await
    }
}

#[allow(clippy::future_not_send, clippy::too_many_arguments)]
async fn serve_tcp_listener<I, H>(
    bind_addr: &str,
    port: u16,
    config: &Config,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    interceptor: I,
    health_service: H,
    plane: ProcessPlane,
    stores: Arc<CombinedStoreLayout>,
) -> Result<(), Box<dyn std::error::Error>>
where
    I: tonic::service::Interceptor + Clone + Send + Sync + 'static,
    H: tower::Service<http::Request<tonic::body::Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    H::Response: IntoResponse,
    H::Future: Send + 'static,
{
    let maybe_tls = tls_policy(bind_addr, config).map_err(std::io::Error::other)?;
    let addr = format!("{}:{}", bind_addr, port).parse()?;
    tracing::info!(addr = %addr, "gRPC server listening");

    let mut server = Server::builder().layer(MetricsLayer);
    if let Some((cert, key)) = maybe_tls {
        let identity = Identity::from_pem(std::fs::read(cert)?, std::fs::read(key)?);
        server = server.tls_config(ServerTlsConfig::new().identity(identity))?;
    }

    server
        .add_service(health_service)
        .add_service(rpc_identity::RpcIdentityService::new(
            InterceptedService::new(
                RpcMaturityLayer::from_env().layer(
                    pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(
                        sekai_svc.clone(),
                    ),
                ),
                with_restore_fence(
                    stores.clone(),
                    with_plane(plane, ProcessPlane::Sekai, interceptor.clone()),
                ),
            ),
        ))
        .add_service(rpc_identity::RpcIdentityService::new(
            InterceptedService::new(
                RpcMaturityLayer::from_env().layer(
                    pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(
                        chisei_svc.clone(),
                    ),
                ),
                with_restore_fence(stores, with_plane(plane, ProcessPlane::Chisei, interceptor)),
            ),
        ))
        .serve(addr)
        .await
        .map_err(Into::into)
}

async fn serve_uds<I, H>(
    socket_path: String,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    interceptor: I,
    health_service: H,
    plane: ProcessPlane,
    stores: Arc<CombinedStoreLayout>,
) -> Result<(), Box<dyn std::error::Error>>
where
    I: tonic::service::Interceptor + Clone + Send + Sync + 'static,
    H: tower::Service<http::Request<tonic::body::Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    H::Response: IntoResponse,
    H::Future: Send + 'static,
{
    let path = Path::new(&socket_path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!(
        socket_path,
        "gRPC server listening on UDS (mode 0600; unauthenticated callers are forced to principal local)"
    );

    Ok(tonic::transport::Server::builder()
        .layer(MetricsLayer)
        .add_service(health_service)
        .add_service(rpc_identity::RpcIdentityService::new(
            InterceptedService::new(
                RpcMaturityLayer::from_env().layer(
                    pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(
                        sekai_svc.clone(),
                    ),
                ),
                with_restore_fence(
                    stores.clone(),
                    with_plane(plane, ProcessPlane::Sekai, interceptor.clone()),
                ),
            ),
        ))
        .add_service(rpc_identity::RpcIdentityService::new(
            InterceptedService::new(
                RpcMaturityLayer::from_env().layer(
                    pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(
                        chisei_svc.clone(),
                    ),
                ),
                with_restore_fence(stores, with_plane(plane, ProcessPlane::Chisei, interceptor)),
            ),
        ))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?)
}

pub fn build_services(
    config: &Config,
    stores: &CombinedStoreLayout,
) -> Result<
    (
        Arc<sekai_service::SekaiServiceImpl>,
        Arc<chisei_service::ChiseiServiceImpl>,
    ),
    String,
> {
    build_services_for_plane(config, stores, ProcessPlane::Combined)
}

pub fn build_services_for_plane(
    config: &Config,
    stores: &CombinedStoreLayout,
    plane: ProcessPlane,
) -> Result<
    (
        Arc<sekai_service::SekaiServiceImpl>,
        Arc<chisei_service::ChiseiServiceImpl>,
    ),
    String,
> {
    let (sekai_store, chisei_store) = stores.handles();
    let budget = Arc::new(BudgetTracker::with_topology(
        chisei_store.clone(),
        config.budget_topology.clone(),
    ));
    let mut sekai_svc = if plane.serves_sekai() {
        sekai_service::SekaiServiceImpl::new_with_gateway_schema_principals(
            sekai_store.clone(),
            config.gateway_receipt_principals.clone(),
        )
    } else {
        sekai_service::SekaiServiceImpl::wrong_plane_placeholder(sekai_store.clone())
    }
    .with_site_id(config.site_id.clone())
    .with_runtime_token_authority(config.assertion_authority()?.map(Arc::new))
    .with_agent_ceiling(config.actor_chain_enforcement);
    if plane == ProcessPlane::Combined {
        let clerk = Arc::new(
            crate::composition::cross_store_admission::CrossStoreAdmission::new(
                chisei_store.clone(),
                sekai_store.clone(),
                Some(budget.clone()),
            ),
        );
        sekai_svc = sekai_svc.with_cross_store_admission(clerk);
    }
    let mut chisei_svc =
        chisei_service::ChiseiServiceImpl::with_budget(chisei_store, config.clone(), budget);
    match plane {
        ProcessPlane::Combined => {
            // Owned and split layouts alike: Sekai facts come from the Sekai
            // store, never from the Chisei store.
            chisei_svc = chisei_svc
                .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::in_process(
                    sekai_store.clone(),
                ))?
                .with_sekai_commit_lookup(Arc::new(sekai_store));
        }
        ProcessPlane::Chisei => {
            let endpoint = config.sekai_endpoint.as_deref().unwrap_or("");
            plane.require_sekai_endpoint(Some(endpoint))?;
            chisei_svc = chisei_svc
                .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::new(Arc::new(
                    crate::grpc::remote_sekai::RemoteSekaiFactReader::from_env(
                        endpoint.to_string(),
                    ),
                )))?
                .with_sekai_commit_lookup(Arc::new(
                    crate::grpc::remote_sekai::RemoteSekaiCommitLookup::from_env(
                        endpoint.to_string(),
                    ),
                ));
        }
        ProcessPlane::Sekai => {}
    }

    let chisei_svc = Arc::new(chisei_svc);
    if plane == ProcessPlane::Combined {
        sekai_svc = sekai_svc.with_embedding_route(hosted_embedding_route(chisei_svc.clone()));
    }
    Ok((Arc::new(sekai_svc), chisei_svc))
}

/// The hosted catalog route of a stored embedding spec, admitted as hosted
/// execution admits it. Combined mode only: it needs the Chisei catalog.
fn hosted_embedding_route(
    chisei: Arc<chisei_service::ChiseiServiceImpl>,
) -> crate::composition::embedding_catch_up::EmbeddingRoute {
    use crate::sekai::embedding_index::EmbeddingError;
    Arc::new(move |stored| {
        let admitted = chisei
            .hosted_embedder(&stored.spec.namespace, &stored.model)
            .map_err(|status| EmbeddingError::Refused(status.message().to_string()));
        Box::pin(async move { admitted })
    })
}

fn spawn_service_background_tasks(
    config: &Config,
    db: Arc<RuntimeDb>,
    sekai_svc: &Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: &Arc<chisei_service::ChiseiServiceImpl>,
    plane: ProcessPlane,
) {
    if plane == ProcessPlane::Combined && config.scoring_enabled {
        tracing::info!(
            model = %config.scoring_model,
            interval_secs = config.scoring_interval_secs,
            batch_size = config.scoring_batch_size,
            "scoring job enabled"
        );
        tokio::spawn(
            chisei_svc
                .scoring_job()
                .with_knowledge_writer(sekai_svc.clone())
                .run_loop(),
        );
    }
    if plane.serves_sekai() {
        spawn_catalog_reconciler(db.clone());
        spawn_export_sweeper(db.clone());
        spawn_execution_evidence_reconciler(db.clone());
    }
    if plane == ProcessPlane::Combined
        && let Some(clerk) = &sekai_svc.cross_store
    {
        spawn_admission_reconciler(clerk.clone());
    }
    if plane == ProcessPlane::Combined {
        spawn_embedding_catch_up(db.clone(), chisei_svc.clone());
    }
}

/// Embed every stored spec on a schedule (#1609). Combined mode only: it
/// needs the Sekai change feed and the Chisei route catalog. Safe on every
/// instance at once; catch-up writes are fenced per spec.
fn spawn_embedding_catch_up(db: Arc<RuntimeDb>, chisei: Arc<chisei_service::ChiseiServiceImpl>) {
    use crate::composition::embedding_catch_up::catch_up_stored_specs;
    use crate::sekai::embedding_index::EmbeddingError;
    let hosted = hosted_embedding_route(chisei);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let route = |stored| hosted(stored);
            let now = || chrono::Utc::now().timestamp_millis();
            // Another pass while any spec has more pending, up to a bound.
            for _ in 0..8 {
                let outcomes = match catch_up_stored_specs(&db, &route, &now).await {
                    Ok(outcomes) => outcomes,
                    Err(error) => {
                        tracing::error!(%error, "embedding specs unavailable");
                        break;
                    }
                };
                let mut more = false;
                for (stored, outcome) in outcomes {
                    match outcome {
                        Ok(report) => more |= report.more,
                        Err(EmbeddingError::Conflict(_)) => {}
                        Err(error) => tracing::warn!(
                            namespace = %stored.spec.namespace,
                            spec = %stored.spec.id,
                            %error,
                            "embedding catch-up failed; retrying next pass"
                        ),
                    }
                }
                if !more {
                    break;
                }
            }
        }
    });
}

fn spawn_admission_reconciler(
    clerk: Arc<crate::composition::cross_store_admission::CrossStoreAdmission>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let clerk = clerk.clone();
            let result = tokio::task::spawn_blocking(move || {
                clerk.reconcile_pending(chrono::Utc::now().timestamp_millis())
            })
            .await;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::error!(?error, "admission reservation reconciliation failed")
                }
                Err(error) => {
                    tracing::error!(%error, "admission reservation reconciliation task failed")
                }
            }
        }
    });
}

/// Remove expired export artifacts and close exports whose exporter was
/// lost (#1628, ADR 0130), whether or not anything exports. Safe on every
/// instance at once: each removal and each close is conditional.
fn spawn_export_sweeper(db: Arc<RuntimeDb>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let db = db.clone();
            let result = tokio::task::spawn_blocking(move || {
                let now = chrono::Utc::now().timestamp_millis();
                crate::sekai::data_export::recover_abandoned_exports(&db, now)?;
                crate::sekai::data_export::sweep_expired_artifacts(&db, now)
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!(%error, "export sweep failed"),
                Err(error) => tracing::error!(%error, "export sweep task failed"),
            }
        }
    });
}

/// Keep object-type catalog entries in line with each published ontology
/// (ADR 0122). Safe on every instance at once.
fn spawn_catalog_reconciler(db: Arc<RuntimeDb>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let db = db.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::sekai::catalog::reconcile_ontology_entries(
                    &db,
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .await;
            match result {
                Ok(Ok(failed)) if failed.is_empty() => {}
                Ok(Ok(failed)) => {
                    tracing::warn!(?failed, "catalog reconciliation failed for namespaces")
                }
                Ok(Err(error)) => tracing::error!(%error, "catalog reconciliation failed"),
                Err(error) => tracing::error!(%error, "catalog reconciliation task failed"),
            }
        }
    });
}

fn execution_evidence_runtime(stores: &CombinedStoreLayout) -> Arc<RuntimeDb> {
    stores.sekai_runtime()
}

const EVIDENCE_RECONCILE_ACTIVE_SECS: u64 = 10;
const EVIDENCE_RECONCILE_IDLE_SECS: u64 = 60;

fn evidence_reconcile_backoff(last_alert_count: usize) -> std::time::Duration {
    if last_alert_count == 0 {
        std::time::Duration::from_secs(EVIDENCE_RECONCILE_IDLE_SECS)
    } else {
        std::time::Duration::from_secs(EVIDENCE_RECONCILE_ACTIVE_SECS)
    }
}

fn spawn_execution_evidence_reconciler(db: Arc<RuntimeDb>) {
    tokio::spawn(async move {
        let mut delay = std::time::Duration::ZERO;
        loop {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let db = db.clone();
            let result = tokio::task::spawn_blocking(move || {
                db.reconcile_missing_execution_evidence(chrono::Utc::now().timestamp_millis())
            })
            .await;
            let alert_count = match &result {
                Ok(Ok(alerts)) => alerts.len(),
                _ => 1,
            };
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::error!(%error, "execution evidence reconciliation failed")
                }
                Err(error) => {
                    tracing::error!(%error, "execution evidence reconciliation task failed")
                }
            }
            delay = evidence_reconcile_backoff(alert_count);
        }
    });
}

fn spawn_health_reporter(
    health_reporter: HealthReporter,
    db: Arc<RuntimeDb>,
    provider_registry_state_path: std::path::PathBuf,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            let ready = tokio::task::spawn_blocking({
                let db = db.clone();
                let provider_registry_state_path = provider_registry_state_path.clone();
                move || {
                    db.ping().is_ok()
                        && crate::provider_profile::refresh_provider_registry(
                            &provider_registry_state_path,
                        )
                        .is_ok()
                }
            })
            .await
            .unwrap_or(false);
            let status = if ready {
                ServingStatus::Serving
            } else {
                ServingStatus::NotServing
            };
            health_reporter.set_service_status("", status).await;
            health_reporter
                .set_service_status("sekai.SekaiService", status)
                .await;
            health_reporter
                .set_service_status("chisei.ChiseiService", status)
                .await;
            interval.tick().await;
        }
    });
}

#[cfg(test)]
mod runtime_token_tests;

#[cfg(test)]
mod service_principal_tests;

#[cfg(test)]
mod service_scope_tests;

#[cfg(test)]
mod service_token_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::service::Interceptor;

    fn in_memory_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )))
    }

    fn base_config() -> Config {
        let mut config = Config::from_env();
        config.tls_cert = None;
        config.tls_key = None;
        config.allow_plaintext = false;
        config
    }

    #[test]
    fn run_returns_setup_errors_before_the_server_future_is_polled() {
        let parent_file = tempfile::NamedTempFile::new().unwrap();
        let mut config = base_config();
        config.sekai_socket = Some(
            parent_file
                .path()
                .join("sekai.sock")
                .to_string_lossy()
                .into_owned(),
        );
        let stores = Arc::new(CombinedStoreLayout::from_backend(
            crate::runtime_backend::RuntimeBackend::from_sqlite_with_enterprise_extension(
                ":memory:", None,
            )
            .unwrap(),
        ));
        let tcp_mode = GrpcTcpMode {
            bind_addr: "127.0.0.1".into(),
            token_auth_mode: false,
            auth_configured: false,
            bind_inferred_from_active_credentials: false,
        };

        let result = run(config, stores, Vec::new(), tcp_mode);

        assert!(result.is_err());
    }

    #[test]
    fn execution_evidence_reconciler_binds_sekai_store_in_split_mode() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = crate::combined_stores::CombinedStoreSources {
            backend: Some(crate::runtime_backend::BackendIdentity::Sqlite),
            default_sqlite_path: "unused.db".into(),
            sekai_sqlite_path: Some(sekai.to_string_lossy().into_owned()),
            chisei_sqlite_path: Some(chisei.to_string_lossy().into_owned()),
            postgres_max_connections: 16,
            ..crate::combined_stores::CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        let evidence = execution_evidence_runtime(&layout);
        assert!(
            Arc::ptr_eq(&evidence, &layout.sekai_runtime()),
            "Sekai execution-evidence reconcile must use the Sekai runtime"
        );
        assert!(
            !Arc::ptr_eq(&evidence, &layout.chisei_runtime()),
            "Sekai execution-evidence reconcile must not use the Chisei runtime"
        );
    }

    #[test]
    fn evidence_reconcile_backoff_idles_when_empty() {
        assert_eq!(
            evidence_reconcile_backoff(0),
            std::time::Duration::from_secs(EVIDENCE_RECONCILE_IDLE_SECS)
        );
        assert_eq!(
            evidence_reconcile_backoff(1),
            std::time::Duration::from_secs(EVIDENCE_RECONCILE_ACTIVE_SECS)
        );
    }

    #[test]
    fn build_services_wires_reserve_commit_finalize_clerk() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = crate::combined_stores::CombinedStoreSources {
            backend: Some(crate::runtime_backend::BackendIdentity::Sqlite),
            default_sqlite_path: "unused.db".into(),
            sekai_sqlite_path: Some(sekai.to_string_lossy().into_owned()),
            chisei_sqlite_path: Some(chisei.to_string_lossy().into_owned()),
            postgres_max_connections: 16,
            ..crate::combined_stores::CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        let (sekai_svc, chisei_svc) =
            build_services(&crate::config::Config::from_env(), &layout).unwrap();
        let clerk = sekai_svc
            .cross_store
            .as_ref()
            .expect("combined mode must own the typed admission hop");
        assert!(clerk.distinct_stores());
        assert!(
            chisei_svc.sekai_commit_lookup.is_some(),
            "GetOperationReceipt must be able to project a live Sekai commit handle"
        );
    }

    #[test]
    fn token_auth_interceptor_enforces_missing_authorization() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor =
            TokenAuthInterceptor::new(store, crate::db::store::SekaiStore::from_shared_runtime(db));

        let request = Request::new(());
        assert!(interceptor.call(request).is_err());
    }

    #[test]
    fn token_auth_interceptor_rejects_assertion_with_caller_tenant_header() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor =
            TokenAuthInterceptor::new(store, crate::db::store::SekaiStore::from_shared_runtime(db));
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer sia1.payload.sig"),
        );
        request.metadata_mut().insert(
            TENANT_CONTEXT_HEADER,
            MetadataValue::from_static("tenant-evil"),
        );
        let error = interceptor.call(request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "caller-selected tenant header");
    }

    #[test]
    fn community_interceptor_treats_assertions_as_invalid_without_authority() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor =
            TokenAuthInterceptor::new(store, crate::db::store::SekaiStore::from_shared_runtime(db));
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer sia1.payload.sig"),
        );
        let error = interceptor.call(request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    fn test_assertion_authority() -> crate::identity_assertion::AssertionAuthority {
        crate::identity_assertion::AssertionAuthority::new(
            "https://issuer.test",
            "https://sekai.test",
            b"test-hmac-key",
        )
    }

    fn test_assertion_claims(
        nonce: &str,
        expires_at: i64,
    ) -> crate::identity_assertion::IdentityAssertion {
        crate::identity_assertion::IdentityAssertion {
            contract_version: crate::identity_assertion::IDENTITY_ASSERTION_VERSION.into(),
            issuer: "https://issuer.test".into(),
            audience: "https://sekai.test".into(),
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
            credential_kind: "human_session".into(),
            space: None,
            space_role: None,
            act: None,
            tenant_id: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            expires_at,
            nonce: nonce.into(),
            device: None,
        }
    }

    fn interceptor_with_authority(
        authority: crate::identity_assertion::AssertionAuthority,
    ) -> TokenAuthInterceptor {
        TokenAuthInterceptor::from_runtime(
            Arc::new(PrincipalCredentialStore::new()),
            crate::db::store::SekaiStore::from_shared_runtime(in_memory_db()),
            Some(Arc::new(authority)),
        )
    }

    fn bearer_request(token: &str) -> Request<()> {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).expect("bearer metadata"),
        );
        request
    }

    #[test]
    fn catalog_describe_is_discover_and_content_is_read() {
        use crate::enterprise::NamespaceAction;
        assert_eq!(
            rpc_namespace_action("ListSchemaTypes"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("ListDatasets"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("GetCatalogEntryLineage"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("ListCatalogCriticalityOutbox"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("ListDatasetVersions"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("GetDatasetVersion"),
            NamespaceAction::Read
        );
        assert_eq!(
            rpc_namespace_action("RollbackDataset"),
            NamespaceAction::Write
        );
        for method in ["ListDatasetBranches", "CompareDatasetBranch"] {
            assert_eq!(rpc_namespace_action(method), NamespaceAction::Read);
        }
        for method in [
            "CreateDatasetBranch",
            "DeleteDatasetBranch",
            "ProposeDatasetBranchMerge",
            "MergeDatasetBranch",
        ] {
            assert_eq!(rpc_namespace_action(method), NamespaceAction::Write);
            assert!(enterprise_namespace_rpc("sekai.SekaiService", method));
        }
        assert_eq!(
            rpc_namespace_action("DescribeObjectAction"),
            NamespaceAction::Discover
        );
        assert_eq!(
            rpc_namespace_action("DiscoverCapabilities"),
            NamespaceAction::Discover
        );
        assert_eq!(rpc_namespace_action("GetObject"), NamespaceAction::Read);
        assert_eq!(rpc_namespace_action("QueryRows"), NamespaceAction::Read);
        assert_eq!(
            rpc_namespace_action("EvaluateObjectSet"),
            NamespaceAction::Read
        );
        assert_eq!(rpc_namespace_action("CreateObject"), NamespaceAction::Write);
    }

    #[test]
    fn signed_space_roles_constrain_mutations_and_approval_rpc() {
        use crate::enterprise::SpaceRole;
        for (role, method, allowed) in [
            (SpaceRole::Discoverer, "ListSchemaTypes", true),
            (SpaceRole::Discoverer, "ListDatasets", true),
            (SpaceRole::Discoverer, "GetCatalogEntryLineage", true),
            (SpaceRole::Discoverer, "ListCatalogCriticalityOutbox", true),
            (SpaceRole::Discoverer, "ListDatasetVersions", true),
            (SpaceRole::Discoverer, "GetDatasetVersion", false),
            (SpaceRole::Discoverer, "RollbackDataset", false),
            (SpaceRole::Viewer, "GetDatasetVersion", true),
            (SpaceRole::Viewer, "RollbackDataset", false),
            (SpaceRole::Editor, "RollbackDataset", true),
            (SpaceRole::Discoverer, "DescribeObjectAction", true),
            (SpaceRole::Discoverer, "DiscoverCapabilities", true),
            (SpaceRole::Discoverer, "GetObject", false),
            (SpaceRole::Discoverer, "QueryRows", false),
            (SpaceRole::Discoverer, "EvaluateObjectSet", false),
            (SpaceRole::Discoverer, "CreateObject", false),
            (SpaceRole::Viewer, "CreateObject", false),
            (SpaceRole::Viewer, "GetObject", true),
            (SpaceRole::Viewer, "CompareDefinitionRevisions", true),
            (SpaceRole::Viewer, "PreviewObjectAction", false),
            (SpaceRole::Editor, "PreviewObjectAction", true),
            (SpaceRole::Viewer, "GetOntologyLintReport", true),
            // Data leaving the plane takes space write, not view.
            (SpaceRole::Viewer, "ExportObjectSet", false),
            (SpaceRole::Editor, "ExportObjectSet", true),
            (SpaceRole::Discoverer, "GetOntologyLintReport", false),
            (SpaceRole::Viewer, "GetOntologyHealth", true),
            (SpaceRole::Discoverer, "GetOntologyHealth", false),
            (SpaceRole::Viewer, "ListOntologyHealthTrend", true),
            (SpaceRole::Viewer, "RecordOntologyHealthSnapshot", false),
            (SpaceRole::Editor, "RecordOntologyHealthSnapshot", true),
            (SpaceRole::Editor, "CreateObject", true),
            (SpaceRole::Editor, "DecideActionInstance", false),
            (SpaceRole::Approver, "DecideActionInstance", true),
            (SpaceRole::Editor, "DecidePlanReview", false),
            (SpaceRole::Approver, "DecidePlanReview", true),
            (SpaceRole::Viewer, "GetPlan", true),
            (SpaceRole::Viewer, "SubmitPlanReview", false),
            (SpaceRole::Editor, "SubmitPlanReview", true),
            (SpaceRole::Viewer, "ExecuteActionPlan", false),
            (SpaceRole::Editor, "ExecuteActionPlan", true),
            (SpaceRole::Approver, "CreateObject", false),
            (SpaceRole::Administrator, "CreateObject", true),
        ] {
            let authority = test_assertion_authority();
            let mut claims = test_assertion_claims(
                &uuid::Uuid::new_v4().to_string(),
                chrono::Utc::now().timestamp() + 60,
            );
            claims.tenant_id = Some("tenant-test".into());
            claims.space = Some("space-a".into());
            claims.space_role = Some(role);
            claims.act = Some("origin-user".into());
            let token = authority.sign(&claims).unwrap();
            let mut interceptor = interceptor_with_authority(authority);
            let mut request = bearer_request(&token);
            request
                .extensions_mut()
                .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
            let result = interceptor.call(request);
            assert_eq!(
                result.is_ok(),
                allowed,
                "{role:?} {method}: {:?}",
                result.as_ref().err()
            );
            if let Ok(request) = result {
                let context = request
                    .extensions()
                    .get::<crate::enterprise::AuthenticatedContext>()
                    .unwrap();
                assert_eq!(context.principal.subject, "subject-a");
                assert_eq!(context.act.as_deref(), Some("origin-user"));
            }
        }
    }

    #[test]
    fn human_discover_scope_does_not_admit_content_reads() {
        use crate::enterprise::SpaceRole;
        for (method, allowed) in [
            ("ListSchemaTypes", true),
            ("DiscoverCapabilities", true),
            ("GetObject", false),
            ("QueryRows", false),
        ] {
            let authority = test_assertion_authority();
            let mut claims = test_assertion_claims(
                &uuid::Uuid::new_v4().to_string(),
                chrono::Utc::now().timestamp() + 60,
            );
            claims.tenant_id = Some("tenant-test".into());
            claims.space = Some("space-a".into());
            claims.space_role = Some(SpaceRole::Viewer);
            claims.act = Some("origin-user".into());
            claims.scopes = vec!["sekai.discover".into()];
            let token = authority.sign(&claims).unwrap();
            let mut interceptor = interceptor_with_authority(authority);
            let mut request = bearer_request(&token);
            request
                .extensions_mut()
                .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
            let result = interceptor.call(request);
            assert_eq!(
                result.is_ok(),
                allowed,
                "{method}: {:?}",
                result.as_ref().err()
            );
        }
    }

    #[test]
    fn token_auth_interceptor_valid_assertion_fills_authenticated_context() {
        let authority = test_assertion_authority();
        let expires_at = chrono::Utc::now().timestamp() + 60;
        let token = authority
            .sign(&test_assertion_claims("n-ok", expires_at))
            .unwrap();
        let mut interceptor = interceptor_with_authority(authority);
        let request = interceptor.call(bearer_request(&token)).unwrap();
        let context = request
            .extensions()
            .get::<crate::enterprise::AuthenticatedContext>()
            .expect("assertion must fill AuthenticatedContext on the interceptor path");
        assert_eq!(context.principal.subject, "subject-a");
        assert_eq!(context.principal.credential_id, "credential-a");
        assert_eq!(context.scopes, ["sekai.read", "sekai.write"]);
        assert_eq!(context.issuer, "https://issuer.test");
        assert_eq!(context.resource, "https://sekai.test");
        assert!(context.tenant.is_none());
        assert_eq!(
            request
                .metadata()
                .get("x-principal")
                .unwrap()
                .to_str()
                .unwrap(),
            "subject-a"
        );
        assert_eq!(
            request
                .metadata()
                .get(AUTH_SOURCE_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            "token"
        );
    }

    #[test]
    fn token_auth_interceptor_rejects_each_assertion_class() {
        let authority = test_assertion_authority();
        let expires_at = chrono::Utc::now().timestamp() + 60;
        let mut interceptor = interceptor_with_authority(authority.clone());

        let token = authority
            .sign(&test_assertion_claims("n-header", expires_at))
            .unwrap();
        let mut request = bearer_request(&token);
        request.metadata_mut().insert(
            TENANT_CONTEXT_HEADER,
            MetadataValue::from_static("tenant-evil"),
        );
        let error = interceptor.call(request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "caller-selected tenant header");

        let mut bad_iss = test_assertion_claims("n-iss", expires_at);
        bad_iss.issuer = "https://other.test".into();
        let error = interceptor
            .call(bearer_request(&authority.sign(&bad_iss).unwrap()))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid assertion issuer");

        let mut bad_aud = test_assertion_claims("n-aud", expires_at);
        bad_aud.audience = "https://other.test".into();
        let error = interceptor
            .call(bearer_request(&authority.sign(&bad_aud).unwrap()))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid assertion audience");

        let mut token = authority
            .sign(&test_assertion_claims("n-sig", expires_at))
            .unwrap();
        token.push('x');
        let error = interceptor.call(bearer_request(&token)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid assertion signature");

        let expired = authority
            .sign(&test_assertion_claims(
                "n-exp",
                chrono::Utc::now().timestamp() - 120,
            ))
            .unwrap();
        let error = interceptor.call(bearer_request(&expired)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "assertion expired");

        let replay = authority
            .sign(&test_assertion_claims("n-replay", expires_at))
            .unwrap();
        interceptor.call(bearer_request(&replay)).unwrap();
        let error = interceptor.call(bearer_request(&replay)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "assertion replay");

        let mut escalate = test_assertion_claims("n-scope", expires_at);
        escalate.scopes = vec!["sekai.admin".into()];
        let error = interceptor
            .call(bearer_request(&authority.sign(&escalate).unwrap()))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(error.message(), "assertion scope escalation");
    }

    #[test]
    fn token_auth_interceptor_from_config_installs_authority() {
        let mut config = base_config();
        config.assertion_issuer = Some("https://issuer.test".into());
        config.assertion_audience = Some("https://sekai.test".into());
        config.assertion_hmac_key = Some("test-hmac-key".into());
        let mut interceptor = TokenAuthInterceptor::from_config(
            Arc::new(PrincipalCredentialStore::new()),
            crate::db::store::SekaiStore::from_shared_runtime(in_memory_db()),
            &config,
        )
        .unwrap();
        let authority = test_assertion_authority();
        let token = authority
            .sign(&test_assertion_claims(
                "n-config",
                chrono::Utc::now().timestamp() + 60,
            ))
            .unwrap();
        let context = interceptor
            .call(bearer_request(&token))
            .unwrap()
            .extensions()
            .get::<crate::enterprise::AuthenticatedContext>()
            .cloned()
            .expect("config-installed authority must verify on the interceptor path");
        assert_eq!(context.principal.subject, "subject-a");
        assert_eq!(context.scopes, ["sekai.read", "sekai.write"]);
    }

    #[test]
    fn token_auth_interceptor_throttles_per_principal_when_enabled() {
        let authority = test_assertion_authority();
        let mut interceptor = interceptor_with_authority(authority.clone())
            .with_actor_rate_gate(crate::chisei::actor_limit::ActorRateGate::enabled(1, 1));
        let expires_at = chrono::Utc::now().timestamp() + 60;
        let unique = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let first = authority
            .sign(&test_assertion_claims(
                &format!("n-limit-a-{unique}"),
                expires_at,
            ))
            .unwrap();
        interceptor.call(bearer_request(&first)).unwrap();
        let second = authority
            .sign(&test_assertion_claims(
                &format!("n-limit-b-{unique}"),
                expires_at,
            ))
            .unwrap();
        let error = interceptor.call(bearer_request(&second)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(error.message().contains("retry_after"));
        assert!(error.metadata().get("retry-after-ms").is_some());
    }

    #[test]
    fn token_auth_interceptor_rejects_unsupported_or_expired_enterprise_context() {
        struct BoundedExtension {
            version: &'static str,
            expires_at: i64,
        }

        impl crate::enterprise::EnterpriseExtension for BoundedExtension {
            fn contract_version(&self) -> &'static str {
                self.version
            }

            fn authenticate_bearer(
                &self,
                _bearer_token: &str,
            ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
            {
                Ok(crate::enterprise::AuthenticatedPrincipal {
                    subject: "human:alice".into(),
                    credential_id: "credential-1".into(),
                })
            }

            fn authenticate_context(
                &self,
                bearer_token: &str,
            ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
            {
                let principal = self.authenticate_bearer(bearer_token)?;
                Ok(crate::enterprise::AuthenticatedContext {
                    contract_version: self.contract_version(),
                    home_tenant: None,
                    tenant: Some(self.tenant_context(&principal)?),
                    principal,
                    credential_kind: crate::enterprise::CredentialKind::HumanSession,
                    space: None,
                    space_role: None,
                    act: None,
                    scopes: vec!["sekai.read".into()],
                    issuer: "https://issuer.test".into(),
                    resource: "https://sekai.test".into(),
                    expires_at: self.expires_at,
                    device: None,
                })
            }

            fn tenant_context(
                &self,
                principal: &crate::enterprise::AuthenticatedPrincipal,
            ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError>
            {
                Ok(crate::enterprise::TenantContext {
                    tenant_id: "tenant-1".into(),
                    subject: principal.subject.clone(),
                })
            }

            fn authorize_namespace(
                &self,
                _context: &crate::enterprise::TenantContext,
                _namespace: &str,
                _action: crate::enterprise::NamespaceAction,
            ) -> Result<(), crate::enterprise::ExtensionError> {
                Ok(())
            }

            fn authorize_unscoped_namespace(
                &self,
                _principal: &crate::enterprise::AuthenticatedPrincipal,
                _namespace: &str,
                _action: crate::enterprise::NamespaceAction,
            ) -> Result<(), crate::enterprise::ExtensionError> {
                Ok(())
            }
        }

        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(BoundedExtension {
                    version: "sekai.identity-extension/v0",
                    expires_at: i64::MAX,
                })),
            )
            .unwrap(),
        )));
        let mut interceptor = TokenAuthInterceptor::new(
            Arc::new(PrincipalCredentialStore::new()),
            crate::db::store::SekaiStore::from_shared_runtime(db),
        );
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer enterprise-token"),
        );
        request
            .extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", "GetObject"));
        assert_eq!(
            interceptor.call(request).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );

        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(BoundedExtension {
                    version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
                    expires_at: 0,
                })),
            )
            .unwrap(),
        )));
        let mut interceptor = TokenAuthInterceptor::new(
            Arc::new(PrincipalCredentialStore::new()),
            crate::db::store::SekaiStore::from_shared_runtime(db),
        );
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer enterprise-token"),
        );
        request
            .extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", "GetObject"));
        assert_eq!(
            interceptor.call(request).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn principal_metadata_rejects_list_injection_and_lossy_whitespace() {
        assert!(valid_single_principal("enterprise-user"));
        assert!(!valid_single_principal("user,root"));
        assert!(!valid_single_principal(" enterprise-user"));
        assert!(!valid_single_principal(""));
    }

    /// Tenant-callable RPCs (#1777, docs/tenant-assertion-rpcs.md): the
    /// namespace-scoped ones are admitted, and the global schema and ontology
    /// calls, which have no namespace to bind a tenant to, are not.
    #[test]
    fn tenant_assertions_reach_namespace_scoped_rpcs_only() {
        for method in [
            "PreviewObjectAction",
            "ListGovernedActionTypes",
            "ExplainDerivation",
            "EvaluateObjectSet",
            "GetSourceSyncState",
            "ReadObjectChangeSubscription",
            "CompareDefinitionRevisions",
            "QueryObjectPolicyAudit",
        ] {
            assert!(enterprise_namespace_method(method), "{method}");
        }
        // #1770: Chisei reads, admitted only on their own service.
        for method in ["GetOperationReceipt", "GetQualityTrend"] {
            assert!(enterprise_namespace_rpc("chisei.ChiseiService", method));
            assert!(!enterprise_namespace_rpc("sekai.SekaiService", method));
            assert_eq!(
                rpc_namespace_action(method),
                crate::enterprise::NamespaceAction::Read
            );
        }
        for method in [
            // ADR 0111: closing a proposal stays with unscoped credentials.
            "CloseDefinitionProposal",
            "CreateSchemaType",
            "CreateOntologyClass",
            "CreateOntologyRelation",
            "ListOntologyClasses",
            "ListOntologyRelations",
        ] {
            assert!(!enterprise_namespace_method(method), "{method}");
        }
        assert_eq!(
            rpc_namespace_action("CompareDefinitionRevisions"),
            crate::enterprise::NamespaceAction::Read
        );
        assert_eq!(
            rpc_namespace_action("PreviewObjectAction"),
            crate::enterprise::NamespaceAction::Write
        );
    }

    #[test]
    fn enterprise_allowlist_includes_governed_facts_and_native_execution() {
        for method in [
            "GetGovernedFactVersion",
            "ResolveInvariantSet",
            "PlanExecution",
            "ExecutePlanStream",
            "ListSchemaTypes",
            "ListDatasets",
            "DescribeObjectAction",
            "DiscoverCapabilities",
        ] {
            assert!(enterprise_namespace_method(method));
        }
    }

    #[test]
    fn scoped_draft_methods_require_the_qualified_service() {
        for method in [
            "GetDefinitionBranch",
            "CreateDefinitionBranch",
            "ApplyDefinitionBranchEdit",
            "ProposeDefinitionRollback",
            "ExportDefinitionPackage",
            "ImportDefinitionPackage",
            "ImportDefinitionTree",
        ] {
            assert!(enterprise_namespace_rpc("sekai.SekaiService", method));
            assert!(!enterprise_namespace_rpc("chisei.ChiseiService", method));
        }
        // ADR 0111: proposals publish drafts under the same grants and the
        // ADR 0079 certification gate; close stays unadmitted.
        for method in [
            "GetDefinitionProposal",
            "CreateDefinitionProposal",
            "ApproveDefinitionProposal",
            "MergeDefinitionProposal",
        ] {
            assert!(enterprise_namespace_rpc("sekai.SekaiService", method));
            assert!(!enterprise_namespace_rpc("chisei.ChiseiService", method));
        }
        assert!(!enterprise_namespace_rpc(
            "sekai.SekaiService",
            "CloseDefinitionProposal"
        ));
    }

    #[test]
    fn scoped_contexts_reach_offline_sync_with_read_scope() {
        // Admitted for scoped contexts, and classified as reads, so a
        // `sekai.read` device assertion passes the credential-scope check.
        for method in ["PutSyncScope", "ReadSyncSnapshot", "ReadSyncDeltas"] {
            assert!(enterprise_namespace_rpc("sekai.SekaiService", method));
            assert!(!enterprise_namespace_rpc("chisei.ChiseiService", method));
            assert_eq!(
                rpc_namespace_action(method),
                crate::enterprise::NamespaceAction::Read
            );
        }
    }

    #[test]
    fn scoped_transform_reads_preview_and_put_exclude_run() {
        // Reads and preview check namespace read (ADR 0110). Put checks
        // namespace write and dataset read (#1557). Run stays unadmitted.
        for method in [
            "ListGovernedTransforms",
            "ListGovernedTransformRuns",
            "GetGovernedTransformRun",
            "PreviewGovernedTransform",
            "PutGovernedTransform",
        ] {
            assert!(enterprise_namespace_rpc("sekai.SekaiService", method));
            assert!(!enterprise_namespace_rpc("chisei.ChiseiService", method));
        }
        for method in [
            "RunGovernedTransform",
            "RunGovernedTransformOnBranch",
            "ReplayGovernedTransform",
            "ShadowGovernedTransform",
        ] {
            assert!(!enterprise_namespace_rpc("sekai.SekaiService", method));
        }
    }

    #[test]
    fn token_auth_interceptor_overwrites_client_principal() {
        let db = in_memory_db();
        let store = PrincipalCredentialStore::new();
        let token = hash_gateway_key("sekai-client-token");
        db.create_principal_credential("agent-a", &token, 1)
            .unwrap();

        let credentials = db.list_active_credentials().unwrap();
        store.load(&credentials);

        let mut interceptor = TokenAuthInterceptor::new(
            Arc::new(store),
            crate::db::store::SekaiStore::from_shared_runtime(db.clone()),
        );

        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer sekai-client-token"),
        );
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("attacker"));
        request.metadata_mut().insert(
            TENANT_CONTEXT_HEADER,
            MetadataValue::from_static("tenant_forged"),
        );
        request
            .extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", "GetObject"));
        let request = interceptor.call(request).unwrap();

        assert_eq!(
            request
                .metadata()
                .get("x-principal")
                .unwrap()
                .to_str()
                .unwrap(),
            "agent-a"
        );
        assert!(request.metadata().get(TENANT_CONTEXT_HEADER).is_none());

        db.revoke_principal_credential("agent-a").unwrap();

        let mut revoked_request = Request::new(());
        revoked_request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer sekai-client-token"),
        );
        revoked_request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("attacker"));
        assert!(interceptor.call(revoked_request).is_err());
    }

    #[test]
    fn uds_interceptor_authenticates_bearer_tokens() {
        let db = in_memory_db();
        let store = PrincipalCredentialStore::new();
        let token_hash = hash_gateway_key("gateway-token");
        db.create_principal_credential("gateway-prod", &token_hash, 1)
            .unwrap();
        store.load(&db.list_active_credentials().unwrap());
        let mut interceptor = LocalOrTokenAuthInterceptor {
            local: LocalInterceptor::new(true),
            token: TokenAuthInterceptor::new(
                Arc::new(store),
                crate::db::store::SekaiStore::from_shared_runtime(db),
            ),
        };

        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer gateway-token"),
        );
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("root"));
        request
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, MetadataValue::from_static("local"));
        let request = interceptor.call(request).unwrap();

        assert_eq!(
            request.metadata().get("x-principal").unwrap(),
            "gateway-prod"
        );
        assert_eq!(request.metadata().get(AUTH_SOURCE_HEADER).unwrap(), "token");
    }

    #[test]
    fn uds_interceptor_overwrites_client_principal_without_bearer() {
        let db = in_memory_db();
        let store = PrincipalCredentialStore::new();
        let mut interceptor = LocalOrTokenAuthInterceptor {
            local: LocalInterceptor::new(true),
            token: TokenAuthInterceptor::new(
                Arc::new(store),
                crate::db::store::SekaiStore::from_shared_runtime(db),
            ),
        };

        for forged in ["root", "local", "alice", "chisei-gateway"] {
            let mut request = Request::new(());
            request
                .metadata_mut()
                .insert("x-principal", MetadataValue::try_from(forged).unwrap());
            request
                .metadata_mut()
                .insert(AUTH_SOURCE_HEADER, MetadataValue::from_static("token"));
            let request = interceptor.call(request).unwrap();
            assert_eq!(
                request
                    .metadata()
                    .get("x-principal")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "local",
                "forged principal {forged:?} must be overwritten"
            );
            assert_eq!(request.metadata().get(AUTH_SOURCE_HEADER).unwrap(), "local");
        }
    }

    #[test]
    fn local_interceptor_does_not_attach_authenticated_context() {
        let mut interceptor = LocalInterceptor::new(true);
        let request = interceptor
            .call(bearer_request("sia1.ignored.sig"))
            .unwrap();
        assert!(
            request
                .extensions()
                .get::<crate::enterprise::AuthenticatedContext>()
                .is_none()
        );
        assert_eq!(
            request
                .metadata()
                .get("x-principal")
                .unwrap()
                .to_str()
                .unwrap(),
            "local"
        );
    }

    #[test]
    fn insecure_tcp_interceptor_fills_context_from_assertion_bearer() {
        let authority = test_assertion_authority();
        let expires_at = chrono::Utc::now().timestamp() + 60;
        let token = authority
            .sign(&test_assertion_claims("n-insecure-tcp", expires_at))
            .unwrap();
        let mut interceptor = local_or_token_interceptor(
            Arc::new(PrincipalCredentialStore::new()),
            in_memory_db(),
            Some(Arc::new(authority)),
        );
        let mut request = bearer_request(&token);
        request.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "ApplySourceBatch",
        ));
        let request = interceptor.call(request).unwrap();
        let context = request
            .extensions()
            .get::<crate::enterprise::AuthenticatedContext>()
            .expect("insecure TCP must honor a presented assertion bearer");
        assert_eq!(context.principal.subject, "subject-a");
        assert!(context.tenant.is_none());
        assert_eq!(
            request
                .metadata()
                .get("x-principal")
                .unwrap()
                .to_str()
                .unwrap(),
            "subject-a"
        );
    }

    #[test]
    fn insecure_tcp_interceptor_rejects_assertion_tenant_header() {
        let authority = test_assertion_authority();
        let expires_at = chrono::Utc::now().timestamp() + 60;
        let token = authority
            .sign(&test_assertion_claims("n-insecure-header", expires_at))
            .unwrap();
        let mut interceptor = local_or_token_interceptor(
            Arc::new(PrincipalCredentialStore::new()),
            in_memory_db(),
            Some(Arc::new(authority)),
        );
        let mut request = bearer_request(&token);
        request.metadata_mut().insert(
            TENANT_CONTEXT_HEADER,
            MetadataValue::from_static("tenant-evil"),
        );
        let error = interceptor.call(request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "caller-selected tenant header");
    }

    #[test]
    fn local_gateway_credential_is_persisted_for_uds_authentication() {
        let db = in_memory_db();
        let socket_path = std::env::temp_dir().join(format!(
            "sekai-gateway-credential-{}.sock",
            uuid::Uuid::new_v4()
        ));
        let socket_path = socket_path.to_string_lossy().to_string();
        let token_path = format!("{socket_path}.gateway-token");

        ensure_local_gateway_credential(&socket_path, &db).unwrap();
        let token = std::fs::read_to_string(&token_path).unwrap();
        let credential = db
            .get_principal_credential(&hash_gateway_key(token.trim()))
            .unwrap()
            .unwrap();
        assert_eq!(credential.principal, "chisei-gateway");

        std::fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn tls_policy_rejects_bind_without_certs() {
        let config = base_config();
        let err = tls_policy("0.0.0.0", &config).unwrap_err();
        assert!(err.contains("SEKAI_TLS_CERT"));
    }

    #[test]
    fn tls_policy_allows_plain_bind_with_plaintext_override() {
        let mut config = base_config();
        config.allow_plaintext = true;
        assert!(tls_policy("0.0.0.0", &config).is_ok());
    }

    #[test]
    fn plane_interceptor_rejects_the_other_service() {
        let mut interceptor = with_plane(
            ProcessPlane::Sekai,
            ProcessPlane::Chisei,
            LocalInterceptor::new(true),
        );
        let error = interceptor.call(Request::new(())).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("wrong-plane"));
        let mut allowed = with_plane(
            ProcessPlane::Sekai,
            ProcessPlane::Sekai,
            LocalInterceptor::new(true),
        );
        assert!(allowed.call(Request::new(())).is_ok());
    }

    fn dest_pair_layout(dir: &tempfile::TempDir) -> CombinedStoreLayout {
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        crate::combined_stores::CombinedStoreSources {
            backend: Some(crate::runtime_backend::BackendIdentity::Sqlite),
            default_sqlite_path: sekai.to_str().unwrap().into(),
            sekai_sqlite_path: Some(sekai.to_str().unwrap().into()),
            chisei_sqlite_path: Some(chisei.to_str().unwrap().into()),
            postgres_max_connections: 16,
            ..crate::combined_stores::CombinedStoreSources::default()
        }
        .open()
        .unwrap()
    }

    #[test]
    fn restore_fence_refuses_mutating_rpc_until_restamp() {
        let dir = tempfile::tempdir().unwrap();
        let layout = dest_pair_layout(&dir);
        crate::store_relocate::align_split_generations(&layout).unwrap();
        crate::store_relocate::write_runtime_generation(&layout.sekai_runtime(), 3).unwrap();
        crate::store_relocate::write_runtime_generation(&layout.chisei_runtime(), 4).unwrap();
        let stores = Arc::new(layout);
        let mut interceptor = with_restore_fence(stores.clone(), LocalInterceptor::new(true));
        let mut mutating = Request::new(());
        mutating.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "SubmitActionInstance",
        ));
        let error = interceptor.call(mutating).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("restamp"), "{}", error.message());

        let mut preview = Request::new(());
        preview.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "PreviewObjectAction",
        ));
        let preview_error = interceptor.call(preview).unwrap_err();
        assert_eq!(preview_error.code(), tonic::Code::FailedPrecondition);
        assert!(
            preview_error.message().contains("restamp"),
            "{}",
            preview_error.message()
        );

        let mut reading = Request::new(());
        reading.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "GetActionInstance",
        ));
        assert!(interceptor.call(reading).is_ok());

        let mut describe = Request::new(());
        describe.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "DescribeObjectAction",
        ));
        assert!(interceptor.call(describe).is_ok());

        crate::store_relocate::restamp_split_generation(&stores).unwrap();
        let mut after = Request::new(());
        after.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "SubmitActionInstance",
        ));
        assert!(interceptor.call(after).is_ok());
    }
}

#[cfg(test)]
mod device_proof_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer as _;
    use prost::Message as _;

    const METHOD: &str = "/sekai.v1.Sekai/GetObject";

    fn request(
        device: Option<&ed25519_dalek::SigningKey>,
        proof: Option<String>,
    ) -> tonic::Request<sekai_proto::sekai::GetObjectRequest> {
        let mut context = crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "device-user".into(),
                credential_id: "credential".into(),
            },
        );
        context.device = device.map(|key| crate::enterprise::AuthenticatedDevice {
            id: "device-7".into(),
            public_key: key.verifying_key().to_bytes(),
            assertion_nonce: "nonce-1".into(),
            wipe: false,
        });
        let mut request = tonic::Request::new(sekai_proto::sekai::GetObjectRequest {
            id: "object-1".into(),
        });
        request.extensions_mut().insert(context);
        if let Some(proof) = proof {
            request
                .metadata_mut()
                .insert(DEVICE_PROOF_HEADER, proof.parse().unwrap());
        }
        request
    }

    fn proof(
        key: &ed25519_dalek::SigningKey,
        message: &sekai_proto::sekai::GetObjectRequest,
    ) -> String {
        let digest = crate::identity_assertion::request_digest(METHOD, &message.encode_to_vec());
        let input = crate::identity_assertion::device_proof_input("nonce-1", &digest);
        URL_SAFE_NO_PAD.encode(key.sign(&input).to_bytes())
    }

    #[test]
    fn the_hook_checks_the_proof_over_the_request_it_guards() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let message = request(None, None).into_inner();
        let valid = request(Some(&key), Some(proof(&key, &message)));
        assert!(require_device_proof(&valid, METHOD, true).is_ok());
        let other = sekai_proto::sekai::GetObjectRequest {
            id: "object-2".into(),
        };
        let mismatched = request(Some(&key), Some(proof(&key, &other)));
        assert_eq!(
            require_device_proof(&mismatched, METHOD, false)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert!(require_device_proof(&request(Some(&key), None), METHOD, false).is_err());
        assert!(require_device_proof(&request(None, None), METHOD, false).is_ok());
        assert!(require_device_proof(&request(None, None), METHOD, true).is_err());
    }
}
