pub mod chisei_service;
pub use sekai_admin_client::client;
mod provider_execution;
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
use crate::gateway_keys::hash_gateway_key;
use crate::obs::grpc_layer::MetricsLayer;
use crate::plane::ProcessPlane;
use crate::rpc_maturity::RpcMaturityLayer;
use crate::sekai::credentials::PrincipalCredentialStore;
use axum::response::IntoResponse;
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

#[derive(Clone)]
pub struct TokenAuthInterceptor {
    store: Arc<PrincipalCredentialStore>,
    db: crate::db::store::SekaiStore,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
}

impl TokenAuthInterceptor {
    pub fn new(
        store: Arc<PrincipalCredentialStore>,
        db: impl Into<crate::db::store::SekaiStore>,
    ) -> Self {
        Self {
            store,
            db: db.into(),
            assertion_authority: None,
        }
    }

    pub fn with_assertion_authority(
        mut self,
        assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        self.assertion_authority = assertion_authority;
        self
    }

    pub fn from_runtime(
        store: Arc<PrincipalCredentialStore>,
        db: impl Into<crate::db::store::SekaiStore>,
        assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        Self::new(store, db).with_assertion_authority(assertion_authority)
    }

    pub fn from_config(
        store: Arc<PrincipalCredentialStore>,
        db: Arc<RuntimeDb>,
        config: &Config,
    ) -> Result<Self, String> {
        Ok(Self::from_runtime(
            store,
            db,
            config.assertion_authority()?.map(Arc::new),
        ))
    }

    /// Resolve a raw bearer token to an active principal credential.
    ///
    /// Rechecks durable state on every call so rotation/revocation cannot be
    /// bypassed by a stale process-local cache. Used by gRPC interceptors and
    /// the authenticated operator console.
    pub fn resolve_credential(&self, token: &str) -> Option<PrincipalCredential> {
        self.store.maybe_reload(&self.db);
        let token_hash = hash_gateway_key(token);

        // Recheck durable state for every authentication. The cache accelerates
        // startup discovery but never extends a rotated or revoked credential.
        match self.db.get_principal_credential(&token_hash) {
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
    }
}

fn finish_authenticated(
    mut req: Request<()>,
    authenticated_context: crate::enterprise::AuthenticatedContext,
    enterprise_scoped: bool,
) -> Result<Request<()>, Status> {
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
        let method = req
            .extensions()
            .get::<tonic::GrpcMethod<'_>>()
            .map(|method| method.method());
        if method.is_none_or(|method| !enterprise_namespace_method(method)) {
            return Err(Status::permission_denied(
                "RPC is not available to enterprise-scoped credentials",
            ));
        }
    }
    req.extensions_mut().insert(authenticated_context);
    Ok(req)
}

impl tonic::service::Interceptor for TokenAuthInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let Some(token) = Self::parse_bearer_token(req.metadata()) else {
            reject_unauthorized();
            return Err(Status::unauthenticated("missing authorization"));
        };
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
                    let enterprise_scoped = authenticated_context.tenant.is_some();
                    return finish_authenticated(req, authenticated_context, enterprise_scoped);
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
            .enterprise_extension()
            .map(|extension| extension.authenticate_context(&token));
        let (authenticated_context, enterprise_scoped) = match enterprise_result {
            Some(Ok(context)) => {
                let extension_version = self
                    .db
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
            Some(Err(crate::enterprise::ExtensionError::CredentialNotFound)) | None => {
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
        finish_authenticated(req, authenticated_context, enterprise_scoped)
    }
}

fn valid_single_principal(principal: &str) -> bool {
    !principal.is_empty() && principal.trim() == principal && !principal.contains(',')
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
            | "ListObjectChanges"
            | "GetGovernedFactVersion"
            | "ResolveInvariantSet"
            | "PlanExecution"
            | "ExecutePlanStream"
            | "PlanContentExecution"
            | "ExecuteContentPlanStream"
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
        if req.metadata().get("authorization").is_some() {
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
            crate::store_relocate::refuse_mutating_if_generation_mismatch(&self.stores)
                .map_err(Status::failed_precondition)?;
        }
        self.inner.call(req)
    }
}

fn request_is_mutating_rpc<T>(req: &Request<T>) -> bool {
    req.extensions()
        .get::<tonic::GrpcMethod>()
        .map(|method| crate::store_relocate::is_mutating_rpc(method.method()))
        .unwrap_or(false)
}

fn local_or_token_interceptor(
    credential_store: Arc<PrincipalCredentialStore>,
    db: Arc<RuntimeDb>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
) -> LocalOrTokenAuthInterceptor {
    LocalOrTokenAuthInterceptor {
        local: LocalInterceptor::new(true),
        token: TokenAuthInterceptor::from_runtime(credential_store, db, assertion_authority),
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

        if let Some(socket_path) = config.sekai_socket.as_deref() {
            ensure_local_gateway_credential(socket_path, &db)?;
        }
        let assertion_authority = config
            .assertion_authority()
            .map_err(std::io::Error::other)?
            .map(Arc::new);
        let services = build_services_for_plane(&config, &stores, plane);
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

        if let Some(ops_port) = config.ops_port {
            crate::obs::ops::bind_and_spawn(
                &config.ops_bind,
                ops_port,
                db.clone(),
                Some(chisei_db.clone()),
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
                        db.clone(),
                        assertion_authority.clone(),
                    ),
                    stores.clone(),
                )
                .await?;
            } else {
                crate::http_projection::bind_and_spawn(
                    &config.http_bind,
                    http_port,
                    sekai_svc.clone(),
                    chisei_svc.clone(),
                    local_or_token_interceptor(
                        credential_store.clone(),
                        db.clone(),
                        assertion_authority.clone(),
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
                local_or_token_interceptor(
                    credential_store.clone(),
                    db.clone(),
                    assertion_authority.clone(),
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
            TokenAuthInterceptor::from_runtime(credential_store, db, assertion_authority),
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
            local_or_token_interceptor(credential_store, db, assertion_authority),
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
        .add_service(InterceptedService::new(
            RpcMaturityLayer::from_env().layer(
                pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc.clone()),
            ),
            with_restore_fence(
                stores.clone(),
                with_plane(plane, ProcessPlane::Sekai, interceptor.clone()),
            ),
        ))
        .add_service(InterceptedService::new(
            RpcMaturityLayer::from_env().layer(
                pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(
                    chisei_svc.clone(),
                ),
            ),
            with_restore_fence(stores, with_plane(plane, ProcessPlane::Chisei, interceptor)),
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
        .add_service(InterceptedService::new(
            RpcMaturityLayer::from_env().layer(
                pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc.clone()),
            ),
            with_restore_fence(
                stores.clone(),
                with_plane(plane, ProcessPlane::Sekai, interceptor.clone()),
            ),
        ))
        .add_service(InterceptedService::new(
            RpcMaturityLayer::from_env().layer(
                pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(
                    chisei_svc.clone(),
                ),
            ),
            with_restore_fence(stores, with_plane(plane, ProcessPlane::Chisei, interceptor)),
        ))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?)
}

pub fn build_services(
    config: &Config,
    stores: &CombinedStoreLayout,
) -> (
    Arc<sekai_service::SekaiServiceImpl>,
    Arc<chisei_service::ChiseiServiceImpl>,
) {
    build_services_for_plane(config, stores, ProcessPlane::Combined)
}

pub fn build_services_for_plane(
    config: &Config,
    stores: &CombinedStoreLayout,
    plane: ProcessPlane,
) -> (
    Arc<sekai_service::SekaiServiceImpl>,
    Arc<chisei_service::ChiseiServiceImpl>,
) {
    let (sekai_store, chisei_store) = stores.handles();
    let budget = Arc::new(BudgetTracker::with_topology(
        chisei_store.clone(),
        config.budget_topology.clone(),
    ));
    let mut sekai_svc = sekai_service::SekaiServiceImpl::with_budget_and_gateway_schema_principals(
        sekai_store.clone(),
        budget.clone(),
        config.gateway_receipt_principals.clone(),
    )
    .with_site_id(config.site_id.clone());
    if plane == ProcessPlane::Combined {
        let clerk = Arc::new(
            crate::chisei::cross_store_admission::CrossStoreAdmission::new(
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
            chisei_svc = chisei_svc.with_sekai_commit_lookup(Arc::new(sekai_store));
        }
        ProcessPlane::Chisei => {
            if let Some(endpoint) = &config.sekai_endpoint {
                chisei_svc = chisei_svc.with_sekai_commit_lookup(Arc::new(
                    crate::chisei::remote_sekai::RemoteSekaiCommitLookup::from_env(
                        endpoint.clone(),
                    ),
                ));
            }
        }
        ProcessPlane::Sekai => {}
    }

    (Arc::new(sekai_svc), Arc::new(chisei_svc))
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
        spawn_execution_evidence_reconciler(db);
    }
    if plane == ProcessPlane::Combined
        && let Some(clerk) = &sekai_svc.cross_store
    {
        spawn_admission_reconciler(clerk.clone());
    }
}

fn spawn_admission_reconciler(
    clerk: Arc<crate::chisei::cross_store_admission::CrossStoreAdmission>,
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

fn execution_evidence_runtime(stores: &CombinedStoreLayout) -> Arc<RuntimeDb> {
    stores.sekai_runtime()
}

fn spawn_execution_evidence_reconciler(db: Arc<RuntimeDb>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let db = db.clone();
            let result = tokio::task::spawn_blocking(move || {
                db.reconcile_missing_execution_evidence(chrono::Utc::now().timestamp_millis())
            })
            .await;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::error!(%error, "execution evidence reconciliation failed")
                }
                Err(error) => {
                    tracing::error!(%error, "execution evidence reconciliation task failed")
                }
            }
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
        let (sekai_svc, chisei_svc) = build_services(&crate::config::Config::from_env(), &layout);
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
        let mut interceptor = TokenAuthInterceptor::new(store, db);

        let request = Request::new(());
        assert!(interceptor.call(request).is_err());
    }

    #[test]
    fn token_auth_interceptor_rejects_assertion_with_caller_tenant_header() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor = TokenAuthInterceptor::new(store, db);
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
        let mut interceptor = TokenAuthInterceptor::new(store, db);
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
            tenant_id: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            expires_at,
            nonce: nonce.into(),
        }
    }

    fn interceptor_with_authority(
        authority: crate::identity_assertion::AssertionAuthority,
    ) -> TokenAuthInterceptor {
        TokenAuthInterceptor::from_runtime(
            Arc::new(PrincipalCredentialStore::new()),
            in_memory_db(),
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
            in_memory_db(),
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
                    tenant: Some(self.tenant_context(&principal)?),
                    principal,
                    credential_kind: crate::enterprise::CredentialKind::HumanSession,
                    scopes: vec!["sekai.read".into()],
                    issuer: "https://issuer.test".into(),
                    resource: "https://sekai.test".into(),
                    expires_at: self.expires_at,
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
        let mut interceptor =
            TokenAuthInterceptor::new(Arc::new(PrincipalCredentialStore::new()), db);
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
        let mut interceptor =
            TokenAuthInterceptor::new(Arc::new(PrincipalCredentialStore::new()), db);
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

    #[test]
    fn enterprise_allowlist_includes_governed_facts_and_native_execution() {
        for method in [
            "GetGovernedFactVersion",
            "ResolveInvariantSet",
            "PlanExecution",
            "ExecutePlanStream",
        ] {
            assert!(enterprise_namespace_method(method));
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

        let mut interceptor = TokenAuthInterceptor::new(Arc::new(store), db.clone());

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
            token: TokenAuthInterceptor::new(Arc::new(store), db),
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
            token: TokenAuthInterceptor::new(Arc::new(store), db),
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

        let mut reading = Request::new(());
        reading.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "GetActionInstance",
        ));
        assert!(interceptor.call(reading).is_ok());

        crate::store_relocate::restamp_split_generation(&stores).unwrap();
        let mut after = Request::new(());
        after.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "SubmitActionInstance",
        ));
        assert!(interceptor.call(after).is_ok());
    }
}
