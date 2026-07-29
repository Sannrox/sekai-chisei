pub mod chisei_service;
pub mod client;
mod llm_service;
pub mod sekai_service;

pub mod pb {
    pub(super) use sekai_proto::llm;
    pub use sekai_proto::{chisei, sekai};
}

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::chisei::budget::BudgetTracker;
use crate::config::{Config, GrpcTcpMode};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::PrincipalCredential;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::gateway_keys::hash_gateway_key;
use crate::obs::grpc_layer::MetricsLayer;
use crate::runtime_backend::RuntimeBackend;
use crate::sekai::credentials::PrincipalCredentialStore;
use axum::response::IntoResponse;
use std::convert::Infallible;
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::server::NamedService;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Status, metadata::MetadataValue};
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

const AUTH_SOURCE_HEADER: &str = "x-sekai-auth-source";
const CREDENTIAL_ID_HEADER: &str = "x-sekai-credential-id";
const TENANT_CONTEXT_HEADER: &str = "x-sekai-tenant-id";
/// Caller metadata that the community authentication boundary accepts as
/// authority-bearing. Tenant hints are stripped and therefore absent here.
pub const COMMUNITY_ACCEPTED_AUTHORITY_METADATA_KEYS: &[&str] = &["authorization", "x-principal"];

#[derive(Clone)]
pub struct TokenAuthInterceptor {
    store: Arc<PrincipalCredentialStore>,
    db: Arc<RuntimeDb>,
    legacy_root_token: Option<String>,
}

impl TokenAuthInterceptor {
    pub fn new(
        store: Arc<PrincipalCredentialStore>,
        db: Arc<RuntimeDb>,
        legacy_root_token: Option<String>,
    ) -> Self {
        Self {
            store,
            db,
            legacy_root_token,
        }
    }

    /// Resolve a raw bearer token to an active principal credential.
    ///
    /// Rechecks durable state on every call so rotation/revocation cannot be
    /// bypassed by a stale process-local cache. Used by gRPC interceptors and
    /// the authenticated operator console.
    pub fn resolve_credential(&self, token: &str) -> Option<PrincipalCredential> {
        self.store.maybe_reload(&self.db);
        let token_hash = hash_gateway_key(token);

        if let Some(principal) = self.legacy_root_token.as_ref()
            && token.as_bytes().ct_eq(principal.as_bytes()).into()
        {
            return Some(PrincipalCredential {
                id: "legacy-root".into(),
                principal: "root".into(),
                token_hash,
                status: "active".into(),
                created: 0,
                rotated_at: 0,
                revoked_at: 0,
                tenant_id: String::new(),
            });
        }

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

impl tonic::service::Interceptor for TokenAuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let Some(token) = Self::parse_bearer_token(req.metadata()) else {
            reject_unauthorized();
            return Err(Status::unauthenticated("missing authorization"));
        };

        let enterprise_result = self
            .db
            .enterprise_extension()
            .map(|extension| extension.authenticate_context(&token));
        let (principal, credential_id, authenticated_context, enterprise_scoped) =
            match enterprise_result {
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
                    (
                        context.principal.subject.clone(),
                        context.principal.credential_id.clone(),
                        context,
                        true,
                    )
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
                        principal.subject.clone(),
                        principal.credential_id.clone(),
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
            | "GuardedCreateObject"
            | "GetObject"
            | "UpdateObject"
            | "GuardedUpdateObject"
            | "DeleteObject"
            | "GuardedDeleteObject"
            | "ListObjects"
            | "FindByExternalId"
            | "FindByProperty"
            | "ResolveObjectSet"
            | "CreateLink"
            | "DeleteLink"
            | "GetLinks"
            | "GetLinkedObjects"
            | "Traverse"
            | "ListObjectChanges"
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
        Self::new(false)
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
    backend: Arc<RuntimeBackend>,
    active_credentials: Vec<PrincipalCredential>,
    tcp_mode: GrpcTcpMode,
) -> Result<
    impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
    Box<dyn std::error::Error>,
> {
    // This setup deliberately executes when `run` is called, before the
    // returned future is polled. The PostgreSQL backend uses synchronous
    // clients, so service construction must not acquire or release them from
    // inside Tokio.
    let (db, provider_registry_state_path, credential_store, (sekai_svc, chisei_svc)) =
        (|| -> Result<_, std::io::Error> {
            backend
                .capabilities()
                .validate_required(crate::runtime_backend::COMMUNITY_REQUIRED_SURFACES)
                .map_err(std::io::Error::other)?;
            let db = backend.database();
            let provider_registry_state_path =
                crate::provider_profile::provider_registry_state_path(&config.db_path);
            let credential_store = Arc::new(PrincipalCredentialStore::new());
            credential_store.load(&active_credentials);

            if let Some(socket_path) = config.sekai_socket.as_deref() {
                ensure_local_gateway_credential(socket_path, &db)?;
            }
            let services = build_services(&config, db.clone());
            Ok((db, provider_registry_state_path, credential_store, services))
        })()?;

    Ok(async move {
        spawn_service_background_tasks(&config, db.clone(), &sekai_svc, &chisei_svc);

        if let Some(ops_port) = config.ops_port {
            crate::obs::ops::bind_and_spawn(
                &config.ops_bind,
                ops_port,
                db.clone(),
                provider_registry_state_path.clone(),
                credential_store.clone(),
                config.auth_token.clone(),
            )
            .await?;
        }

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        spawn_health_reporter(health_reporter, db.clone(), provider_registry_state_path);

        if let Some(socket_path) = config.sekai_socket.clone() {
            let uds_server = serve_uds(
                socket_path,
                sekai_svc.clone(),
                chisei_svc.clone(),
                LocalOrTokenAuthInterceptor {
                    local: LocalInterceptor::new(false),
                    token: TokenAuthInterceptor::new(
                        credential_store.clone(),
                        db.clone(),
                        config.auth_token.clone(),
                    ),
                },
                health_service.clone(),
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
                    health_service,
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
                "SEKAI_AUTH_TOKEN must be set, or set SEKAI_INSECURE=1 for local dev",
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
            health_service,
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
    health_service: H,
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
            TokenAuthInterceptor::new(credential_store, db, config.auth_token.clone()),
            health_service,
        )
        .await
    } else {
        serve_tcp_listener(
            bind_addr,
            port,
            config,
            sekai_svc,
            chisei_svc,
            LocalInterceptor::new(true),
            health_service,
        )
        .await
    }
}

#[allow(clippy::future_not_send)]
async fn serve_tcp_listener<I, H>(
    bind_addr: &str,
    port: u16,
    config: &Config,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    interceptor: I,
    health_service: H,
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
            pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc.clone()),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(chisei_svc.clone()),
            interceptor,
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
    tracing::info!(socket_path, "gRPC server listening on UDS");

    Ok(tonic::transport::Server::builder()
        .layer(MetricsLayer)
        .add_service(health_service)
        .add_service(InterceptedService::new(
            pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc.clone()),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(chisei_svc.clone()),
            interceptor,
        ))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?)
}

fn build_services(
    config: &Config,
    db: Arc<RuntimeDb>,
) -> (
    Arc<sekai_service::SekaiServiceImpl>,
    Arc<chisei_service::ChiseiServiceImpl>,
) {
    let budget = Arc::new(BudgetTracker::with_topology(
        db.clone(),
        config.budget_topology.clone(),
    ));
    let sekai_svc = Arc::new(
        sekai_service::SekaiServiceImpl::with_budget_and_gateway_schema_principals(
            db.clone(),
            budget.clone(),
            config.gateway_receipt_principals.clone(),
        )
        .with_site_id(config.site_id.clone()),
    );
    let chisei_svc = Arc::new(chisei_service::ChiseiServiceImpl::with_budget(
        db.clone(),
        config.clone(),
        budget,
    ));

    (sekai_svc, chisei_svc)
}

fn spawn_service_background_tasks(
    config: &Config,
    db: Arc<RuntimeDb>,
    sekai_svc: &Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: &Arc<chisei_service::ChiseiServiceImpl>,
) {
    if config.scoring_enabled {
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
    spawn_execution_evidence_reconciler(db);
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
        let backend = Arc::new(
            RuntimeBackend::from_sqlite_with_enterprise_extension(":memory:", None).unwrap(),
        );
        let tcp_mode = GrpcTcpMode {
            bind_addr: "127.0.0.1".into(),
            token_auth_mode: false,
            auth_configured: false,
            bind_inferred_from_active_credentials: false,
        };

        let result = run(config, backend, Vec::new(), tcp_mode);

        assert!(result.is_err());
    }

    #[test]
    fn token_auth_interceptor_enforces_missing_authorization() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor =
            TokenAuthInterceptor::new(store, db, Some("legacy-root-token".to_string()));

        let request = Request::new(());
        assert!(interceptor.call(request).is_err());
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
            TokenAuthInterceptor::new(Arc::new(PrincipalCredentialStore::new()), db, None);
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
            TokenAuthInterceptor::new(Arc::new(PrincipalCredentialStore::new()), db, None);
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
    fn enterprise_allowlist_includes_lease_guarded_mutations() {
        for method in [
            "GuardedCreateObject",
            "GuardedUpdateObject",
            "GuardedDeleteObject",
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

        let mut interceptor = TokenAuthInterceptor::new(
            Arc::new(store),
            db.clone(),
            Some("legacy-root-token".to_string()),
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
    #[cfg(any())]
    fn tenant_scoped_credentials_fail_closed_on_uncovered_rpcs() {
        let db = in_memory_db();
        let store = PrincipalCredentialStore::new();
        let token = hash_gateway_key("tenant-client-token");
        let tenant = db.create_tenant("root", "tenant-auth-a", 1).unwrap();
        db.create_tenant_credential(&tenant.id, "agent-a", &token, "root", true, 2)
            .unwrap();
        store.load(&db.list_active_credentials().unwrap());
        let mut interceptor = TokenAuthInterceptor::new(Arc::new(store), db, None);
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer tenant-client-token"),
        );
        request.extensions_mut().insert(tonic::GrpcMethod::new(
            "sekai.SekaiService",
            "ExecuteFunction",
        ));
        assert_eq!(
            interceptor.call(request).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    #[cfg(any())]
    fn token_auth_interceptor_derives_tenant_from_credential_and_overwrites_forgery() {
        let db = in_memory_db();
        let store = PrincipalCredentialStore::new();
        let token = hash_gateway_key("tenant-client-token");
        let tenant = db.create_tenant("root", "tenant-auth-b", 1).unwrap();
        db.create_tenant_credential(&tenant.id, "agent-a", &token, "root", true, 2)
            .unwrap();
        store.load(&db.list_active_credentials().unwrap());
        let mut interceptor = TokenAuthInterceptor::new(Arc::new(store), db, None);

        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer tenant-client-token"),
        );
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
                .get(TENANT_CONTEXT_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            tenant.id.as_str()
        );
    }

    #[test]
    fn token_auth_interceptor_supports_legacy_root_token() {
        let db = in_memory_db();
        let store = Arc::new(PrincipalCredentialStore::new());
        let mut interceptor =
            TokenAuthInterceptor::new(store, db, Some("legacy-root-token".to_string()));

        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("legacy-root-token"),
        );
        let request = interceptor.call(request).unwrap();

        assert_eq!(
            request
                .metadata()
                .get("x-principal")
                .unwrap()
                .to_str()
                .unwrap(),
            "root"
        );
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
            local: LocalInterceptor::new(false),
            token: TokenAuthInterceptor::new(Arc::new(store), db, None),
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
}
