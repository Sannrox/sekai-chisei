pub mod chisei_service;
pub mod client;
mod llm_service;
pub mod sekai_service;

pub mod pb {
    pub mod sekai {
        tonic::include_proto!("sekai");
    }
    pub mod chisei {
        tonic::include_proto!("chisei");
    }
    pub(super) mod llm {
        tonic::include_proto!("llm");
    }
}

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::chisei::budget::BudgetTracker;
use crate::config::{Config, GrpcTcpMode};
use crate::db::sekai::{PrincipalCredential, SekaiDb};
use crate::gateway_keys::hash_gateway_key;
use crate::obs::grpc_layer::MetricsLayer;
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

#[derive(Clone)]
pub struct TokenAuthInterceptor {
    store: Arc<PrincipalCredentialStore>,
    db: Arc<SekaiDb>,
    legacy_root_token: Option<String>,
}

impl TokenAuthInterceptor {
    pub fn new(
        store: Arc<PrincipalCredentialStore>,
        db: Arc<SekaiDb>,
        legacy_root_token: Option<String>,
    ) -> Self {
        Self {
            store,
            db,
            legacy_root_token,
        }
    }

    fn resolve_principal(&self, token: &str) -> Option<String> {
        let cache_trustworthy = self.store.maybe_reload(&self.db);
        let token_hash = hash_gateway_key(token);
        let cached_principal = self.store.resolve(token);

        if let Some(principal) = self.legacy_root_token.as_ref()
            && token.as_bytes().ct_eq(principal.as_bytes()).into()
        {
            return Some("root".to_string());
        }

        if let Some(cached_principal) = cached_principal
            && cache_trustworthy
        {
            return Some(cached_principal);
        }

        match self.db.get_principal_credential(&token_hash) {
            Ok(Some(credential)) => {
                self.store.load_credential(&credential);
                Some(credential.principal)
            }
            Ok(None) => None,
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

impl tonic::service::Interceptor for TokenAuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let Some(token) = Self::parse_bearer_token(req.metadata()) else {
            return Err(Status::unauthenticated("missing authorization"));
        };

        let principal = self
            .resolve_principal(&token)
            .ok_or_else(|| Status::unauthenticated("invalid token"))?;

        while req.metadata_mut().remove("x-principal").is_some() {}
        req.metadata_mut().insert(
            "x-principal",
            MetadataValue::from_str(&principal)
                .map_err(|_| Status::unauthenticated("invalid principal metadata value"))?,
        );
        Ok(req)
    }
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

impl tonic::service::Interceptor for LocalInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
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

pub async fn run(
    config: Config,
    db: Arc<SekaiDb>,
    active_credentials: Vec<PrincipalCredential>,
    tcp_mode: GrpcTcpMode,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ops_port) = config.ops_port {
        crate::obs::ops::bind_and_spawn(&config.ops_bind, ops_port, db.clone()).await?;
    }

    let credential_store = Arc::new(PrincipalCredentialStore::new());
    credential_store.load(&active_credentials);

    let (sekai_svc, chisei_svc) = build_services(&config, db.clone());
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    spawn_health_reporter(health_reporter, db.clone());

    if let Some(socket_path) = config.sekai_socket.clone() {
        let uds_server = serve_uds(
            socket_path,
            sekai_svc.clone(),
            chisei_svc.clone(),
            LocalInterceptor::new(false),
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
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp<H>(
    port: u16,
    config: &Config,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    tcp_mode: &GrpcTcpMode,
    credential_store: Arc<PrincipalCredentialStore>,
    db: Arc<SekaiDb>,
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
    db: Arc<SekaiDb>,
) -> (
    Arc<sekai_service::SekaiServiceImpl>,
    Arc<chisei_service::ChiseiServiceImpl>,
) {
    let budget = Arc::new(BudgetTracker::new());
    let sekai_svc = Arc::new(sekai_service::SekaiServiceImpl::with_budget(
        db.clone(),
        budget.clone(),
    ));
    let chisei_svc = Arc::new(chisei_service::ChiseiServiceImpl::with_budget(
        db,
        config.clone(),
        budget,
    ));

    if config.scoring_enabled {
        tracing::info!(
            model = %config.scoring_model,
            interval_secs = config.scoring_interval_secs,
            batch_size = config.scoring_batch_size,
            "scoring job enabled"
        );
        tokio::spawn(chisei_svc.scoring_job().run_loop());
    }

    (sekai_svc, chisei_svc)
}

fn spawn_health_reporter(health_reporter: HealthReporter, db: Arc<SekaiDb>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            let ready = tokio::task::spawn_blocking({
                let db = db.clone();
                move || db.ping().is_ok()
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

    fn in_memory_db() -> Arc<SekaiDb> {
        Arc::new(SekaiDb::new(":memory:").unwrap())
    }

    fn base_config() -> Config {
        let mut config = Config::from_env();
        config.tls_cert = None;
        config.tls_key = None;
        config.allow_plaintext = false;
        config
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
