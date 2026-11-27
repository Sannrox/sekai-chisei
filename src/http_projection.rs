//! HTTP/JSON projection of stable gRPC (#875, ADR 0075).
//!
//! Routes are the proto service paths. Bodies are proto3 JSON of the same
//! messages. Authorization, maturity, and hidden-row rules stay on the
//! existing interceptors and service impls. Streaming RPCs stay on gRPC.
//!
//! The listener serves TLS with the gRPC certificate when `SEKAI_TLS_CERT` and
//! `SEKAI_TLS_KEY` are set (#3172). `/mcp` is served only over TLS or on a
//! loopback bind, and each MCP tool call is authorized by the interceptor
//! against that tool's RPC path, as on gRPC.

use std::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::{Request, Status};
use tracing::{error, info, warn};

use crate::combined_stores::CombinedStoreLayout;
use crate::config::{Config, GrpcTcpMode};
use crate::grpc::chisei_service::ChiseiServiceImpl;
use crate::grpc::pb::chisei::chisei_service_server::ChiseiService;
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::mcp_adapter::{NativeSurface, handle_message};
use crate::rpc_maturity::{self, experimental_rpcs_enabled};

pub const HTTP_PROJECTION_CONTRACT: &str = "sekai.http-projection/v1";
pub const DEFAULT_HTTP_PORT: u16 = 50080;
pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const STREAMING_MESSAGE: &str = "streaming RPCs stay on gRPC";

const FORWARDED_HEADERS: &[&str] = &[
    "authorization",
    "x-sekai-namespace",
    "x-sekai-capability",
    "x-sekai-operation-id",
    "x-sekai-purpose",
    "x-chisei-work-unit",
    "x-sekai-catalog-version",
    "x-sekai-definition-revision",
    "x-chisei-request-id",
    "x-principal",
];

#[derive(Clone)]
pub struct HttpProjectionState<I> {
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    interceptor: I,
    stores: Option<Arc<CombinedStoreLayout>>,
    /// Why `/mcp` is refused on this listener, when it is.
    mcp_refusal: Option<&'static str>,
}

/// `/mcp` carries bearer credentials, so it is refused on a plaintext
/// listener that is reachable beyond loopback, even when the RPC routes run
/// there under `SEKAI_ALLOW_PLAINTEXT=1`.
const MCP_NEEDS_TLS: &str =
    "MCP on a non-loopback HTTP listener requires TLS; set SEKAI_TLS_CERT and SEKAI_TLS_KEY";

/// The RPC path `/mcp` authenticates before any tool runs: listing tools reads
/// the namespace's capability catalog.
const MCP_DOOR_RPC: &str = "/sekai.SekaiService/DiscoverCapabilities";

pub fn should_bind(config: &Config, tcp_mode: &GrpcTcpMode) -> bool {
    config.http_port.is_some() && (tcp_mode.token_auth_mode || config.insecure)
}

/// Refuse a bind that would put credentials on the network unprotected. A
/// non-loopback bind needs TLS, or `SEKAI_ALLOW_PLAINTEXT=1` for the RPC routes
/// only (`/mcp` stays refused there).
pub fn validate_bind(bind: &str, config: &Config) -> Result<(), String> {
    if is_loopback(bind) {
        return Ok(());
    }
    if config.insecure {
        return Err("SEKAI_HTTP_BIND must be loopback when SEKAI_INSECURE=1".into());
    }
    if tls_configured(config) || config.allow_plaintext {
        return Ok(());
    }
    Err("non-loopback HTTP projection requires TLS (SEKAI_TLS_CERT and SEKAI_TLS_KEY) or SEKAI_ALLOW_PLAINTEXT=1".into())
}

/// Whether the projection serves TLS: the gRPC certificate and key are both
/// set. A half-set pair is refused by the gRPC listener's own policy.
pub fn tls_configured(config: &Config) -> bool {
    let set = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
    set(&config.tls_cert) && set(&config.tls_key)
}

/// The projection's TLS acceptor from the gRPC certificate and key, requiring
/// a client certificate signed by `client_ca` when one is set, as gRPC does.
/// Unreadable or invalid files fail here, before listen.
pub fn tls_acceptor(
    cert: &str,
    key: &str,
    client_ca: Option<&str>,
) -> Result<tokio_rustls::TlsAcceptor, std::io::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let invalid = |what: &str, error: &dyn std::fmt::Display| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{what}: {error}"))
    };
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|error| invalid("SEKAI_TLS_CERT", &error))?;
    let key =
        PrivateKeyDer::from_pem_file(key).map_err(|error| invalid("SEKAI_TLS_KEY", &error))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid("TLS", &error))?;
    let builder = match client_ca.filter(|path| !path.trim().is_empty()) {
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            for ca in CertificateDer::pem_file_iter(path)
                .map_err(|error| invalid("SEKAI_TLS_CLIENT_CA", &error))?
            {
                roots
                    .add(ca.map_err(|error| invalid("SEKAI_TLS_CLIENT_CA", &error))?)
                    .map_err(|error| invalid("SEKAI_TLS_CLIENT_CA", &error))?;
            }
            let verifier =
                rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider)
                    .build()
                    .map_err(|error| invalid("SEKAI_TLS_CLIENT_CA", &error))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|error| invalid("SEKAI_TLS_CERT", &error))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Why `/mcp` is refused on a listener at `bind`: plaintext beyond loopback.
fn mcp_refusal(bind: &str, tls: bool) -> Option<&'static str> {
    (!tls && !is_loopback(bind)).then_some(MCP_NEEDS_TLS)
}

fn is_loopback(bind: &str) -> bool {
    matches!(bind, "127.0.0.1" | "::1" | "localhost")
}

pub fn router<I>(state: HttpProjectionState<I>) -> Router
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/mcp", post(mcp_handler::<I>))
        .route("/{service}/{method}", post(rpc_handler::<I>))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

/// Bind the projection without TLS. See [`bind_and_spawn_with_tls`].
pub async fn bind_and_spawn<I>(
    bind: &str,
    port: u16,
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    interceptor: I,
    stores: Arc<CombinedStoreLayout>,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>>
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    bind_and_spawn_with_tls(bind, port, sekai, chisei, interceptor, stores, None).await
}

/// Bind the projection, serving TLS through `tls` when given. `/mcp` is
/// refused unless the listener has TLS or the bind is loopback.
pub async fn bind_and_spawn_with_tls<I>(
    bind: &str,
    port: u16,
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    interceptor: I,
    stores: Arc<CombinedStoreLayout>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>>
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    let listener = TcpListener::bind((bind, port)).await?;
    let addr = listener.local_addr()?;
    let mcp_refusal = mcp_refusal(bind, tls.is_some());
    if let Some(reason) = mcp_refusal {
        warn!(addr = %addr, reason, "HTTP projection refuses /mcp");
    }
    let app = router(HttpProjectionState {
        sekai,
        chisei,
        interceptor,
        stores: Some(stores),
        mcp_refusal,
    });
    info!(
        addr = %addr,
        contract = HTTP_PROJECTION_CONTRACT,
        tls = tls.is_some(),
        "HTTP/JSON projection of stable gRPC listening"
    );
    match tls {
        None => {
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, app).await {
                    error!(error = %err, "HTTP projection listener exited");
                }
            });
        }
        Some(acceptor) => {
            tokio::spawn(serve_tls(listener, acceptor, app));
        }
    }
    Ok(addr)
}

/// Accept TLS connections and serve `app` on each. A handshake runs in its own
/// task, so a slow or failed handshake never blocks the next accept.
async fn serve_tls(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor, app: Router) {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = %err, "HTTP projection accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(peer = %peer, error = %err, "HTTP projection TLS handshake failed");
                    return;
                }
            };
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .await
            {
                warn!(peer = %peer, error = %err, "HTTP projection connection ended");
            }
        });
    }
}

async fn rpc_handler<I>(
    State(state): State<HttpProjectionState<I>>,
    Path((service, method)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    let path = format!("/{service}/{method}");
    let authenticated = match authenticate(&state.interceptor, &headers, None) {
        Ok(request) => request,
        Err(status) => return status_response(status),
    };
    if crate::store_relocate::is_mutating_rpc(&method)
        && let Some(stores) = &state.stores
        && let Err(message) = crate::store_relocate::refuse_mutating_if_generation_mismatch(stores)
    {
        return status_response(Status::failed_precondition(message));
    }
    if let Err(status) = rpc_maturity::require_path(&path, experimental_rpcs_enabled()) {
        return status_response(status);
    }
    if matches!(
        method.as_str(),
        "ExecutePlanStream" | "ExecuteContentPlanStream"
    ) {
        return status_response(Status::unimplemented(STREAMING_MESSAGE));
    }
    let (metadata, extensions, ()) = authenticated.into_parts();
    dispatch(&state, &service, &method, metadata, extensions, body).await
}

async fn mcp_handler<I>(
    State(state): State<HttpProjectionState<I>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    if let Some(reason) = state.mcp_refusal {
        return status_response(Status::failed_precondition(reason));
    }
    // The door: no tool runs, and no tool is listed, for a caller the
    // interceptor refuses for the catalog read. Each tool call is then
    // authorized again for its own RPC.
    let door = match authenticate(&state.interceptor, &headers, Some(MCP_DOOR_RPC)) {
        Ok(request) => request,
        Err(status) => return status_response(status),
    };
    let authenticated = door.metadata().clone();
    let message = match serde_json::from_slice::<Value>(&body) {
        Ok(value) => value,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":error.to_string()}}),
            );
        }
    };
    let principal = metadata_str(&authenticated, "x-principal").unwrap_or_default();
    let namespace = header_str(&headers, "x-sekai-namespace").unwrap_or_default();
    if principal.is_empty() {
        return status_response(Status::unauthenticated("missing authorization"));
    }
    if namespace.is_empty() {
        return status_response(Status::invalid_argument("x-sekai-namespace is required"));
    }
    let surface = HttpMcpSurface {
        sekai: state.sekai.clone(),
        chisei: state.chisei.clone(),
        interceptor: state.interceptor.clone(),
        headers,
        door: crate::mcp_adapter::CallerIdentity::authenticated(door),
        principal,
        namespace,
    };
    match handle_message(&surface, message).await {
        Some(value) => json_response(StatusCode::OK, value),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Run the interceptor on the caller's headers. `rpc_path` is the server-chosen
/// RPC the request is authorized for; enterprise-scoped credentials are
/// refused without one.
fn authenticate<I>(
    interceptor: &I,
    headers: &HeaderMap,
    rpc_path: Option<&str>,
) -> Result<Request<()>, Status>
where
    I: Interceptor + Clone,
{
    let mut interceptor = interceptor.clone();
    let mut request = Request::from_parts(headers_to_metadata(headers), Default::default(), ());
    if let Some(path) = rpc_path {
        crate::grpc::rpc_identity::set_server_rpc_path(&mut request, path);
    }
    interceptor.call(request)
}

async fn dispatch<I>(
    state: &HttpProjectionState<I>,
    service: &str,
    method: &str,
    metadata: MetadataMap,
    extensions: http::Extensions,
    body: Bytes,
) -> Response {
    match (service, method) {
        ("sekai.SekaiService", "PutActionBinding") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_action_binding(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RunActionBinding") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::run_action_binding(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetActionBinding") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_action_binding(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListActionBindings") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_action_bindings(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListActionBindingHistory") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_action_binding_history(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AcquireLease") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::acquire_lease(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetLease") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_lease(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RefreshLease") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::refresh_lease(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReleaseLease") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::release_lease(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "TakeoverExpiredLease") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::takeover_expired_lease(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ApplySourceBatch") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::apply_source_batch(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetSourceSyncState") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_source_sync_state(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "Search") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::search(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetSearchIndexStatus") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_search_index_status(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AdmitGovernedDocument") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::admit_governed_document(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AttachGovernedDocumentRendition") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::attach_governed_document_rendition(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetGovernedDocument") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_governed_document(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "HoldGovernedDocument") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::hold_governed_document(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReleaseGovernedDocumentHold") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::release_governed_document_hold(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExpireGovernedDocument") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::expire_governed_document(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteGovernedDocument") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::delete_governed_document(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetPublishedDefinitionRevision") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_published_definition_revision(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateDefinitionBranch") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_definition_branch(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ApplyDefinitionBranchEdit") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::apply_definition_branch_edit(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateDefinitionProposal") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_definition_proposal(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CompareDefinitionRevisions") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::compare_definition_revisions(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReportDefinitionConsumerImpact") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::report_definition_consumer_impact(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetDefinitionBranch") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_definition_branch(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetDefinitionProposal") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_definition_proposal(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ApproveDefinitionProposal") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::approve_definition_proposal(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "MergeDefinitionProposal") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::merge_definition_proposal(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetDefinitionCertificationGate") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_definition_certification_gate(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListPublishedDefinitionRevisions") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_published_definition_revisions(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetDefinitionMember") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_definition_member(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetOntologyClass") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_ontology_class(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExpandNeighborhood") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::expand_neighborhood(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateObject") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetObject") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "UpdateObject") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::update_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteObject") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::delete_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListObjects") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_objects(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RetrieveContext") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::retrieve_context(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExpandRelations") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::expand_relations(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExplainDerivation") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::explain_derivation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "EvaluateObjectSet") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::evaluate_object_set(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RegisterObjectTypeDatasource") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::register_object_type_datasource(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReindexObjectType") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::reindex_object_type(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetObjectTypeIndexStatus") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_object_type_index_status(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutObjectTypeIndexEdit") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_object_type_index_edit(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReadObjectChangeSubscription") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::read_object_change_subscription(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutObjectSecurityPolicyRevision") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_object_security_policy_revision(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ActivateObjectSecurityPolicies") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::activate_object_security_policies(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetObjectSecurityActivation") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_object_security_activation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "FindByExternalId") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::find_by_external_id(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "FindByProperty") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::find_by_property(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateLink") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_link(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteLink") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::delete_link(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ApplyGraphChanges") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::apply_graph_changes(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetLinks") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_links(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "Traverse") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::traverse(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DiscoverCapabilities") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::discover_capabilities(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListSchemaTypes") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_schema_types(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateSchemaType") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_schema_type(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateOntologyClass") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_ontology_class(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateOntologyRelation") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_ontology_relation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateDataset") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_dataset(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "UpdateDataset") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::update_dataset(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AppendRows") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::append_rows(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "QueryRows") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::query_rows(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListDatasets") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_datasets(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListDatasetVersions") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_dataset_versions(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetDatasetVersion") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_dataset_version(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RollbackDataset") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::rollback_dataset(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutDatasetHealthCheck") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_dataset_health_check(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListDatasetHealthChecks") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_dataset_health_checks(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListDatasetHealthResults") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_dataset_health_results(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RunDatasetHealthChecks") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::run_dataset_health_checks(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListDatasetAlerts") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_dataset_alerts(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateGrant") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_grant(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteGrant") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::delete_grant(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListGrants") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_grants(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CheckAccess") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::check_access(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutGovernedActionType") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_governed_action_type(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "SubmitActionInstance") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::submit_action_instance(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DecideActionInstance") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::decide_action_instance(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DescribeObjectAction") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::describe_object_action(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PreviewObjectAction") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::preview_object_action(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetActionInstance") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_action_instance(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListActionInstances") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_action_instances(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetActionEffect") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_action_effect(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListActionEffects") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_action_effects(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetLineage") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_lineage(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutGovernedTransform") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_governed_transform(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListGovernedTransforms") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_governed_transforms(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PreviewGovernedTransform") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::preview_governed_transform(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RunGovernedTransform") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::run_governed_transform(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetGovernedTransformRun") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_governed_transform_run(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListGovernedTransformRuns") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_governed_transform_runs(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CancelGovernedTransformRun") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::cancel_governed_transform_run(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetTransformOutputState") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_transform_output_state(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "TickGovernedTransforms") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::tick_governed_transforms(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutTransformChain") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::put_transform_chain(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RunTransformChain") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::run_transform_chain(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetTransformChainRun") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::get_transform_chain_run(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateCredential") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::create_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RotateCredential") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::rotate_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RevokeCredential") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::revoke_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListCredentials") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_credentials(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RegisterEvidenceSchema") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::register_evidence_schema(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "SubmitEvidence") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::submit_evidence(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "AuthorizeExternalAction") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::authorize_external_action(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "TransitionExternalAction") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::transition_external_action(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "RedeemExternalActionPermit") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::redeem_external_action_permit(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "RecordUsage") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::record_usage(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "SetBudgetLimit") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::set_budget_limit(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "SetNamespacePolicy") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::set_namespace_policy(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PlanExecution") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::plan_execution(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PlanContentExecution") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::plan_content_execution(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ReportOperationEvent") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::report_operation_event(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "GetOperationReceipt") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::get_operation_receipt(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "GetQualityTrend") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::get_quality_trend(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PutEvaluationPlan") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::put_evaluation_plan(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ResolveEvaluationPlan") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::resolve_evaluation_plan(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ExecuteEvaluationManifest") => {
            invoke_chisei(state, metadata, extensions, body, |svc, req| async move {
                ChiseiService::execute_evaluation_manifest(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListClaimableWork") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::list_claimable_work(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ClaimWork") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::claim_work(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "HeartbeatWorkClaim") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::heartbeat_work_claim(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AckWork") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::ack_work(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RecordDecision") => {
            invoke_sekai(state, metadata, extensions, body, |svc, req| async move {
                SekaiService::record_decision(&*svc, req).await
            })
            .await
        }
        _ => status_response(Status::unimplemented("rpc is not hosted on HTTP/JSON")),
    }
}

async fn invoke_sekai<I, Req, Fut, Res>(
    state: &HttpProjectionState<I>,
    metadata: MetadataMap,
    extensions: http::Extensions,
    body: Bytes,
    handler: impl FnOnce(Arc<SekaiServiceImpl>, Request<Req>) -> Fut,
) -> Response
where
    Req: DeserializeOwned + Serialize + Default,
    Res: Serialize,
    Fut: Future<Output = Result<tonic::Response<Res>, Status>>,
{
    match decode_authenticated(metadata, extensions, body) {
        Ok(request) => match handler(state.sekai.clone(), request).await {
            Ok(response) => json_ok(response.into_inner()),
            Err(status) => status_response(status),
        },
        Err(status) => status_response(status),
    }
}

async fn invoke_chisei<I, Req, Fut, Res>(
    state: &HttpProjectionState<I>,
    metadata: MetadataMap,
    extensions: http::Extensions,
    body: Bytes,
    handler: impl FnOnce(Arc<ChiseiServiceImpl>, Request<Req>) -> Fut,
) -> Response
where
    Req: DeserializeOwned + Serialize + Default,
    Res: Serialize,
    Fut: Future<Output = Result<tonic::Response<Res>, Status>>,
{
    match decode_authenticated(metadata, extensions, body) {
        Ok(request) => match handler(state.chisei.clone(), request).await {
            Ok(response) => json_ok(response.into_inner()),
            Err(status) => status_response(status),
        },
        Err(status) => status_response(status),
    }
}

fn decode_proto_json<T>(body: Bytes) -> Result<T, Status>
where
    T: DeserializeOwned + Serialize + Default,
{
    if body.is_empty() {
        return Ok(T::default());
    }
    let incoming: Value = serde_json::from_slice(&body)
        .map_err(|error| Status::invalid_argument(format!("invalid proto JSON: {error}")))?;
    let mut merged =
        serde_json::to_value(T::default()).map_err(|error| Status::internal(error.to_string()))?;
    merge_json(&mut merged, incoming);
    serde_json::from_value(merged)
        .map_err(|error| Status::invalid_argument(format!("invalid proto JSON: {error}")))
}

fn merge_json(base: &mut Value, incoming: Value) {
    match (base, incoming) {
        (Value::Object(base), Value::Object(incoming)) => {
            for (key, value) in incoming {
                match base.get_mut(&key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, incoming) => *base = incoming,
    }
}

fn decode_authenticated<T>(
    metadata: MetadataMap,
    extensions: http::Extensions,
    body: Bytes,
) -> Result<Request<T>, Status>
where
    T: DeserializeOwned + Serialize + Default,
{
    let payload = decode_proto_json::<T>(body)?;
    Ok(Request::from_parts(metadata, extensions, payload))
}

fn headers_to_metadata(headers: &HeaderMap) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for key in FORWARDED_HEADERS {
        let Some(value) = headers.get(*key) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        let Ok(metadata_key) = MetadataKey::from_bytes(key.as_bytes()) else {
            continue;
        };
        if let Ok(metadata_value) = MetadataValue::try_from(value) {
            metadata.insert(metadata_key, metadata_value);
        }
    }
    metadata
}

fn metadata_str(metadata: &MetadataMap, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn header_str(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn json_ok<T: Serialize>(value: T) -> Response {
    match serde_json::to_value(&value) {
        Ok(payload) => json_response(StatusCode::OK, payload),
        Err(error) => status_response(Status::internal(error.to_string())),
    }
}

fn json_response(status: StatusCode, payload: Value) -> Response {
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

fn status_response(status: Status) -> Response {
    let http_status = match status.code() {
        tonic::Code::InvalidArgument
        | tonic::Code::FailedPrecondition
        | tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists | tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_response(
        http_status,
        json!({
            "code": grpc_code_name(status.code()),
            "message": status.message(),
        }),
    )
}

fn grpc_code_name(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "ok",
        tonic::Code::Cancelled => "cancelled",
        tonic::Code::Unknown => "unknown",
        tonic::Code::InvalidArgument => "invalid_argument",
        tonic::Code::DeadlineExceeded => "deadline_exceeded",
        tonic::Code::NotFound => "not_found",
        tonic::Code::AlreadyExists => "already_exists",
        tonic::Code::PermissionDenied => "permission_denied",
        tonic::Code::ResourceExhausted => "resource_exhausted",
        tonic::Code::FailedPrecondition => "failed_precondition",
        tonic::Code::Aborted => "aborted",
        tonic::Code::OutOfRange => "out_of_range",
        tonic::Code::Unimplemented => "unimplemented",
        tonic::Code::Internal => "internal",
        tonic::Code::Unavailable => "unavailable",
        tonic::Code::DataLoss => "data_loss",
        tonic::Code::Unauthenticated => "unauthenticated",
    }
}

/// MCP over the projection. The catalog read runs as the door's identity;
/// each tool call re-runs the interceptor on the caller's original headers
/// for that tool's RPC path and dispatches as the identity it returns.
struct HttpMcpSurface<I> {
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    interceptor: I,
    headers: HeaderMap,
    door: crate::mcp_adapter::CallerIdentity,
    principal: String,
    namespace: String,
}

#[async_trait::async_trait]
impl<I> NativeSurface for HttpMcpSurface<I>
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    async fn discover(
        &self,
    ) -> Result<crate::mcp_adapter::CatalogSnapshot, crate::mcp_adapter::AdapterError> {
        use crate::grpc::pb::sekai::DiscoverCapabilitiesRequest;
        use crate::mcp_adapter::status_error;
        use crate::sekai::capability::CONTRACT_VERSION;

        let mut request = Request::new(DiscoverCapabilitiesRequest {
            namespace: self.namespace.clone(),
            product_tier_filter: "all".into(),
            page_size: 200,
            ..Default::default()
        });
        self.door.apply(&mut request);
        bind_identity(&mut request, &self.principal, &self.namespace);
        let response = self
            .sekai
            .discover_capabilities(request)
            .await
            .map_err(status_error)?
            .into_inner();
        Ok(crate::mcp_adapter::CatalogSnapshot {
            context: crate::capability_projection::ProjectionContext {
                namespace: self.namespace.clone(),
                principal: self.principal.clone(),
                contract_version: if response.contract_version.is_empty() {
                    CONTRACT_VERSION.into()
                } else {
                    response.contract_version
                },
                catalog_version: response.catalog_version,
            },
        })
    }

    async fn dispatch(
        &self,
        rpc: crate::mcp_adapter::NativeRpc,
        invocation: crate::capability_projection::SdkInvocation,
    ) -> Result<Value, crate::mcp_adapter::AdapterError> {
        use crate::mcp_adapter::{CallerIdentity, dispatch_native_as, status_error};

        let path = format!("/{}/{}", rpc.service_name(), rpc.rpc_name());
        let caller = authenticate(&self.interceptor, &self.headers, Some(&path))
            .map(CallerIdentity::authenticated)
            .map_err(status_error)?;
        dispatch_native_as(
            &self.sekai,
            &self.chisei,
            rpc,
            invocation,
            experimental_rpcs_enabled(),
            &caller,
        )
        .await
    }

    fn experimental_tools(&self) -> bool {
        experimental_rpcs_enabled()
    }
}

fn bind_identity<T>(request: &mut Request<T>, principal: &str, namespace: &str) {
    if let Ok(value) = MetadataValue::try_from(principal) {
        request.metadata_mut().insert("x-principal", value);
    }
    if let Ok(value) = MetadataValue::try_from(namespace) {
        request.metadata_mut().insert("x-sekai-namespace", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::actor_limit::ActorRateGate;
    use crate::chisei::budget::BudgetTracker;
    use crate::config::Config;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::grpc::TokenAuthInterceptor;
    use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
    use crate::grpc::pb::sekai::{
        CreateSchemaTypeRequest, EvaluateObjectSetRequest, ListSchemaTypesRequest,
        ObjectSetDescriptor, ObjectType, PropertyDef,
    };
    use crate::sekai::credentials::PrincipalCredentialStore;
    use crate::sekai::security::{Grant, Role};
    use http_body_util::BodyExt;
    use sekai_domain::gateway_keys::hash_gateway_key;
    use tower::ServiceExt;

    fn fixture_config() -> Config {
        let mut config = Config::from_env();
        config.grpc_port = 0;
        config.http_port = Some(DEFAULT_HTTP_PORT);
        config.http_bind = "127.0.0.1".into();
        config.ops_port = None;
        config.sekai_socket = None;
        config.db_path = ":memory:".into();
        config.insecure = false;
        config.allow_plaintext = false;
        config
    }

    fn token_world() -> (
        Arc<SekaiServiceImpl>,
        Arc<ChiseiServiceImpl>,
        TokenAuthInterceptor,
        String,
    ) {
        token_world_seeded(|_| {})
    }

    /// [`token_world`] with `seed` run against the store before the services
    /// start.
    fn token_world_seeded(
        seed: impl FnOnce(&RuntimeDb),
    ) -> (
        Arc<SekaiServiceImpl>,
        Arc<ChiseiServiceImpl>,
        TokenAuthInterceptor,
        String,
    ) {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        seed(&db);
        db.ensure_team_namespace("acme", "alice", Role::Admin, "local")
            .unwrap();
        db.create_grant(&Grant {
            id: "schema-admin".into(),
            object_id: "schema".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 0,
            ..Default::default()
        })
        .unwrap();
        let token = "http-projection-token";
        db.create_principal_credential("alice", &hash_gateway_key(token), 1)
            .unwrap();
        let store = Arc::new(PrincipalCredentialStore::new());
        store.load(&db.list_active_credentials().unwrap());
        let (sekai, chisei) = services_for(db.clone());
        (
            sekai,
            chisei,
            TokenAuthInterceptor::new(store, crate::db::store::SekaiStore::from_shared_runtime(db)),
            token.into(),
        )
    }

    fn services_for(db: Arc<RuntimeDb>) -> (Arc<SekaiServiceImpl>, Arc<ChiseiServiceImpl>) {
        let sekai_store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let chisei_store = crate::chisei_store::ChiseiStore::from_shared_runtime(db.clone());
        let budget = Arc::new(BudgetTracker::new(chisei_store.clone()));
        let clerk = crate::composition::cross_store_admission::CrossStoreAdmission::new(
            chisei_store.clone(),
            sekai_store.clone(),
            Some(budget),
        );
        let sekai = Arc::new(
            SekaiServiceImpl::new(sekai_store.clone()).with_cross_store_admission(Arc::new(clerk)),
        );
        let chisei = Arc::new(
            ChiseiServiceImpl::new(chisei_store, fixture_config())
                .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::in_process(
                    sekai_store.clone(),
                ))
                .unwrap(),
        );
        (sekai, chisei)
    }

    fn router_for(
        sekai: Arc<SekaiServiceImpl>,
        chisei: Arc<ChiseiServiceImpl>,
        interceptor: TokenAuthInterceptor,
    ) -> Router {
        router(HttpProjectionState {
            sekai,
            chisei,
            interceptor,
            stores: None,
            mcp_refusal: None,
        })
    }

    fn named_request<T>(payload: T, principal: &str) -> Request<T> {
        let mut request = Request::new(payload);
        request.metadata_mut().insert(
            "x-principal",
            MetadataValue::try_from(principal).expect("principal"),
        );
        request.metadata_mut().insert(
            "x-sekai-namespace",
            MetadataValue::try_from("acme").expect("namespace"),
        );
        request
    }

    async fn http_json(
        app: Router,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        http_json_with(app, path, token, &[], body).await
    }

    async fn http_json_with(
        app: Router,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request = request.header("x-sekai-namespace", "acme");
        request = request.header("x-principal", "attacker");
        let request = request
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, payload)
    }

    #[test]
    fn loopback_bind_is_required_for_insecure() {
        let mut config = fixture_config();
        config.insecure = true;
        config.http_bind = "0.0.0.0".into();
        assert!(validate_bind(&config.http_bind, &config).is_err());
        config.http_bind = "127.0.0.1".into();
        assert!(validate_bind(&config.http_bind, &config).is_ok());
    }

    #[test]
    fn http_binds_only_with_token_auth_or_insecure() {
        let mut config = fixture_config();
        let token = GrpcTcpMode {
            bind_addr: "0.0.0.0".into(),
            token_auth_mode: true,
            auth_configured: true,
            bind_inferred_from_active_credentials: true,
        };
        assert!(should_bind(&config, &token));
        let local = GrpcTcpMode {
            bind_addr: "127.0.0.1".into(),
            token_auth_mode: false,
            auth_configured: false,
            bind_inferred_from_active_credentials: false,
        };
        assert!(!should_bind(&config, &local));
        config.insecure = true;
        assert!(should_bind(&config, &local));
        config.http_port = None;
        assert!(!should_bind(&config, &token));
    }

    #[tokio::test]
    async fn unauthenticated_and_forged_principal_fail_closed() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let (status, payload) = http_json(
            app.clone(),
            "/sekai.SekaiService/ListSchemaTypes",
            None,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(payload["code"], "unauthenticated");

        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/ListSchemaTypes",
            Some("wrong-token"),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(payload["code"], "unauthenticated");
        let _ = token;
    }

    #[tokio::test]
    async fn http_json_charges_the_actor_rate_gate_once_per_request() {
        let (sekai, chisei, interceptor, token) = token_world();
        let interceptor = interceptor.with_actor_rate_gate(ActorRateGate::enabled(1, 1));
        let app = router_for(sekai, chisei, interceptor);
        let (status, payload) = http_json(
            app.clone(),
            "/sekai.SekaiService/ListSchemaTypes",
            Some(&token),
            json!({}),
        )
        .await;
        assert_ne!(payload["code"], "resource_exhausted");
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/ListSchemaTypes",
            Some(&token),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(payload["code"], "resource_exhausted");
        assert!(
            payload["message"]
                .as_str()
                .unwrap_or_default()
                .contains("retry_after")
        );
    }

    /// Every RPC the generated HTTP clients call has a `dispatch` arm: an
    /// unauthenticated call is refused, and an authenticated one reaches a
    /// handler instead of the `unimplemented` fallback or the experimental gate.
    #[tokio::test]
    async fn every_generated_http_client_method_is_hosted_and_stays_authorized() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let methods = crate::http_codegen::http_unary_methods();
        assert!(!methods.is_empty(), "no generated HTTP client methods");
        let mut unhosted = Vec::new();
        for method in methods {
            let path = format!("/{}/{}", method.service, method.rpc);
            let (status, payload) = http_json(app.clone(), &path, None, json!({})).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(payload["code"], "unauthenticated", "{path}");

            let (_, payload) = http_json(app.clone(), &path, Some(&token), json!({})).await;
            let message = payload["message"].as_str().unwrap_or_default();
            if payload["code"] == "unimplemented" {
                unhosted.push(path);
                continue;
            }
            assert!(
                !message.contains("experimental"),
                "{path} is stable and must not hit the experimental gate: {message}"
            );
        }
        assert!(
            unhosted.is_empty(),
            "generated HTTP clients call RPCs with no dispatch arm: {unhosted:#?}"
        );
    }

    #[tokio::test]
    async fn promoted_get_lineage_is_hosted_and_stays_authorized() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let path = "/sekai.SekaiService/GetLineage";
        let (status, payload) = http_json(app.clone(), path, None, json!({})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(payload["code"], "unauthenticated");

        let (_, payload) = http_json(
            app,
            path,
            Some(&token),
            json!({"objectId": "missing", "maxNodes": 5}),
        )
        .await;
        assert_eq!(payload["code"], "not_found", "{payload}");
    }

    /// Proto3 JSON may omit default-valued fields of a nested input message;
    /// admission and attachment still decode (#2266).
    #[tokio::test]
    async fn document_inputs_decode_with_default_valued_fields_omitted() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let (status, admitted) = http_json(
            app.clone(),
            "/sekai.SekaiService/AdmitGovernedDocument",
            Some(&token),
            json!({"document": {
                "contractVersion": "sekai.governed-document/v1",
                "documentId": "doc:brief",
                "namespace": "acme",
                "typeRevision": "v1",
                "purpose": "case-review",
                "classification": "public",
                "title": "Brief",
                "contentRef": {
                    "scheme": "digest",
                    "digest": format!("sha256:01{}", "ab".repeat(31)),
                    "mediaType": "application/pdf",
                    "byteLength": 128
                }
            }}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{admitted}");
        assert_eq!(admitted["document"]["owner"], "alice");
        let parent = admitted["document"]["contentDigest"].clone();

        let (status, attached) = http_json(
            app,
            "/sekai.SekaiService/AttachGovernedDocumentRendition",
            Some(&token),
            json!({"rendition": {
                "namespace": "acme",
                "documentId": "doc:brief",
                "renditionId": "rend:text",
                "class": "extracted_text",
                "parentContentDigest": parent,
                "contentRef": {
                    "scheme": "digest",
                    "digest": format!("sha256:02{}", "cd".repeat(31)),
                    "mediaType": "text/plain",
                    "byteLength": 32
                },
                "extractorId": "extractor:text",
                "extractorProfileDigest": format!("sha256:03{}", "ef".repeat(31))
            }}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        assert_eq!(attached["rendition"]["attachedBy"], "alice");
    }

    #[tokio::test]
    async fn experimental_rpc_is_refused_after_auth() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/ListOntologyClasses",
            Some(&token),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(payload["code"], "failed_precondition");
        assert!(
            payload["message"]
                .as_str()
                .unwrap_or_default()
                .contains("experimental")
        );
    }

    #[tokio::test]
    async fn list_schema_types_matches_grpc_and_ignores_client_principal() {
        let (sekai, chisei, interceptor, token) = token_world();
        sekai
            .create_schema_type(named_request(
                CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: "widget".into(),
                        description: "HTTP widget".into(),
                        is_builtin: false,
                        implements: vec![],
                        properties: vec![PropertyDef {
                            name: "name".into(),
                            r#type: "string".into(),
                            required: true,
                            ..Default::default()
                        }],
                    }),
                },
                "alice",
            ))
            .await
            .unwrap();
        let grpc = sekai
            .list_schema_types(named_request(ListSchemaTypesRequest {}, "alice"))
            .await
            .unwrap()
            .into_inner();
        let app = router_for(sekai, chisei, interceptor);
        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/ListSchemaTypes",
            Some(&token),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let expected = serde_json::to_value(&grpc).unwrap();
        assert_eq!(payload, expected);
        assert!(
            payload["types"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r#type| r#type["kind"] == "widget")
        );
    }

    #[tokio::test]
    async fn evaluate_object_set_hidden_namespace_matches_grpc() {
        let (sekai, chisei, interceptor, token) = token_world();
        let request = EvaluateObjectSetRequest {
            descriptor: Some(ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
                namespace: "other".into(),
                kind: "Customer".into(),
                ..Default::default()
            }),
            page_token: String::new(),
            required_freshness_ms: 0,
        };
        let grpc = sekai
            .evaluate_object_set(named_request(request.clone(), "alice"))
            .await
            .unwrap_err();
        let app = router_for(sekai, chisei, interceptor);
        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/EvaluateObjectSet",
            Some(&token),
            serde_json::to_value(&request).unwrap(),
        )
        .await;
        assert_eq!(payload["code"], grpc_code_name(grpc.code()));
        assert_eq!(payload["message"], grpc.message());
        assert_eq!(
            status,
            match grpc.code() {
                tonic::Code::NotFound => StatusCode::NOT_FOUND,
                tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
                other => panic!("unexpected hidden-row code {other:?}"),
            }
        );
    }

    /// ADR 0160: a generated HTTP ontology client's revision pin reaches every
    /// pinned call, so object reads, object writes, object-set evaluation, and
    /// Action submission refuse a pin that is not the live revision.
    #[tokio::test]
    async fn revision_pinned_http_calls_fail_closed_on_a_stale_revision() {
        use crate::sekai::definition_branch::{
            DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
        };
        let mut live = String::new();
        let (sekai, chisei, interceptor, token) = token_world_seeded(|db| {
            let member = DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Customer".into(),
                definition_json: r#"{"properties":["name"]}"#.into(),
                member_digest: String::new(),
            }
            .prepare("acme")
            .unwrap();
            let revision = prepare_revision(
                "acme",
                "",
                [DefinitionRevisionMember {
                    member_kind: member.member_kind.clone(),
                    member_id: member.member_id.clone(),
                    member_digest: member.member_digest.clone(),
                }],
                true,
                "root",
                1,
            )
            .unwrap();
            db.seed_published_definition_revision(&revision, &[member])
                .unwrap();
            live = revision.revision_digest;
        });
        let app = router_for(sekai, chisei, interceptor);
        let stale = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        use crate::grpc::pb::sekai::{
            CreateObjectRequest, ListFilter, ListObjectsRequest, Object,
            SubmitActionInstanceRequest,
        };
        let header_pinned = [
            (
                "/sekai.SekaiService/ListObjects",
                serde_json::to_value(ListObjectsRequest {
                    filter: Some(ListFilter {
                        namespace: "acme".into(),
                        kind: "Customer".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .unwrap(),
            ),
            (
                "/sekai.SekaiService/CreateObject",
                serde_json::to_value(CreateObjectRequest {
                    object: Some(Object {
                        id: "c-1".into(),
                        kind: "Customer".into(),
                        namespace: "acme".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .unwrap(),
            ),
            (
                "/sekai.SekaiService/SubmitActionInstance",
                serde_json::to_value(SubmitActionInstanceRequest {
                    namespace: "acme".into(),
                    type_id: "Approve".into(),
                    version: "1".into(),
                    ..Default::default()
                })
                .unwrap(),
            ),
        ];
        for (path, body) in &header_pinned {
            let (status, payload) = http_json_with(
                app.clone(),
                path,
                Some(&token),
                &[("x-sekai-definition-revision", stale)],
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {payload}");
            assert_eq!(
                payload["message"], "ontology client revision pin is stale",
                "{path}"
            );
        }
        for (path, body) in &header_pinned {
            let (_, payload) = http_json_with(
                app.clone(),
                path,
                Some(&token),
                &[("x-sekai-definition-revision", live.as_str())],
                body.clone(),
            )
            .await;
            assert_ne!(
                payload["message"], "ontology client revision pin is stale",
                "{path}"
            );
        }

        let evaluate = |digest: &str| {
            serde_json::to_value(EvaluateObjectSetRequest {
                descriptor: Some(ObjectSetDescriptor {
                    contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
                    namespace: "acme".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.into(),
                    ..Default::default()
                }),
                page_token: String::new(),
                required_freshness_ms: 0,
            })
            .unwrap()
        };
        let (status, payload) = http_json(
            app.clone(),
            "/sekai.SekaiService/EvaluateObjectSet",
            Some(&token),
            evaluate(stale),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
        assert_eq!(
            payload["message"],
            "object set definition revision is stale"
        );
        let (status, payload) = http_json(
            app,
            "/sekai.SekaiService/EvaluateObjectSet",
            Some(&token),
            evaluate(&live),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{payload}");
    }

    #[test]
    fn a_non_loopback_bind_needs_tls_or_explicit_plaintext() {
        let mut config = fixture_config();
        assert!(validate_bind("0.0.0.0", &config).is_err());
        config.tls_cert = Some("cert.pem".into());
        config.tls_key = Some("key.pem".into());
        assert!(validate_bind("0.0.0.0", &config).is_ok());
        assert_eq!(mcp_refusal("0.0.0.0", true), None);
        // Plaintext beyond loopback keeps the RPC routes and refuses `/mcp`.
        assert_eq!(mcp_refusal("0.0.0.0", false), Some(MCP_NEEDS_TLS));
        assert_eq!(mcp_refusal("127.0.0.1", false), None);
    }

    #[tokio::test]
    async fn mcp_on_a_plaintext_listener_beyond_loopback_is_refused_before_auth() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router(HttpProjectionState {
            sekai,
            chisei,
            interceptor,
            stores: None,
            mcp_refusal: mcp_refusal("0.0.0.0", false),
        });
        let (status, payload) = http_json(
            app,
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
        assert!(payload.to_string().contains("requires TLS"), "{payload}");
    }

    const ENTERPRISE_TOKEN: &str = "enterprise-bearer";

    /// An installed identity provider: one bearer for `erin` in `tenant-a`,
    /// which may use namespace `acme` only.
    struct OneTenantExtension;

    impl crate::enterprise::EnterpriseExtension for OneTenantExtension {
        fn authenticate_bearer(
            &self,
            bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            (bearer_token == ENTERPRISE_TOKEN)
                .then(|| crate::enterprise::AuthenticatedPrincipal {
                    subject: "erin".into(),
                    credential_id: "erin-credential".into(),
                })
                .ok_or(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            let principal = self.authenticate_bearer(bearer_token)?;
            Ok(crate::enterprise::AuthenticatedContext {
                contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
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
                expires_at: i64::MAX,
                device: None,
            })
        }

        fn tenant_context(
            &self,
            principal: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            Ok(crate::enterprise::TenantContext {
                tenant_id: "tenant-a".into(),
                subject: principal.subject.clone(),
            })
        }

        fn authorize_namespace(
            &self,
            _context: &crate::enterprise::TenantContext,
            namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            (namespace == "acme")
                .then_some(())
                .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn authorize_unscoped_namespace(
            &self,
            _principal: &crate::enterprise::AuthenticatedPrincipal,
            _namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }
    }

    /// A projection under enterprise auth with one object `erin` may read.
    fn enterprise_router() -> Router {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(OneTenantExtension)))
                .unwrap(),
        )));
        crate::chisei_store::apply_chisei_schema(&db);
        db.ensure_team_namespace("acme", "erin", Role::Admin, "local")
            .unwrap();
        db.create_object(&sekai_domain::domain::Object {
            id: "ticket-1".into(),
            kind: "ticket".into(),
            name: "first".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let (sekai, chisei) = services_for(db.clone());
        router_for(
            sekai,
            chisei,
            TokenAuthInterceptor::new(
                Arc::new(PrincipalCredentialStore::new()),
                crate::db::store::SekaiStore::from_shared_runtime(db),
            ),
        )
    }

    async fn mcp_call(app: Router, token: Option<&str>, tool: &str, input: Value) -> Value {
        let (status, payload) = http_json_with(
            app,
            "/mcp",
            token,
            &[],
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name": tool, "arguments":{"operation_id":"op-1","input": input}}
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{payload}");
        payload["result"].clone()
    }

    #[tokio::test]
    async fn an_enterprise_credential_reaches_mcp_tools_authorized_per_tool() {
        let app = enterprise_router();
        let (status, payload) = http_json_with(
            app.clone(),
            "/mcp",
            Some(ENTERPRISE_TOKEN),
            &[],
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{payload}");

        // The handler sees the enterprise authenticated context, so the read
        // runs as erin in tenant-a; without it the plane refuses the read.
        let read = mcp_call(
            app.clone(),
            Some(ENTERPRISE_TOKEN),
            "sekai.objects.get",
            json!({"id":"ticket-1"}),
        )
        .await;
        assert_eq!(read["isError"], false, "{read}");
        assert!(read.to_string().contains("ticket-1"), "{read}");

        // Admitted at the door is not admitted for every tool: GetLineage is
        // not served to enterprise-scoped credentials.
        let lineage = mcp_call(
            app.clone(),
            Some(ENTERPRISE_TOKEN),
            "sekai.lineage.get",
            json!({"object_id":"ticket-1"}),
        )
        .await;
        assert_eq!(lineage["isError"], true, "{lineage}");
        assert!(
            lineage
                .to_string()
                .contains("not available to enterprise-scoped credentials"),
            "{lineage}"
        );

        let (status, _) = http_json_with(
            app,
            "/mcp",
            Some("some-other-bearer"),
            &[],
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_projection_serves_mcp_over_tls_with_the_grpc_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let acceptor = tls_acceptor(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
        )
        .unwrap();
        let (sekai, chisei, interceptor, token) = token_world();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_tls(
            listener,
            acceptor,
            router_for(sekai, chisei, interceptor),
        ));
        let client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        let response = client
            .post(format!("https://localhost:{port}/mcp"))
            .bearer_auth(&token)
            .header("x-sekai-namespace", "acme")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let plaintext = reqwest::Client::new()
            .post(format!("http://localhost:{port}/mcp"))
            .bearer_auth(&token)
            .send()
            .await;
        assert!(plaintext.is_err(), "a plaintext request must not be served");
    }

    #[tokio::test]
    async fn mcp_http_requires_bearer_and_lists_projection_tools() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        let (status, _payload) = http_json(
            app.clone(),
            "/mcp",
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, payload) = http_json(
            app,
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let names: Vec<_> = payload["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"sekai.objects.evaluate_set".into()));
        assert!(names.contains(&"sekai.actions.preview".into()));
        assert!(names.contains(&"sekai.actions.submit".into()));
        assert!(names.contains(&"chisei.receipt.read".into()));
    }
}
