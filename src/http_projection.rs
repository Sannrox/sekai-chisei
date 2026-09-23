//! HTTP/JSON projection of stable gRPC (#875, ADR 0075).
//!
//! Routes are the proto service paths. Bodies are proto3 JSON of the same
//! messages. Authorization, maturity, and hidden-row rules stay on the
//! existing interceptors and service impls. Streaming RPCs stay on gRPC.

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
use tracing::{error, info};

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
    "x-chisei-request-id",
    "x-principal",
];

#[derive(Clone)]
pub struct HttpProjectionState<I> {
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    interceptor: I,
    stores: Option<Arc<CombinedStoreLayout>>,
}

pub fn should_bind(config: &Config, tcp_mode: &GrpcTcpMode) -> bool {
    config.http_port.is_some() && (tcp_mode.token_auth_mode || config.insecure)
}

pub fn validate_bind(bind: &str, config: &Config) -> Result<(), String> {
    if is_loopback(bind) {
        return Ok(());
    }
    if config.insecure {
        return Err("SEKAI_HTTP_BIND must be loopback when SEKAI_INSECURE=1".into());
    }
    if !config.allow_plaintext {
        return Err(
            "non-loopback HTTP projection requires SEKAI_ALLOW_PLAINTEXT=1; TLS is not hosted on this listener"
                .into(),
        );
    }
    Ok(())
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
    let listener = TcpListener::bind((bind, port)).await?;
    let addr = listener.local_addr()?;
    let app = router(HttpProjectionState {
        sekai,
        chisei,
        interceptor,
        stores: Some(stores),
    });
    info!(
        addr = %addr,
        contract = HTTP_PROJECTION_CONTRACT,
        "HTTP/JSON projection of stable gRPC listening"
    );
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            error!(error = %err, "HTTP projection listener exited");
        }
    });
    Ok(addr)
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
    if let Err(status) = authenticate(&state.interceptor, &headers) {
        return status_response(status);
    }
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
    dispatch(&state, &service, &method, &headers, body).await
}

async fn mcp_handler<I>(
    State(state): State<HttpProjectionState<I>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    I: Interceptor + Clone + Send + Sync + 'static,
{
    let authenticated = match authenticate(&state.interceptor, &headers) {
        Ok(metadata) => metadata,
        Err(status) => return status_response(status),
    };
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
        principal,
        namespace,
    };
    match handle_message(&surface, message).await {
        Some(value) => json_response(StatusCode::OK, value),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

fn authenticate<I>(interceptor: &I, headers: &HeaderMap) -> Result<MetadataMap, Status>
where
    I: Interceptor + Clone,
{
    let mut interceptor = interceptor.clone();
    let request = interceptor.call(Request::from_parts(
        headers_to_metadata(headers),
        Default::default(),
        (),
    ))?;
    Ok(request.into_parts().0)
}

async fn dispatch<I>(
    state: &HttpProjectionState<I>,
    service: &str,
    method: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response
where
    I: Interceptor + Clone,
{
    match (service, method) {
        ("sekai.SekaiService", "ApplySourceBatch") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::apply_source_batch(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetSourceSyncState") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_source_sync_state(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetPublishedDefinitionRevision") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_published_definition_revision(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateObject") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetObject") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "UpdateObject") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::update_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteObject") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::delete_object(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListObjects") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::list_objects(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RetrieveContext") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::retrieve_context(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExpandRelations") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::expand_relations(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ExplainDerivation") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::explain_derivation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "EvaluateObjectSet") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::evaluate_object_set(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ReadObjectChangeSubscription") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::read_object_change_subscription(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutObjectSecurityPolicyRevision") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::put_object_security_policy_revision(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ActivateObjectSecurityPolicies") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::activate_object_security_policies(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetObjectSecurityActivation") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_object_security_activation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "FindByExternalId") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::find_by_external_id(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "FindByProperty") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::find_by_property(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateLink") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_link(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteLink") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::delete_link(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetLinks") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_links(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "Traverse") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::traverse(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DiscoverCapabilities") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::discover_capabilities(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListSchemaTypes") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::list_schema_types(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateSchemaType") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_schema_type(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateOntologyClass") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_ontology_class(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateOntologyRelation") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_ontology_relation(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateDataset") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_dataset(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "UpdateDataset") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::update_dataset(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "AppendRows") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::append_rows(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "QueryRows") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::query_rows(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateGrant") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_grant(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DeleteGrant") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::delete_grant(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListGrants") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::list_grants(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CheckAccess") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::check_access(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PutGovernedActionType") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::put_governed_action_type(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "SubmitActionInstance") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::submit_action_instance(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "DescribeObjectAction") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::describe_object_action(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "PreviewObjectAction") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::preview_object_action(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetActionInstance") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_action_instance(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "GetActionEffect") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::get_action_effect(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListActionEffects") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::list_action_effects(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "CreateCredential") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::create_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RotateCredential") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::rotate_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RevokeCredential") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::revoke_credential(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "ListCredentials") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::list_credentials(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "RegisterEvidenceSchema") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::register_evidence_schema(&*svc, req).await
            })
            .await
        }
        ("sekai.SekaiService", "SubmitEvidence") => {
            invoke_sekai(state, headers, body, |svc, req| async move {
                SekaiService::submit_evidence(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "AuthorizeExternalAction") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::authorize_external_action(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "TransitionExternalAction") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::transition_external_action(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "RedeemExternalActionPermit") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::redeem_external_action_permit(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "RecordUsage") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::record_usage(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "SetBudgetLimit") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::set_budget_limit(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "DecideGatewayExecution") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::decide_gateway_execution(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "SetNamespacePolicy") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::set_namespace_policy(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PlanExecution") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::plan_execution(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PlanContentExecution") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::plan_content_execution(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ReportOperationEvent") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::report_operation_event(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "GetOperationReceipt") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::get_operation_receipt(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "GetQualityTrend") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::get_quality_trend(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "PutEvaluationPlan") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::put_evaluation_plan(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ResolveEvaluationPlan") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::resolve_evaluation_plan(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ExecuteEvaluationManifest") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::execute_evaluation_manifest(&*svc, req).await
            })
            .await
        }
        ("chisei.ChiseiService", "ClaimGatewayDispatch") => {
            invoke_chisei(state, headers, body, |svc, req| async move {
                ChiseiService::claim_gateway_dispatch(&*svc, req).await
            })
            .await
        }
        _ => status_response(Status::unimplemented("rpc is not hosted on HTTP/JSON")),
    }
}

async fn invoke_sekai<I, Req, Fut, Res>(
    state: &HttpProjectionState<I>,
    headers: &HeaderMap,
    body: Bytes,
    handler: impl FnOnce(Arc<SekaiServiceImpl>, Request<Req>) -> Fut,
) -> Response
where
    I: Interceptor + Clone,
    Req: DeserializeOwned + Serialize + Default,
    Res: Serialize,
    Fut: Future<Output = Result<tonic::Response<Res>, Status>>,
{
    match decode_authenticated(&state.interceptor, headers, body) {
        Ok(request) => match handler(state.sekai.clone(), request).await {
            Ok(response) => json_ok(response.into_inner()),
            Err(status) => status_response(status),
        },
        Err(status) => status_response(status),
    }
}

async fn invoke_chisei<I, Req, Fut, Res>(
    state: &HttpProjectionState<I>,
    headers: &HeaderMap,
    body: Bytes,
    handler: impl FnOnce(Arc<ChiseiServiceImpl>, Request<Req>) -> Fut,
) -> Response
where
    I: Interceptor + Clone,
    Req: DeserializeOwned + Serialize + Default,
    Res: Serialize,
    Fut: Future<Output = Result<tonic::Response<Res>, Status>>,
{
    match decode_authenticated(&state.interceptor, headers, body) {
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

fn decode_authenticated<I, T>(
    interceptor: &I,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Request<T>, Status>
where
    I: Interceptor + Clone,
    T: DeserializeOwned + Serialize + Default,
{
    let payload = decode_proto_json::<T>(body)?;
    let mut interceptor = interceptor.clone();
    let request = interceptor.call(Request::from_parts(
        headers_to_metadata(headers),
        Default::default(),
        (),
    ))?;
    let (metadata, extensions, ()) = request.into_parts();
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

struct HttpMcpSurface {
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
    principal: String,
    namespace: String,
}

#[async_trait::async_trait]
impl NativeSurface for HttpMcpSurface {
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
        crate::mcp_adapter::dispatch_native(&self.sekai, &self.chisei, rpc, invocation).await
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
    use crate::chisei::budget::BudgetTracker;
    use crate::config::Config;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::gateway_keys::hash_gateway_key;
    use crate::grpc::TokenAuthInterceptor;
    use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
    use crate::grpc::pb::sekai::{
        CreateSchemaTypeRequest, EvaluateObjectSetRequest, ListSchemaTypesRequest,
        ObjectSetDescriptor, ObjectType, PropertyDef,
    };
    use crate::sekai::credentials::PrincipalCredentialStore;
    use crate::sekai::security::{Grant, Role};
    use http_body_util::BodyExt;
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
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        db.ensure_team_namespace("acme", "alice", Role::Admin, "local")
            .unwrap();
        db.create_grant(&Grant {
            id: "schema-admin".into(),
            object_id: "schema".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 0,
        })
        .unwrap();
        let token = "http-projection-token";
        db.create_principal_credential("alice", &hash_gateway_key(token), 1)
            .unwrap();
        let store = Arc::new(PrincipalCredentialStore::new());
        store.load(&db.list_active_credentials().unwrap());
        let sekai_store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let chisei_store = crate::db::store::ChiseiStore::from_shared_runtime(db.clone());
        let budget = Arc::new(BudgetTracker::new(chisei_store.clone()));
        let clerk = crate::chisei::cross_store_admission::CrossStoreAdmission::new(
            chisei_store.clone(),
            sekai_store.clone(),
            Some(budget),
        );
        let sekai = Arc::new(
            SekaiServiceImpl::new(sekai_store).with_cross_store_admission(Arc::new(clerk)),
        );
        let chisei = Arc::new(ChiseiServiceImpl::new(chisei_store, fixture_config()));
        (
            sekai,
            chisei,
            TokenAuthInterceptor::new(store, crate::db::store::SekaiStore::from_shared_runtime(db)),
            token.into(),
        )
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
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
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
    async fn promoted_semantic_rpcs_are_hosted_and_stay_authorized() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        for rpc in ["RetrieveContext", "ExpandRelations", "ExplainDerivation"] {
            let path = format!("/sekai.SekaiService/{rpc}");
            let (status, payload) = http_json(app.clone(), &path, None, json!({})).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{rpc}");
            assert_eq!(payload["code"], "unauthenticated", "{rpc}");

            let (_, payload) = http_json(app.clone(), &path, Some(&token), json!({})).await;
            let message = payload["message"].as_str().unwrap_or_default();
            assert_ne!(payload["code"], "unimplemented", "{rpc} must be hosted");
            assert!(
                !message.contains("experimental"),
                "{rpc} is stable and must not hit the experimental gate: {message}"
            );
        }
    }

    #[tokio::test]
    async fn promoted_evaluation_rpcs_are_hosted_and_stay_authorized() {
        let (sekai, chisei, interceptor, token) = token_world();
        let app = router_for(sekai, chisei, interceptor);
        for rpc in [
            "PutEvaluationPlan",
            "ResolveEvaluationPlan",
            "ExecuteEvaluationManifest",
        ] {
            let path = format!("/chisei.ChiseiService/{rpc}");
            let (status, payload) = http_json(app.clone(), &path, None, json!({})).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{rpc}");
            assert_eq!(payload["code"], "unauthenticated", "{rpc}");

            let (_, payload) = http_json(app.clone(), &path, Some(&token), json!({})).await;
            let message = payload["message"].as_str().unwrap_or_default();
            assert_ne!(payload["code"], "unimplemented", "{rpc} must be hosted");
            assert!(
                !message.contains("experimental"),
                "{rpc} is stable and must not hit the experimental gate: {message}"
            );
        }
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
