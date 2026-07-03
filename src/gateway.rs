use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use chrono::Utc;
use futures_util::StreamExt;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request as GrpcRequest;

use crate::gateway_keys::hash_gateway_key;
use crate::grpc::client::{GatewayClient, connect_sekai};
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    CheckBudgetRequest, GatewayAuditEvent, PipelineRequest as ChiseiPipelineRequest,
    RecordGatewayAuditRequest, RecordSampleObservationRequest, RecordUsageRequest,
    ResolvePolicyRequest, RunPipelineRequest, SampleObservation,
};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    AppendRowsRequest, ColumnDef, CreateDatasetRequest, CreateLinkRequest, CreateObjectRequest,
    Dataset, FindByExternalIdRequest, FindByPropertyRequest, Link, Object as SekaiObject, Row,
};

const DEFAULT_GATEWAY_BIND: &str = "127.0.0.1:8788";
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com/v1";
const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;
const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const X_CHISEI_AGENT: HeaderName = HeaderName::from_static("x-chisei-agent");
const X_CHISEI_PROJECT: HeaderName = HeaderName::from_static("x-chisei-project");
const X_CHISEI_WORK_UNIT: HeaderName = HeaderName::from_static("x-chisei-work-unit");
const X_CHISEI_TASK_ID: HeaderName = HeaderName::from_static("x-chisei-task-id");
const DEFAULT_KEY_CACHE_TTL_SECS: u64 = 30;

#[derive(Clone)]
pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub openai_base_url: String,
    pub openai_api_key: Option<String>,
    pub anthropic_base_url: String,
    pub anthropic_api_key: Option<String>,
    pub chisei_grpc_target: Option<String>,
    pub fail_closed: bool,
    pub default_project: String,
    pub gateway_keys: HashMap<String, GatewayIdentity>,
    pub allow_auth_passthrough: bool,
    pub rewrite_openai_passthrough_auth: bool,
    pub no_preflight: bool,
    pub pricing: HashMap<String, ModelPricing>,
    pub run_pipeline: bool,
    pub allow_cross_provider: bool,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let bind_addr = std::env::var("GATEWAY_BIND")
            .or_else(|_| std::env::var("GATEWAY_PORT").map(|port| format!("127.0.0.1:{port}")))
            .unwrap_or_else(|_| DEFAULT_GATEWAY_BIND.to_string())
            .parse()?;
        let openai_base_url = std::env::var("CHISEI_OPENAI_BASE_URL")
            .or_else(|_| std::env::var("OPENAI_BASE_URL"))
            .unwrap_or_else(|_| DEFAULT_OPENAI_BASE_URL.to_string());
        let openai_api_key = std::env::var("OPENAI_API_KEY").ok();
        let anthropic_base_url = std::env::var("CHISEI_ANTHROPIC_BASE_URL")
            .or_else(|_| std::env::var("ANTHROPIC_BASE_URL"))
            .unwrap_or_else(|_| DEFAULT_ANTHROPIC_BASE_URL.to_string());
        let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok();
        let allow_auth_passthrough = matches!(
            std::env::var("CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        let rewrite_openai_passthrough_auth = matches!(
            std::env::var("CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        let no_preflight = matches!(
            std::env::var("CHISEI_GATEWAY_NO_PREFLIGHT")
                .or_else(|_| std::env::var("GATEWAY_NO_PREFLIGHT"))
                .as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        if openai_api_key.is_none() && anthropic_api_key.is_none() && !allow_auth_passthrough {
            return Err(
                "OPENAI_API_KEY or ANTHROPIC_API_KEY must be set for chisei-gateway".into(),
            );
        }
        let chisei_grpc_target = std::env::var("CHISEI_GRPC_URL")
            .or_else(|_| std::env::var("SEKAI_SOCKET"))
            .ok()
            .filter(|value| !value.trim().is_empty());
        let fail_closed = matches!(
            std::env::var("GATEWAY_GOVERNANCE_FAILURE").as_deref(),
            Ok("closed") | Ok("fail-closed") | Ok("1") | Ok("true")
        );
        if fail_closed && chisei_grpc_target.is_none() {
            return Err(
                "GATEWAY_GOVERNANCE_FAILURE is enabled, but CHISEI_GRPC_URL/SEKAI_SOCKET is not set".into(),
            );
        }
        if chisei_grpc_target.is_none() {
            eprintln!(
                "warning: CHISEI_GRPC_URL/SEKAI_SOCKET is unset; running without control-plane governance"
            );
        }
        let default_project =
            std::env::var("GATEWAY_DEFAULT_PROJECT").unwrap_or_else(|_| "default".to_string());
        let gateway_keys = parse_gateway_keys(
            &std::env::var("GATEWAY_KEYS").unwrap_or_default(),
            &default_project,
        )?;
        let pricing = parse_pricing_table(
            &std::env::var("CHISEI_GATEWAY_PRICING")
                .or_else(|_| std::env::var("GATEWAY_PRICING"))
                .unwrap_or_default(),
        )?;
        let run_pipeline = matches!(
            std::env::var("CHISEI_GATEWAY_RUN_PIPELINE").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        let allow_cross_provider = matches!(
            std::env::var("CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );

        Ok(Self {
            bind_addr,
            openai_base_url,
            openai_api_key,
            anthropic_base_url,
            anthropic_api_key,
            chisei_grpc_target,
            fail_closed,
            default_project,
            gateway_keys,
            allow_auth_passthrough,
            rewrite_openai_passthrough_auth,
            no_preflight,
            pricing,
            run_pipeline,
            allow_cross_provider,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelPricing {
    pub input_usd_micros_per_million: i64,
    pub output_usd_micros_per_million: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayIdentity {
    pub agent: String,
    pub project: String,
    pub user_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamAuthMode {
    GatewayKey,
    Passthrough,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityContext {
    identity: GatewayIdentity,
    upstream_auth: UpstreamAuthMode,
}

#[derive(Clone)]
struct GatewayState {
    client: reqwest::Client,
    config: Arc<GatewayConfig>,
    runtime: GatewayRuntime,
}

#[derive(Clone)]
struct GatewayRuntime {
    key_cache: Arc<RwLock<HashMap<String, KeyCacheEntry>>>,
    key_cache_ttl: Duration,
    admin_token: Option<String>,
}

impl GatewayRuntime {
    fn from_env() -> Self {
        let key_cache_ttl = std::env::var("CHISEI_GATEWAY_KEY_CACHE_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS));
        Self::new(
            key_cache_ttl,
            std::env::var("CHISEI_GATEWAY_ADMIN_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        )
    }

    fn new(key_cache_ttl: Duration, admin_token: Option<String>) -> Self {
        Self {
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            key_cache_ttl,
            admin_token,
        }
    }
}

#[derive(Debug, Clone)]
struct KeyCacheEntry {
    identity: Option<GatewayIdentity>,
    cached_at: Instant,
}

pub fn app(config: GatewayConfig) -> Router {
    app_with_runtime(config, GatewayRuntime::from_env())
}

fn app_with_runtime(config: GatewayConfig, runtime: GatewayRuntime) -> Router {
    let state = GatewayState {
        client: reqwest::Client::new(),
        config: Arc::new(config),
        runtime,
    };

    Router::new()
        .route("/_chisei/admin/refresh", post(refresh_gateway_admin))
        .route("/{*path}", any(proxy_gateway))
        .with_state(state)
}

pub async fn serve(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = config.bind_addr;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("chisei-gateway listening on http://{}", bind_addr);
    axum::serve(listener, app(config)).await?;
    Ok(())
}

async fn refresh_gateway_admin(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response<Body> {
    if !admin_authorized(&headers, &state.runtime) {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "invalid chisei gateway admin token",
        );
    }
    let mut cache = state.runtime.key_cache.write().await;
    let cleared_entries = cache.len();
    cache.clear();
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "refreshed": true,
            "cleared_key_cache_entries": cleared_entries
        }),
    )
}

fn admin_authorized(headers: &HeaderMap, runtime: &GatewayRuntime) -> bool {
    let Some(expected) = runtime.admin_token.as_deref() else {
        return true;
    };
    let Some(token) = client_key(headers) else {
        return false;
    };
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}

async fn proxy_gateway(
    State(state): State<GatewayState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let Some(upstream_target) = upstream_url(&state.config, &uri) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "chisei-gateway currently supports /v1/responses, /v1/chat/completions, /v1/models, /v1/messages, and /v1/messages/count_tokens",
        );
    };
    let identity_context = match resolve_identity(&headers, &state).await {
        Ok(identity) => identity,
        Err(err) => {
            record_gateway_event(
                &state.config,
                "chisei-gateway",
                "gateway.auth_failed",
                err.reason(),
                "denied",
                err.evidence(&state.config),
            )
            .await;
            return err.response();
        }
    };
    let identity = identity_context.identity;

    let body = match to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("failed to read request body: {err}"),
            );
        }
    };
    let request_bytes = body.len();
    let requested_model = extract_request_model(&body);
    let request_id = uuid::Uuid::new_v4().to_string();
    let work_unit_id = gateway_work_unit_id(&headers).map(ToOwned::to_owned);
    let pipeline_spec = extract_gateway_pipeline_spec(&body);
    let started_ms = Utc::now().timestamp_millis();
    let preflight_context = UsageContext {
        request_id: request_id.clone(),
        provider: upstream_target.provider,
        requested_model: requested_model.clone(),
        resolved_model: None,
        work_unit_id: work_unit_id.clone(),
        pipeline_spec: pipeline_spec.clone(),
        request_bytes,
        started_ms,
    };
    let (resolved, egress) = if state.config.no_preflight {
        let resolved = PolicyPreflight {
            body: body.to_vec(),
            resolved_model: requested_model.clone(),
            resolved_provider: upstream_target.provider,
        };
        let egress = ContextEgressPreflight {
            body: resolved.body.clone(),
        };
        (resolved, egress)
    } else {
        if let Err(rejection) =
            check_budget_preflight(&state.config, &identity, request_bytes).await
        {
            record_refusal_and_append(&state.config, &identity, &preflight_context, &rejection)
                .await;
            return rejection.response();
        }
        let resolved = match resolve_policy_preflight(
            &state.config,
            &identity,
            upstream_target.provider,
            &body,
            requested_model.as_deref(),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(rejection) => {
                record_refusal_and_append(&state.config, &identity, &preflight_context, &rejection)
                    .await;
                return rejection.response();
            }
        };
        let egress = match apply_context_egress(
            &state.config,
            &identity,
            upstream_target.provider,
            &resolved.body,
            requested_model.as_deref(),
            resolved.resolved_model.as_deref(),
        )
        .await
        {
            Ok(egress) => egress,
            Err(response) => return response,
        };
        (resolved, egress)
    };
    let prepared = match prepare_upstream_request(
        &state.config,
        &identity,
        &uri,
        upstream_target.provider,
        resolved.resolved_provider,
        egress.body,
        resolved.resolved_model.as_deref(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(response) => return response,
    };

    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("unsupported method: {err}"),
            );
        }
    };

    let mut upstream = state
        .client
        .request(upstream_method, prepared.url)
        .body(prepared.body);
    let upstream_auth_mode = upstream_auth_mode(
        &state.config,
        identity_context.upstream_auth,
        prepared.provider,
    );
    if upstream_auth_mode == UpstreamAuthMode::GatewayKey {
        upstream = match apply_provider_auth(upstream, &state.config, prepared.provider) {
            Ok(upstream) => upstream,
            Err(response) => return response,
        };
    }
    for (name, value) in headers.iter() {
        if should_forward_request_header(name, upstream_auth_mode) {
            upstream = upstream.header(name, value);
        }
    }

    match upstream.send().await {
        Ok(resp) => {
            response_from_upstream(
                resp,
                &state.config,
                &identity,
                UsageContext {
                    request_id,
                    provider: prepared.provider,
                    requested_model,
                    resolved_model: resolved.resolved_model,
                    work_unit_id,
                    pipeline_spec,
                    request_bytes,
                    started_ms,
                },
                prepared.response_adapter,
            )
            .await
        }
        Err(err) => json_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            &format!("OpenAI upstream request failed: {err}"),
        ),
    }
}

#[derive(Debug, Clone)]
struct UsageContext {
    request_id: String,
    provider: ProviderKind,
    requested_model: Option<String>,
    resolved_model: Option<String>,
    work_unit_id: Option<String>,
    pipeline_spec: String,
    request_bytes: usize,
    started_ms: i64,
}

#[derive(Debug)]
struct GatewayRejection {
    status: StatusCode,
    error_type: String,
    reason: String,
}

impl GatewayRejection {
    fn json(status: StatusCode, error_type: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            status,
            error_type: error_type.to_string(),
            reason,
        }
    }

    fn response(&self) -> Response<Body> {
        json_error(self.status, &self.error_type, &self.reason)
    }
}

async fn check_budget_preflight(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    request_bytes: usize,
) -> Result<(), GatewayRejection> {
    let Some(target) = &config.chisei_grpc_target else {
        return Ok(());
    };
    let estimated_tokens = estimate_tokens_from_bytes(request_bytes);
    match connect_sekai(target).await {
        Ok(channel) => {
            let mut client = ChiseiServiceClient::new(channel);
            for budget_subject in gateway_budget_subjects(identity) {
                let req = GrpcRequest::new(CheckBudgetRequest {
                    user_id: budget_subject.clone(),
                    estimated_tokens,
                    subject: budget_subject.clone(),
                    project: identity.project.clone(),
                    agent: identity.agent.clone(),
                    key_id: identity.key_id.clone(),
                });
                match client.check_budget(req).await {
                    Ok(resp) => {
                        let resp = resp.into_inner();
                        if resp.allowed {
                            continue;
                        }
                        let usage = resp.usage;
                        let message = usage
                            .map(|usage| {
                                format!(
                                    "budget exceeded for {}: used {} + estimated {} > {}",
                                    usage.user_id,
                                    usage.tokens_used,
                                    estimated_tokens,
                                    usage.max_tokens
                                )
                            })
                            .unwrap_or_else(|| format!("budget exceeded for {budget_subject}"));
                        record_gateway_decision(
                            config,
                            identity,
                            "gateway.budget_denied",
                            &message,
                            "denied",
                            HashMap::from([
                                ("estimated_tokens".to_string(), estimated_tokens.to_string()),
                                ("budget_subject".to_string(), budget_subject),
                            ]),
                        )
                        .await;
                        return Err(GatewayRejection::json(
                            StatusCode::TOO_MANY_REQUESTS,
                            "budget_exceeded",
                            message,
                        ));
                    }
                    Err(err) => {
                        return governance_error(
                            config,
                            identity,
                            &format!("CheckBudget failed: {err}"),
                        )
                        .await;
                    }
                }
            }
            Ok(())
        }
        Err(err) => {
            governance_error(
                config,
                identity,
                &format!("failed to connect to Chisei control plane: {err}"),
            )
            .await
        }
    }
}

fn gateway_budget_subjects(identity: &GatewayIdentity) -> Vec<String> {
    let mut subjects = vec![identity.user_id.clone()];
    let project_subject = format!("project:{}", identity.project);
    if !identity.project.trim().is_empty() && !subjects.contains(&project_subject) {
        subjects.push(project_subject);
    }
    subjects
}

#[derive(Debug, Clone)]
struct PolicyPreflight {
    body: Vec<u8>,
    resolved_model: Option<String>,
    resolved_provider: ProviderKind,
}

#[derive(Debug, Clone)]
struct ContextEgressPreflight {
    body: Vec<u8>,
}

async fn resolve_policy_preflight(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    provider: ProviderKind,
    body: &[u8],
    requested_model: Option<&str>,
) -> Result<PolicyPreflight, GatewayRejection> {
    let Some(requested_model) = requested_model else {
        return Ok(PolicyPreflight {
            body: body.to_vec(),
            resolved_model: None,
            resolved_provider: provider,
        });
    };
    let Some(target) = &config.chisei_grpc_target else {
        return Ok(PolicyPreflight {
            body: body.to_vec(),
            resolved_model: Some(requested_model.to_string()),
            resolved_provider: provider,
        });
    };
    match connect_sekai(target).await {
        Ok(channel) => {
            let mut client = ChiseiServiceClient::new(channel);
            let req = GrpcRequest::new(ResolvePolicyRequest {
                namespace: identity.project.clone(),
                preferred_runtime: provider.runtime_name().to_string(),
                preferred_model: requested_model.to_string(),
                subject: identity.user_id.clone(),
                project: identity.project.clone(),
                agent: identity.agent.clone(),
                key_id: identity.key_id.clone(),
            });
            match client.resolve_policy(req).await {
                Ok(resp) => {
                    let resolution = resp.into_inner().resolution.ok_or_else(|| {
                        GatewayRejection::json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "governance_unavailable",
                            "Chisei returned an empty policy resolution",
                        )
                    })?;
                    let Some(resolved_provider) = ProviderKind::from_runtime(&resolution.runtime)
                    else {
                        return policy_denied(
                            config,
                            identity,
                            requested_model,
                            &resolution.model,
                            &format!(
                                "policy resolved unsupported runtime {:?}",
                                resolution.runtime
                            ),
                        )
                        .await;
                    };
                    if !provider.same_family(resolved_provider) && !config.allow_cross_provider {
                        return policy_denied(
                            config,
                            identity,
                            requested_model,
                            &resolution.model,
                            &format!(
                                "policy resolved unsupported runtime {:?}",
                                resolution.runtime
                            ),
                        )
                        .await;
                    }
                    if !resolved_provider.is_compatible_model(&resolution.model) {
                        return policy_denied(
                            config,
                            identity,
                            requested_model,
                            &resolution.model,
                            &format!(
                                "policy resolved unsupported {} proxy model {:?}",
                                resolved_provider.runtime_name(),
                                resolution.model
                            ),
                        )
                        .await;
                    }
                    if resolution.eval_regressed {
                        record_gateway_decision(
                            config,
                            identity,
                            "gateway.eval_regression",
                            "eval regression signal influenced gateway routing",
                            "routed",
                            HashMap::from([
                                ("requested_model".to_string(), requested_model.to_string()),
                                ("resolved_model".to_string(), resolution.model.clone()),
                                ("project".to_string(), identity.project.clone()),
                                (
                                    "reason".to_string(),
                                    resolution.eval_regression_reason.clone(),
                                ),
                            ]),
                        )
                        .await;
                    }
                    let next_body = if resolution.model == requested_model {
                        body.to_vec()
                    } else {
                        let rewritten =
                            rewrite_request_model(body, &resolution.model).map_err(|err| {
                                GatewayRejection::json(
                                    StatusCode::BAD_REQUEST,
                                    "invalid_request_error",
                                    &format!("failed to rewrite request model: {err}"),
                                )
                            })?;
                        record_gateway_decision(
                            config,
                            identity,
                            "gateway.model_rewrite",
                            "model rewritten by Chisei policy",
                            "rewritten",
                            HashMap::from([
                                ("requested_model".to_string(), requested_model.to_string()),
                                ("resolved_model".to_string(), resolution.model.clone()),
                                ("project".to_string(), identity.project.clone()),
                            ]),
                        )
                        .await;
                        rewritten
                    };
                    Ok(PolicyPreflight {
                        body: next_body,
                        resolved_model: Some(resolution.model),
                        resolved_provider,
                    })
                }
                Err(err) if err.code() == tonic::Code::InvalidArgument => {
                    policy_denied(
                        config,
                        identity,
                        requested_model,
                        requested_model,
                        &format!("policy denied request: {err}"),
                    )
                    .await
                }
                Err(err) => {
                    governance_error(config, identity, &format!("ResolvePolicy failed: {err}"))
                        .await?;
                    Ok(PolicyPreflight {
                        body: body.to_vec(),
                        resolved_model: Some(requested_model.to_string()),
                        resolved_provider: provider,
                    })
                }
            }
        }
        Err(err) => {
            governance_error(
                config,
                identity,
                &format!("failed to connect to Chisei control plane: {err}"),
            )
            .await?;
            Ok(PolicyPreflight {
                body: body.to_vec(),
                resolved_model: Some(requested_model.to_string()),
                resolved_provider: provider,
            })
        }
    }
}

async fn policy_denied(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    requested_model: &str,
    resolved_model: &str,
    reason: &str,
) -> Result<PolicyPreflight, GatewayRejection> {
    record_gateway_decision(
        config,
        identity,
        "gateway.policy_denied",
        reason,
        "denied",
        HashMap::from([
            ("requested_model".to_string(), requested_model.to_string()),
            ("resolved_model".to_string(), resolved_model.to_string()),
            ("project".to_string(), identity.project.clone()),
        ]),
    )
    .await;
    Err(GatewayRejection::json(
        StatusCode::FORBIDDEN,
        "policy_denied",
        reason,
    ))
}

fn is_openai_compatible_model(model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    if model.is_empty() || model.starts_with("claude") {
        return false;
    }
    if model.starts_with("native-") || model.starts_with("ollama/") {
        return true;
    }
    const NON_OPENAI_PREFIXES: &[&str] = &[
        "gemini",
        "vertex",
        "palm",
        "bedrock",
        "anthropic",
        "azure",
        "cohere",
        "claude",
    ];

    !NON_OPENAI_PREFIXES
        .iter()
        .any(|prefix| model.starts_with(prefix))
}

fn rewrite_request_model(body: &[u8], model: &str) -> Result<Vec<u8>, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_slice(body)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "model".to_string(),
            serde_json::Value::String(model.to_string()),
        );
    }
    serde_json::to_vec(&value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseAdapter {
    Passthrough,
    OpenAiChatToAnthropicMessage,
}

#[derive(Debug, Clone)]
struct PreparedUpstreamRequest {
    provider: ProviderKind,
    url: String,
    body: Vec<u8>,
    response_adapter: ResponseAdapter,
}

async fn prepare_upstream_request(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    uri: &Uri,
    client_provider: ProviderKind,
    resolved_provider: ProviderKind,
    body: Vec<u8>,
    resolved_model: Option<&str>,
) -> Result<PreparedUpstreamRequest, Response<Body>> {
    if client_provider == resolved_provider || client_provider.same_family(resolved_provider) {
        return Ok(PreparedUpstreamRequest {
            provider: client_provider,
            url: upstream_url_for_provider(config, uri, client_provider),
            body,
            response_adapter: ResponseAdapter::Passthrough,
        });
    }
    if client_provider == ProviderKind::Anthropic
        && resolved_provider.is_openai()
        && is_anthropic_messages_path(uri.path())
    {
        if request_stream_enabled(&body) {
            let reason =
                "cross-provider Anthropic to OpenAI streaming translation is not supported";
            record_gateway_decision(
                config,
                identity,
                "gateway.cross_provider_denied",
                reason,
                "denied",
                HashMap::from([
                    (
                        "client_provider".to_string(),
                        client_provider.runtime_name().to_string(),
                    ),
                    (
                        "resolved_provider".to_string(),
                        resolved_provider.runtime_name().to_string(),
                    ),
                ]),
            )
            .await;
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_cross_provider_stream",
                reason,
            ));
        }
        let resolved_model = resolved_model.ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "cross-provider translation requires a resolved model",
            )
        })?;
        let translated =
            anthropic_messages_to_openai_chat(&body, resolved_model).map_err(|err| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("failed to translate Anthropic request to OpenAI: {err}"),
                )
            })?;
        record_gateway_decision(
            config,
            identity,
            "gateway.cross_provider_translate",
            "translated Anthropic Messages request to OpenAI Chat Completions",
            "translated",
            HashMap::from([
                (
                    "client_provider".to_string(),
                    client_provider.runtime_name().to_string(),
                ),
                (
                    "resolved_provider".to_string(),
                    resolved_provider.runtime_name().to_string(),
                ),
                ("resolved_model".to_string(), resolved_model.to_string()),
                ("project".to_string(), identity.project.clone()),
            ]),
        )
        .await;
        return Ok(PreparedUpstreamRequest {
            provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            url: openai_chat_completions_url(config, uri),
            body: translated,
            response_adapter: ResponseAdapter::OpenAiChatToAnthropicMessage,
        });
    }
    let reason = format!(
        "cross-provider translation from {} to {} is not supported",
        client_provider.runtime_name(),
        resolved_provider.runtime_name()
    );
    record_gateway_decision(
        config,
        identity,
        "gateway.cross_provider_denied",
        &reason,
        "denied",
        HashMap::from([
            (
                "client_provider".to_string(),
                client_provider.runtime_name().to_string(),
            ),
            (
                "resolved_provider".to_string(),
                resolved_provider.runtime_name().to_string(),
            ),
        ]),
    )
    .await;
    Err(json_error(
        StatusCode::FORBIDDEN,
        "unsupported_cross_provider_route",
        &reason,
    ))
}

fn upstream_url_for_provider(config: &GatewayConfig, uri: &Uri, provider: ProviderKind) -> String {
    upstream_url(config, uri)
        .filter(|target| target.provider == provider)
        .map(|target| target.url)
        .unwrap_or_else(|| openai_chat_completions_url(config, uri))
}

fn openai_chat_completions_url(config: &GatewayConfig, uri: &Uri) -> String {
    let mut url = format!(
        "{}/chat/completions",
        config.openai_base_url.trim_end_matches('/')
    );
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    url
}

fn is_anthropic_messages_path(path: &str) -> bool {
    (path == "/v1/messages" || path == "/messages")
        || (path.starts_with("/v1/messages/") || path.starts_with("/messages/"))
            && !path.contains("count_tokens")
}

fn request_stream_enabled(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}

fn anthropic_messages_to_openai_chat(
    body: &[u8],
    resolved_model: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let mut messages = Vec::new();
    if let Some(system) = value.get("system") {
        let system_text = anthropic_content_to_text(system);
        if !system_text.trim().is_empty() {
            messages.push(serde_json::json!({"role": "system", "content": system_text}));
        }
    }
    if let Some(items) = value
        .get("messages")
        .and_then(|messages| messages.as_array())
    {
        for item in items {
            let role = item
                .get("role")
                .and_then(|role| role.as_str())
                .unwrap_or("user");
            let content = item
                .get("content")
                .map(anthropic_content_to_text)
                .unwrap_or_default();
            messages.push(serde_json::json!({
                "role": if role == "assistant" { "assistant" } else { "user" },
                "content": content,
            }));
        }
    }
    let mut out = serde_json::json!({
        "model": resolved_model,
        "messages": messages,
    });
    if let Some(max_tokens) = value.get("max_tokens")
        && let Some(object) = out.as_object_mut()
    {
        object.insert("max_tokens".to_string(), max_tokens.clone());
    }
    if let Some(temperature) = value.get("temperature")
        && let Some(object) = out.as_object_mut()
    {
        object.insert("temperature".to_string(), temperature.clone());
    }
    serde_json::to_vec(&out)
}

fn anthropic_content_to_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                if item.get("type").and_then(|value| value.as_str()) == Some("text") {
                    item.get("text")
                        .and_then(|text| text.as_str())
                        .map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn openai_chat_to_anthropic_message(
    body: &[u8],
    resolved_model: Option<&str>,
) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let choice = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first());
    let text = choice
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .unwrap_or_default();
    let finish_reason = choice
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(|reason| reason.as_str())
        .unwrap_or("stop");
    let stop_reason = match finish_reason {
        "length" => "max_tokens",
        "tool_calls" | "function_call" => "tool_use",
        _ => "end_turn",
    };
    let usage = value.get("usage");
    let input_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens"))
        .and_then(|tokens| tokens.as_i64())
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(|tokens| tokens.as_i64())
        .unwrap_or(0);
    let model = resolved_model
        .map(str::to_string)
        .or_else(|| {
            value
                .get("model")
                .and_then(|model| model.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({
        "id": value.get("id").and_then(|id| id.as_str()).unwrap_or("msg_chisei"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    }))
}

async fn apply_context_egress(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    provider: ProviderKind,
    body: &[u8],
    requested_model: Option<&str>,
    resolved_model: Option<&str>,
) -> Result<ContextEgressPreflight, Response<Body>> {
    let Some(target) = &config.chisei_grpc_target else {
        return Ok(ContextEgressPreflight {
            body: body.to_vec(),
        });
    };
    let refs = extract_gateway_object_refs(&identity.project, body);
    if refs.is_empty() {
        return Ok(ContextEgressPreflight {
            body: body.to_vec(),
        });
    }
    let Ok(channel) = connect_sekai(target).await else {
        return Ok(ContextEgressPreflight {
            body: body.to_vec(),
        });
    };
    let mut sekai = SekaiServiceClient::new(channel);
    let mut included_count = 0usize;
    let mut redacted_count = 0usize;
    let mut decisions = 0usize;
    let mut object_refs = Vec::new();
    let mut context_lines = Vec::new();

    for external_id in refs {
        let object = match sekai
            .find_by_external_id(gateway_request(FindByExternalIdRequest {
                external_id: external_id.clone(),
            }))
            .await
        {
            Ok(resp) => resp.into_inner().object,
            Err(_) => None,
        };
        let Some(object) = object else {
            continue;
        };
        let domain_object = domain_object_from_proto(&object);
        let mut record = crate::chisei::egress::new_record(&domain_object);
        let mut included_fields = Vec::new();
        for field in gateway_egress_fields(&domain_object) {
            if let Some(value) =
                crate::chisei::egress::filter_property(&domain_object, field, &mut record, true)
            {
                included_fields.push(format!("{field}: {value}"));
            }
        }
        if record.included_fields.is_empty() && record.redacted_fields.is_empty() {
            continue;
        }
        if !included_fields.is_empty() {
            if crate::chisei::egress::include_identity(&domain_object) {
                context_lines.push(format!(
                    "object {} ({}) [{}] {}",
                    domain_object.kind,
                    domain_object.name,
                    domain_object.external_id,
                    included_fields.join(", ")
                ));
            } else {
                context_lines.push(format!("object context {}", included_fields.join(", ")));
            }
        }
        included_count += record.included_fields.len();
        redacted_count += record.redacted_fields.len();
        decisions += 1;
        object_refs.push(record.object_ref);
    }

    if decisions == 0 {
        return Ok(ContextEgressPreflight {
            body: body.to_vec(),
        });
    }
    let mut rewritten = false;
    let next_body = if context_lines.is_empty() {
        body.to_vec()
    } else {
        match inject_gateway_context(provider, body, &context_lines.join("\n")) {
            Ok(Some(next_body)) => {
                rewritten = true;
                next_body
            }
            Ok(None) => body.to_vec(),
            Err(err) => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("failed to inject object context: {err}"),
                ));
            }
        }
    };

    record_gateway_decision(
        config,
        identity,
        "gateway.egress",
        "context egress policy applied",
        if redacted_count > 0 {
            "redacted"
        } else {
            "included"
        },
        HashMap::from([
            ("provider".to_string(), provider.runtime_name().to_string()),
            (
                "requested_model".to_string(),
                requested_model.unwrap_or_default().to_string(),
            ),
            (
                "resolved_model".to_string(),
                resolved_model.unwrap_or_default().to_string(),
            ),
            ("decisions".to_string(), decisions.to_string()),
            ("included_count".to_string(), included_count.to_string()),
            ("redacted_count".to_string(), redacted_count.to_string()),
            ("object_refs".to_string(), object_refs.join(",")),
            ("payload_rewritten".to_string(), rewritten.to_string()),
        ]),
    )
    .await;
    Ok(ContextEgressPreflight { body: next_body })
}

fn inject_gateway_context(
    provider: ProviderKind,
    body: &[u8],
    context: &str,
) -> Result<Option<Vec<u8>>, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_slice(body)?;
    let context = format!("[Object context]\n{context}");
    let Some(object) = value.as_object_mut() else {
        return Ok(None);
    };

    if provider == ProviderKind::Anthropic {
        if object.contains_key("system") {
            match object.get_mut("system") {
                Some(serde_json::Value::String(system)) => {
                    system.push_str("\n\n");
                    system.push_str(&context);
                    return serde_json::to_vec(&value).map(Some);
                }
                Some(serde_json::Value::Array(system)) => {
                    system.push(serde_json::json!({
                        "type": "text",
                        "text": context,
                    }));
                    return serde_json::to_vec(&value).map(Some);
                }
                _ => {}
            }
        } else if object.contains_key("messages") {
            object.insert("system".to_string(), serde_json::Value::String(context));
            return serde_json::to_vec(&value).map(Some);
        }
        return Ok(None);
    }

    if let Some(input) = object.get_mut("input") {
        match input {
            serde_json::Value::String(text) => {
                text.push_str("\n\n");
                text.push_str(&context);
                return serde_json::to_vec(&value).map(Some);
            }
            serde_json::Value::Array(items) => {
                items.push(serde_json::json!({
                    "role": "system",
                    "content": context,
                }));
                return serde_json::to_vec(&value).map(Some);
            }
            _ => {}
        }
    }

    if let Some(messages) = object
        .get_mut("messages")
        .and_then(|value| value.as_array_mut())
    {
        messages.push(serde_json::json!({
            "role": "system",
            "content": context,
        }));
        return serde_json::to_vec(&value).map(Some);
    }

    Ok(None)
}

fn extract_gateway_object_refs(project: &str, body: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for text in json_strings(&value) {
        for (kind, value) in extract_object_refs_from_text(text) {
            let external_id = format!("{kind}:{value}");
            if seen.insert(external_id.clone()) {
                refs.push(external_id);
            }
        }
    }
    if let Some((kind, value)) = parse_gateway_object_ref(project) {
        let external_id = format!("{kind}:{value}");
        if seen.insert(external_id.clone()) {
            refs.push(external_id);
        }
    }
    refs
}

fn json_strings(value: &serde_json::Value) -> Vec<&str> {
    match value {
        serde_json::Value::String(text) => vec![text.as_str()],
        serde_json::Value::Array(values) => values.iter().flat_map(json_strings).collect(),
        serde_json::Value::Object(object) => object.values().flat_map(json_strings).collect(),
        _ => Vec::new(),
    }
}

fn extract_object_refs_from_text(text: &str) -> Vec<(String, String)> {
    text.split_whitespace()
        .filter_map(parse_gateway_object_ref)
        .collect()
}

fn parse_gateway_object_ref(text: &str) -> Option<(String, String)> {
    let token = text
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')'));
    let (raw_kind, raw_value) = token.split_once(':')?;
    if raw_kind.is_empty() || raw_value.is_empty() {
        return None;
    }
    let kind = normalize_gateway_identifier(raw_kind)?;
    let mut value =
        raw_value.trim_matches(|c| matches!(c, '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')'));
    if value.starts_with('{') && value.ends_with('}') && value.len() > 2 {
        value = &value[1..value.len() - 1];
    }
    let value = normalize_gateway_identifier(value)?;
    Some((kind, value))
}

fn normalize_gateway_identifier(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches(|c| c == '_' || c == '-');
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn gateway_egress_fields(object: &crate::domain::Object) -> Vec<&str> {
    const CANDIDATE_FIELDS: [&str; 9] = [
        "verdict",
        "prior_verdict",
        "conviction",
        "conviction_score",
        "confidence",
        "confidence_score",
        "score",
        "success_rate",
        "prevention",
    ];
    CANDIDATE_FIELDS
        .into_iter()
        .filter(|field| {
            object
                .properties
                .get(*field)
                .is_some_and(|value| !value.is_empty())
        })
        .collect()
}

fn domain_object_from_proto(object: &SekaiObject) -> crate::domain::Object {
    crate::domain::Object {
        id: object.id.clone(),
        kind: object.kind.clone(),
        name: object.name.clone(),
        namespace: object.namespace.clone(),
        external_id: object.external_id.clone(),
        properties: object.properties.clone(),
        created: object.created,
        updated: object.updated,
    }
}

async fn governance_error(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    message: &str,
) -> Result<(), GatewayRejection> {
    record_gateway_decision(
        config,
        identity,
        "gateway.governance_unavailable",
        message,
        if config.fail_closed {
            "fail_closed"
        } else {
            "fail_open"
        },
        HashMap::from([("fail_closed".to_string(), config.fail_closed.to_string())]),
    )
    .await;
    if config.fail_closed {
        Err(GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_unavailable",
            message,
        ))
    } else {
        eprintln!("chisei-gateway governance fail-open: {message}");
        Ok(())
    }
}

fn estimate_tokens_from_bytes(request_bytes: usize) -> i32 {
    ((request_bytes + 3) / 4).min(i32::MAX as usize) as i32
}

async fn resolve_identity(
    headers: &HeaderMap,
    state: &GatewayState,
) -> Result<IdentityContext, IdentityError> {
    let config = &state.config;
    let Some(key) = client_key(headers) else {
        return Err(IdentityError::MissingKey);
    };
    if config.allow_auth_passthrough {
        if let Some(identity) = passthrough_identity(headers, &config.default_project) {
            return Ok(IdentityContext {
                identity,
                upstream_auth: UpstreamAuthMode::Passthrough,
            });
        }
    }

    if let Some(identity) = config.gateway_keys.get(key) {
        return Ok(IdentityContext {
            identity: identity.clone(),
            upstream_auth: UpstreamAuthMode::GatewayKey,
        });
    }
    if !config.gateway_keys.is_empty() {
        return Err(IdentityError::UnknownKey);
    }

    if let Some(identity) = resolve_identity_from_key_store(state, key).await? {
        return Ok(IdentityContext {
            identity,
            upstream_auth: UpstreamAuthMode::GatewayKey,
        });
    }

    Ok(IdentityContext {
        identity: derive_identity_from_key(key, &config.default_project),
        upstream_auth: UpstreamAuthMode::GatewayKey,
    })
}

async fn resolve_identity_from_key_store(
    state: &GatewayState,
    key: &str,
) -> Result<Option<GatewayIdentity>, IdentityError> {
    let config = &state.config;
    let Some(target) = &config.chisei_grpc_target else {
        return Ok(None);
    };
    let key_hash = hash_gateway_key(key);
    if let Some(entry) = cached_gateway_key_identity(state, &key_hash).await {
        return entry.identity.ok_or(IdentityError::UnknownKey).map(Some);
    }
    let channel = connect_sekai(target)
        .await
        .map_err(|_| IdentityError::KeyStoreUnavailable)?;
    let mut sekai = SekaiServiceClient::new(channel);
    let resp = match sekai
        .find_by_property(gateway_request(FindByPropertyRequest {
            kind: "gateway_key".to_string(),
            key: "key_hash".to_string(),
            value: key_hash.clone(),
        }))
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(_) => return Err(IdentityError::KeyStoreUnavailable),
    };
    let object = resp.objects.into_iter().find(|object| {
        object
            .properties
            .get("status")
            .map(|status| status == "active")
            .unwrap_or(true)
    });
    let Some(object) = object else {
        cache_gateway_key_identity(state, key_hash, None).await;
        return Err(IdentityError::UnknownKey);
    };
    let Some(agent) = object
        .properties
        .get("agent")
        .filter(|value| !value.is_empty())
    else {
        cache_gateway_key_identity(state, key_hash, None).await;
        return Err(IdentityError::UnknownKey);
    };
    let project = object
        .properties
        .get("project")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| config.default_project.clone());
    let identity = GatewayIdentity {
        agent: agent.clone(),
        project,
        user_id: format!("agent:{agent}"),
        key_id: object.name.clone(),
    };
    cache_gateway_key_identity(state, key_hash, Some(identity.clone())).await;
    Ok(Some(identity))
}

async fn cached_gateway_key_identity(
    state: &GatewayState,
    key_hash: &str,
) -> Option<KeyCacheEntry> {
    let cache = state.runtime.key_cache.read().await;
    let entry = cache.get(key_hash)?;
    if entry.cached_at.elapsed() < state.runtime.key_cache_ttl {
        return Some(entry.clone());
    }
    None
}

async fn cache_gateway_key_identity(
    state: &GatewayState,
    key_hash: String,
    identity: Option<GatewayIdentity>,
) {
    state.runtime.key_cache.write().await.insert(
        key_hash,
        KeyCacheEntry {
            identity,
            cached_at: Instant::now(),
        },
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityError {
    MissingKey,
    UnknownKey,
    KeyStoreUnavailable,
}

impl IdentityError {
    fn reason(self) -> &'static str {
        match self {
            Self::MissingKey => "missing gateway key",
            Self::UnknownKey => "unknown chisei gateway key",
            Self::KeyStoreUnavailable => "gateway key store unavailable",
        }
    }

    fn evidence(self, config: &GatewayConfig) -> HashMap<String, String> {
        HashMap::from([
            (
                "allowlist_enabled".to_string(),
                (!config.gateway_keys.is_empty()).to_string(),
            ),
            (
                "key_store_configured".to_string(),
                config.chisei_grpc_target.is_some().to_string(),
            ),
            (
                "presented_key".to_string(),
                matches!(self, Self::UnknownKey).to_string(),
            ),
        ])
    }

    fn response(self) -> Response<Body> {
        let status = match self {
            Self::KeyStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        };
        json_error(status, "authentication_error", self.reason())
    }
}

fn client_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .or_else(|| headers.get(X_API_KEY).and_then(|value| value.to_str().ok()))
        .filter(|value| !value.trim().is_empty())
}

fn passthrough_identity(headers: &HeaderMap, default_project: &str) -> Option<GatewayIdentity> {
    let agent = header_str(headers, &X_CHISEI_AGENT)?;
    let project = header_str(headers, &X_CHISEI_PROJECT).unwrap_or(default_project);
    Some(GatewayIdentity {
        user_id: format!("agent:{agent}"),
        agent: agent.to_string(),
        project: project.to_string(),
        key_id: String::new(),
    })
}

fn gateway_work_unit_id(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, &X_CHISEI_WORK_UNIT).or_else(|| header_str(headers, &X_CHISEI_TASK_ID))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn derive_identity_from_key(key: &str, default_project: &str) -> GatewayIdentity {
    let agent = key
        .strip_prefix("sk-chisei-")
        .unwrap_or("unknown")
        .to_string();
    GatewayIdentity {
        user_id: format!("agent:{agent}"),
        key_id: agent.clone(),
        agent,
        project: default_project.to_string(),
    }
}

fn parse_gateway_keys(
    spec: &str,
    default_project: &str,
) -> Result<HashMap<String, GatewayIdentity>, Box<dyn std::error::Error>> {
    let mut keys = HashMap::new();
    for entry in spec
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            format!("invalid GATEWAY_KEYS entry {entry:?}; expected key=agent:project")
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err("invalid GATEWAY_KEYS entry with empty key".into());
        }
        let (agent, project) = value
            .split_once(':')
            .map(|(agent, project)| (agent.trim(), project.trim()))
            .unwrap_or((value.trim(), default_project));
        if agent.is_empty() {
            return Err(format!("invalid GATEWAY_KEYS entry {entry:?}; empty agent").into());
        }
        let project = if project.is_empty() {
            default_project
        } else {
            project
        };
        keys.insert(
            key.to_string(),
            GatewayIdentity {
                agent: agent.to_string(),
                project: project.to_string(),
                user_id: format!("agent:{agent}"),
                key_id: agent.to_string(),
            },
        );
    }
    Ok(keys)
}

fn parse_pricing_table(
    spec: &str,
) -> Result<HashMap<String, ModelPricing>, Box<dyn std::error::Error>> {
    let mut pricing = HashMap::new();
    for entry in spec
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (model, rates) = entry.split_once('=').ok_or_else(|| {
            format!(
                "invalid gateway pricing entry {entry:?}; expected model=input_usd_per_1m:output_usd_per_1m"
            )
        })?;
        let model = model.trim();
        if model.is_empty() {
            return Err("invalid gateway pricing entry with empty model".into());
        }
        let (input, output) = rates.split_once(':').ok_or_else(|| {
            format!(
                "invalid gateway pricing rates for {model:?}; expected input_usd_per_1m:output_usd_per_1m"
            )
        })?;
        pricing.insert(
            model.to_string(),
            ModelPricing {
                input_usd_micros_per_million: parse_usd_micros(input.trim())?,
                output_usd_micros_per_million: parse_usd_micros(output.trim())?,
            },
        );
    }
    Ok(pricing)
}

fn parse_usd_micros(value: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return Err(format!("invalid non-negative USD value {value:?}").into());
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 6 || !fraction.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid USD value {value:?}; use at most 6 decimal places").into());
    }
    let whole_micros = whole
        .parse::<i64>()
        .map_err(|_| format!("invalid USD value {value:?}"))?
        .checked_mul(1_000_000)
        .ok_or("USD value is too large")?;
    let mut padded_fraction = fraction.to_string();
    while padded_fraction.len() < 6 {
        padded_fraction.push('0');
    }
    let fraction_micros = if padded_fraction.is_empty() {
        0
    } else {
        padded_fraction
            .parse::<i64>()
            .map_err(|_| format!("invalid USD value {value:?}"))?
    };
    whole_micros
        .checked_add(fraction_micros)
        .ok_or_else(|| "USD value is too large".into())
}

fn estimate_cost_usd_micros(
    config: &GatewayConfig,
    context: &UsageContext,
    usage: &ResponseUsage,
) -> Option<i64> {
    let pricing = context
        .resolved_model
        .as_ref()
        .and_then(|model| config.pricing.get(model))
        .or_else(|| {
            context
                .requested_model
                .as_ref()
                .and_then(|model| config.pricing.get(model))
        })?;
    let input =
        (usage.input_tokens as i128).checked_mul(pricing.input_usd_micros_per_million as i128)?;
    let output =
        (usage.output_tokens as i128).checked_mul(pricing.output_usd_micros_per_million as i128)?;
    let total = input.checked_add(output)?.checked_div(1_000_000)?;
    i64::try_from(total).ok()
}

fn format_usd_micros(value: i64) -> String {
    format!("{}.{:06}", value / 1_000_000, (value % 1_000_000).abs())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenAiRuntime {
    OpenAi,
    Ollama,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    OpenAi(OpenAiRuntime),
    Anthropic,
}

impl ProviderKind {
    fn from_runtime(runtime: &str) -> Option<Self> {
        match runtime {
            "openai" => Some(Self::OpenAi(OpenAiRuntime::OpenAi)),
            "ollama" => Some(Self::OpenAi(OpenAiRuntime::Ollama)),
            "native" => Some(Self::OpenAi(OpenAiRuntime::Native)),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }

    fn runtime_name(self) -> &'static str {
        match self {
            Self::OpenAi(_) => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    fn is_openai(self) -> bool {
        matches!(self, Self::OpenAi(_))
    }

    fn same_family(self, other: Self) -> bool {
        self.is_openai() == other.is_openai()
    }

    fn is_compatible_model(self, model: &str) -> bool {
        match self {
            Self::OpenAi(openai_runtime) => match openai_runtime {
                OpenAiRuntime::OpenAi => is_openai_compatible_model(model),
                OpenAiRuntime::Ollama | OpenAiRuntime::Native => !model.starts_with("claude"),
            },
            Self::Anthropic => model.starts_with("claude"),
        }
    }
}

#[derive(Debug, Clone)]
struct UpstreamTarget {
    provider: ProviderKind,
    url: String,
}

fn upstream_url(config: &GatewayConfig, uri: &Uri) -> Option<UpstreamTarget> {
    let path = uri.path();
    let (provider, base_url, upstream_path) = if let Some(rest) = path.strip_prefix("/v1/responses")
    {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/responses{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/responses") {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/responses{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/v1/chat/completions") {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/chat/completions{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/chat/completions") {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/chat/completions{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/v1/models") {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/models{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/models") {
        (
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            config.openai_base_url.as_str(),
            format!("/models{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/v1/messages/count_tokens") {
        (
            ProviderKind::Anthropic,
            config.anthropic_base_url.as_str(),
            format!("/messages/count_tokens{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/messages/count_tokens") {
        (
            ProviderKind::Anthropic,
            config.anthropic_base_url.as_str(),
            format!("/messages/count_tokens{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/v1/messages") {
        (
            ProviderKind::Anthropic,
            config.anthropic_base_url.as_str(),
            format!("/messages{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/messages") {
        (
            ProviderKind::Anthropic,
            config.anthropic_base_url.as_str(),
            format!("/messages{rest}"),
        )
    } else {
        return None;
    };
    let mut url = format!("{}{}", base_url.trim_end_matches('/'), upstream_path);
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    Some(UpstreamTarget { provider, url })
}

fn apply_provider_auth(
    upstream: reqwest::RequestBuilder,
    config: &GatewayConfig,
    provider: ProviderKind,
) -> Result<reqwest::RequestBuilder, Response<Body>> {
    match provider {
        ProviderKind::OpenAi(_) => config
            .openai_api_key
            .as_ref()
            .map(|key| upstream.bearer_auth(key))
            .ok_or_else(|| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_config_error",
                    "OPENAI_API_KEY is not configured",
                )
            }),
        ProviderKind::Anthropic => config
            .anthropic_api_key
            .as_ref()
            .map(|key| upstream.header(X_API_KEY, key))
            .ok_or_else(|| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_config_error",
                    "ANTHROPIC_API_KEY is not configured",
                )
            }),
    }
}

fn upstream_auth_mode(
    config: &GatewayConfig,
    requested_mode: UpstreamAuthMode,
    provider: ProviderKind,
) -> UpstreamAuthMode {
    if requested_mode == UpstreamAuthMode::Passthrough
        && provider.is_openai()
        && config.rewrite_openai_passthrough_auth
        && config.openai_api_key.is_some()
    {
        return UpstreamAuthMode::GatewayKey;
    }
    requested_mode
}

async fn record_usage_and_append(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    usage: Option<ResponseUsage>,
    response_observation: Option<ResponseObservation>,
    context: &UsageContext,
    status: StatusCode,
) {
    let Some(target) = &config.chisei_grpc_target else {
        return;
    };
    let elapsed_ms = Utc::now().timestamp_millis() - context.started_ms;
    let total_tokens = usage.as_ref().map(|usage| usage.total_tokens).unwrap_or(0);
    match connect_sekai(target).await {
        Ok(channel) => {
            let mut chisei = ChiseiServiceClient::new(channel.clone());
            if total_tokens > 0 {
                for budget_subject in gateway_budget_subjects(identity) {
                    if let Err(err) = chisei
                        .record_usage(GrpcRequest::new(RecordUsageRequest {
                            user_id: budget_subject.clone(),
                            tokens_used: total_tokens,
                            subject: budget_subject,
                            project: identity.project.clone(),
                            agent: identity.agent.clone(),
                            key_id: identity.key_id.clone(),
                        }))
                        .await
                    {
                        eprintln!("chisei-gateway usage record failed: {err}");
                    }
                }
            }
            let pipeline_observation =
                run_gateway_pipeline_observation(config, identity, context, &mut chisei).await;
            record_sample_observation_if_needed(
                identity,
                context,
                usage,
                response_observation.as_ref(),
                pipeline_observation.as_ref(),
                &mut chisei,
            )
            .await;

            let mut values = HashMap::new();
            values.insert("request_id".to_string(), context.request_id.clone());
            values.insert(
                "timestamp_ms".to_string(),
                Utc::now().timestamp_millis().to_string(),
            );
            values.insert("agent".to_string(), identity.agent.clone());
            values.insert("project".to_string(), identity.project.clone());
            values.insert("user_id".to_string(), identity.user_id.clone());
            if !identity.key_id.is_empty() {
                values.insert("key_id".to_string(), identity.key_id.clone());
            }
            values.insert(
                "provider".to_string(),
                context.provider.runtime_name().to_string(),
            );
            if let Some(model) = &context.requested_model {
                values.insert("model".to_string(), model.clone());
            }
            if let Some(model) = &context.resolved_model {
                values.insert("resolved_model".to_string(), model.clone());
            }
            if let Some(work_unit_id) = &context.work_unit_id {
                values.insert("work_unit_id".to_string(), work_unit_id.clone());
            }
            if let Some(observation) = &pipeline_observation {
                values.insert(
                    "pipeline_sampled".to_string(),
                    observation.sampled.to_string(),
                );
                values.insert("sample_reason".to_string(), observation.reason.clone());
                values.insert("sample_rate".to_string(), observation.rate.to_string());
            }
            values.insert("status".to_string(), status.as_u16().to_string());
            values.insert(
                "request_bytes".to_string(),
                context.request_bytes.to_string(),
            );
            values.insert("latency_ms".to_string(), elapsed_ms.max(0).to_string());
            if let Some(usage) = usage {
                values.insert("input_tokens".to_string(), usage.input_tokens.to_string());
                values.insert("output_tokens".to_string(), usage.output_tokens.to_string());
                values.insert("total_tokens".to_string(), usage.total_tokens.to_string());
                if let Some(cost_usd_micros) = estimate_cost_usd_micros(config, context, &usage) {
                    values.insert("cost_usd_micros".to_string(), cost_usd_micros.to_string());
                    values.insert("cost_usd".to_string(), format_usd_micros(cost_usd_micros));
                }
            }

            let mut sekai = SekaiServiceClient::new(channel);
            let append = AppendRowsRequest {
                dataset_id: "llm_calls".to_string(),
                rows: vec![Row {
                    values: values.clone(),
                }],
            };
            match sekai.append_rows(gateway_request(append.clone())).await {
                Ok(_) => {
                    link_work_unit_usage(&mut sekai, identity, context, &values).await;
                    record_gateway_pipeline_decision(
                        config,
                        identity,
                        context,
                        pipeline_observation,
                    )
                    .await;
                }
                Err(err) if err.code() == tonic::Code::NotFound => {
                    if let Err(create_err) = ensure_llm_calls_dataset(&mut sekai).await {
                        eprintln!("chisei-gateway llm_calls dataset create failed: {create_err}");
                        return;
                    }
                    match sekai.append_rows(gateway_request(append)).await {
                        Ok(_) => {
                            link_work_unit_usage(&mut sekai, identity, context, &values).await;
                            record_gateway_pipeline_decision(
                                config,
                                identity,
                                context,
                                pipeline_observation,
                            )
                            .await;
                        }
                        Err(append_err) => {
                            eprintln!("chisei-gateway llm_calls append failed: {append_err}");
                        }
                    }
                }
                Err(err) => {
                    eprintln!("chisei-gateway llm_calls append failed: {err}");
                }
            }
        }
        Err(err) => {
            eprintln!("chisei-gateway usage append skipped; Chisei unavailable: {err}");
        }
    }
}

async fn record_refusal_and_append(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    rejection: &GatewayRejection,
) {
    let Some(target) = &config.chisei_grpc_target else {
        return;
    };
    let elapsed_ms = Utc::now().timestamp_millis() - context.started_ms;
    let mut values = HashMap::new();
    values.insert("request_id".to_string(), context.request_id.clone());
    values.insert(
        "timestamp_ms".to_string(),
        Utc::now().timestamp_millis().to_string(),
    );
    values.insert("agent".to_string(), identity.agent.clone());
    values.insert("project".to_string(), identity.project.clone());
    values.insert("user_id".to_string(), identity.user_id.clone());
    if !identity.key_id.is_empty() {
        values.insert("key_id".to_string(), identity.key_id.clone());
    }
    values.insert(
        "provider".to_string(),
        context.provider.runtime_name().to_string(),
    );
    if let Some(model) = &context.requested_model {
        values.insert("model".to_string(), model.clone());
    }
    if let Some(model) = &context.resolved_model {
        values.insert("resolved_model".to_string(), model.clone());
    }
    if let Some(work_unit_id) = &context.work_unit_id {
        values.insert("work_unit_id".to_string(), work_unit_id.clone());
    }
    values.insert("status".to_string(), rejection.status.as_u16().to_string());
    values.insert("error_type".to_string(), rejection.error_type.clone());
    values.insert("refusal_reason".to_string(), rejection.reason.clone());
    values.insert(
        "request_bytes".to_string(),
        context.request_bytes.to_string(),
    );
    values.insert("latency_ms".to_string(), elapsed_ms.max(0).to_string());

    match connect_sekai(target).await {
        Ok(channel) => {
            let mut sekai = SekaiServiceClient::new(channel);
            let append = AppendRowsRequest {
                dataset_id: "llm_calls".to_string(),
                rows: vec![Row {
                    values: values.clone(),
                }],
            };
            match sekai.append_rows(gateway_request(append.clone())).await {
                Ok(_) => link_work_unit_usage(&mut sekai, identity, context, &values).await,
                Err(err) if err.code() == tonic::Code::NotFound => {
                    if let Err(create_err) = ensure_llm_calls_dataset(&mut sekai).await {
                        eprintln!("chisei-gateway llm_calls dataset create failed: {create_err}");
                        return;
                    }
                    match sekai.append_rows(gateway_request(append)).await {
                        Ok(_) => link_work_unit_usage(&mut sekai, identity, context, &values).await,
                        Err(append_err) => {
                            eprintln!("chisei-gateway refusal append failed: {append_err}");
                        }
                    }
                }
                Err(err) => eprintln!("chisei-gateway refusal append failed: {err}"),
            }
        }
        Err(err) => eprintln!("chisei-gateway refusal append skipped; Chisei unavailable: {err}"),
    }
}

async fn ensure_llm_calls_dataset(
    sekai: &mut SekaiServiceClient<GatewayClient>,
) -> Result<(), tonic::Status> {
    let columns = [
        "request_id",
        "timestamp_ms",
        "agent",
        "project",
        "user_id",
        "key_id",
        "provider",
        "model",
        "resolved_model",
        "work_unit_id",
        "pipeline_sampled",
        "sample_reason",
        "sample_rate",
        "status",
        "error_type",
        "refusal_reason",
        "request_bytes",
        "latency_ms",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cost_usd_micros",
        "cost_usd",
    ]
    .into_iter()
    .map(|name| ColumnDef {
        name: name.to_string(),
        r#type: "string".to_string(),
    })
    .collect();

    sekai
        .create_dataset(gateway_request(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "llm_calls".to_string(),
                name: "LLM calls".to_string(),
                columns,
                object_id: String::new(),
                created: Utc::now().timestamp_millis(),
            }),
        }))
        .await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct GatewayPipelineObservation {
    sampled: bool,
    reason: String,
    rate: f64,
    prepared_spec: String,
}

async fn run_gateway_pipeline_observation(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    chisei: &mut ChiseiServiceClient<GatewayClient>,
) -> Option<GatewayPipelineObservation> {
    if !config.run_pipeline || context.pipeline_spec.trim().is_empty() {
        return None;
    }
    let model = context
        .resolved_model
        .as_ref()
        .or(context.requested_model.as_ref())
        .cloned()
        .unwrap_or_default();
    let response = chisei
        .run_pipeline(GrpcRequest::new(RunPipelineRequest {
            request: Some(ChiseiPipelineRequest {
                request_id: context.request_id.clone(),
                namespace: identity.project.clone(),
                spec: context.pipeline_spec.clone(),
                model,
                runtime: context.provider.runtime_name().to_string(),
                task_type: "gateway_llm_call".to_string(),
                priority: 0,
            }),
        }))
        .await
        .ok()?
        .into_inner();
    let result = response.result?;
    let sampling_step = result.steps.iter().find(|step| step.step == "sampling")?;
    let value: serde_json::Value = serde_json::from_str(&sampling_step.value).ok()?;
    Some(GatewayPipelineObservation {
        sampled: value.get("sampled")?.as_bool()?,
        reason: value
            .get("reason")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        rate: value.get("effective_rate")?.as_f64()?,
        prepared_spec: result.prepared_spec,
    })
}

async fn record_sample_observation_if_needed(
    identity: &GatewayIdentity,
    context: &UsageContext,
    usage: Option<ResponseUsage>,
    response_observation: Option<&ResponseObservation>,
    pipeline_observation: Option<&GatewayPipelineObservation>,
    chisei: &mut ChiseiServiceClient<GatewayClient>,
) {
    let Some(pipeline_observation) = pipeline_observation else {
        return;
    };
    if !pipeline_observation.sampled {
        return;
    }
    let Some(response_observation) = response_observation else {
        return;
    };
    if response_observation.output_content.trim().is_empty() {
        return;
    }
    let usage = usage.unwrap_or_default();
    match chisei
        .record_sample_observation(GrpcRequest::new(RecordSampleObservationRequest {
            observation: Some(SampleObservation {
                request_id: context.request_id.clone(),
                namespace: identity.project.clone(),
                spec: pipeline_observation.prepared_spec.clone(),
                resolved_model: context
                    .resolved_model
                    .as_ref()
                    .or(context.requested_model.as_ref())
                    .cloned()
                    .unwrap_or_default(),
                output_content: response_observation.output_content.clone(),
                sample_reason: pipeline_observation.reason.clone(),
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                stop_reason: response_observation.stop_reason.clone(),
                timestamp: Utc::now().timestamp_millis(),
            }),
        }))
        .await
    {
        Ok(_) => {}
        Err(err) => eprintln!("chisei-gateway sample observation record failed: {err}"),
    }
}

async fn record_gateway_pipeline_decision(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    observation: Option<GatewayPipelineObservation>,
) {
    let Some(observation) = observation else {
        return;
    };
    if !observation.sampled {
        return;
    }
    record_gateway_decision(
        config,
        identity,
        "gateway.sampled",
        &observation.reason,
        "sampled",
        HashMap::from([
            ("request_id".to_string(), context.request_id.clone()),
            ("sample_rate".to_string(), observation.rate.to_string()),
            (
                "provider".to_string(),
                context.provider.runtime_name().to_string(),
            ),
        ]),
    )
    .await;
}

async fn link_work_unit_usage(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    identity: &GatewayIdentity,
    context: &UsageContext,
    values: &HashMap<String, String>,
) {
    let Some(work_unit_id) = context.work_unit_id.as_deref() else {
        return;
    };
    let work_unit_object_id = match ensure_gateway_object(
        sekai,
        format!("work_unit:{work_unit_id}"),
        format!("work-unit-{}", sanitize_gateway_id(work_unit_id)),
        "work_unit",
        work_unit_id,
        &identity.project,
        HashMap::from([
            ("gateway_managed".to_string(), "true".to_string()),
            ("source".to_string(), "gateway_header".to_string()),
        ]),
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            eprintln!("chisei-gateway work_unit object upsert failed: {err}");
            return;
        }
    };
    let llm_call_object_id = match ensure_gateway_object(
        sekai,
        format!("llm_call:{}", context.request_id),
        format!("llm-call-{}", context.request_id),
        "llm_call",
        &context.request_id,
        &identity.project,
        llm_call_object_properties(identity, context, values),
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            eprintln!("chisei-gateway llm_call object create failed: {err}");
            return;
        }
    };
    let link = Link {
        id: format!(
            "work-unit-{}-incurs-{}",
            sanitize_gateway_id(work_unit_id),
            context.request_id
        ),
        from_id: work_unit_object_id,
        to_id: llm_call_object_id,
        relation: "incurs_usage".to_string(),
        created: Utc::now().timestamp_millis(),
    };
    match sekai
        .create_link(gateway_request(CreateLinkRequest { link: Some(link) }))
        .await
    {
        Ok(_) => {}
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") => {}
        Err(err) => eprintln!("chisei-gateway work_unit usage link failed: {err}"),
    }
}

async fn ensure_gateway_object(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    external_id: String,
    fallback_id: String,
    kind: &str,
    name: &str,
    namespace: &str,
    properties: HashMap<String, String>,
) -> Result<String, tonic::Status> {
    match sekai
        .find_by_external_id(gateway_request(FindByExternalIdRequest {
            external_id: external_id.clone(),
        }))
        .await
    {
        Ok(resp) => {
            if let Some(object) = resp.into_inner().object {
                return Ok(object.id);
            }
        }
        Err(err) if err.code() == tonic::Code::NotFound => {}
        Err(err) => return Err(err),
    }

    let id = fallback_id;
    match sekai
        .create_object(gateway_request(CreateObjectRequest {
            object: Some(SekaiObject {
                id: id.clone(),
                kind: kind.to_string(),
                name: name.to_string(),
                namespace: namespace.to_string(),
                external_id,
                properties,
                created: Utc::now().timestamp_millis(),
                updated: Utc::now().timestamp_millis(),
            }),
        }))
        .await
    {
        Ok(_) => Ok(id),
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") =>
        {
            Ok(id)
        }
        Err(err) => Err(err),
    }
}

fn llm_call_object_properties(
    identity: &GatewayIdentity,
    context: &UsageContext,
    values: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut properties = HashMap::from([
        ("gateway_managed".to_string(), "true".to_string()),
        ("agent".to_string(), identity.agent.clone()),
        ("project".to_string(), identity.project.clone()),
        (
            "provider".to_string(),
            context.provider.runtime_name().to_string(),
        ),
    ]);
    for key in [
        "model",
        "resolved_model",
        "status",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cost_usd_micros",
        "cost_usd",
    ] {
        if let Some(value) = values.get(key).filter(|value| !value.is_empty()) {
            properties.insert(key.to_string(), value.clone());
        }
    }
    properties
}

fn sanitize_gateway_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

async fn record_gateway_decision(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    action: &str,
    reason: &str,
    outcome: &str,
    mut evidence: HashMap<String, String>,
) {
    evidence
        .entry("user_id".to_string())
        .or_insert_with(|| identity.user_id.clone());
    evidence
        .entry("project".to_string())
        .or_insert_with(|| identity.project.clone());
    if !identity.key_id.is_empty() {
        evidence
            .entry("key_id".to_string())
            .or_insert_with(|| identity.key_id.clone());
    }
    record_gateway_event(config, &identity.agent, action, reason, outcome, evidence).await;
}

async fn record_gateway_event(
    config: &GatewayConfig,
    actor: &str,
    action: &str,
    reason: &str,
    outcome: &str,
    evidence: HashMap<String, String>,
) {
    let Some(target) = &config.chisei_grpc_target else {
        return;
    };
    let Ok(channel) = connect_sekai(target).await else {
        return;
    };
    let mut sekai = SekaiServiceClient::new(channel.clone());
    if let Err(err) = ensure_llm_calls_dataset(&mut sekai).await {
        if err.code() != tonic::Code::InvalidArgument
            || !err.message().contains("UNIQUE constraint failed")
        {
            eprintln!("chisei-gateway audit target create failed: {err}");
            return;
        }
    }
    let mut chisei = ChiseiServiceClient::new(channel);
    if let Err(err) = chisei
        .record_gateway_audit(gateway_request(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now().timestamp_millis(),
                actor: actor.to_string(),
                action: action.to_string(),
                reason: reason.to_string(),
                evidence,
                target_id: "llm_calls".to_string(),
                outcome: outcome.to_string(),
            }),
        }))
        .await
    {
        eprintln!("chisei-gateway audit decision record failed: {err}");
    }
}

fn gateway_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "chisei-gateway".parse().unwrap());
    request
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ResponseUsage {
    input_tokens: i32,
    output_tokens: i32,
    total_tokens: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResponseObservation {
    output_content: String,
    stop_reason: String,
}

fn extract_response_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = if let Some(usage) = value.get("usage") {
        usage
    } else if value.get("input_tokens").is_some()
        || value.get("prompt_tokens").is_some()
        || value.get("output_tokens").is_some()
        || value.get("completion_tokens").is_some()
        || value.get("total_tokens").is_some()
    {
        &value
    } else {
        return None;
    };
    let input_tokens = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|value| value.as_i64())
        .unwrap_or(input_tokens + output_tokens);

    Some(ResponseUsage {
        input_tokens: clamp_i64_to_i32(input_tokens),
        output_tokens: clamp_i64_to_i32(output_tokens),
        total_tokens: clamp_i64_to_i32(total_tokens),
    })
}

fn extract_response_observation(body: &[u8]) -> Option<ResponseObservation> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut text = String::new();
    collect_response_text(&value, &mut text);
    let text = truncate_gateway_spec(text.trim());
    if text.is_empty() {
        return None;
    }
    Some(ResponseObservation {
        output_content: text,
        stop_reason: extract_stop_reason(&value),
    })
}

fn collect_response_text(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(text) = map.get("output_text").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            if let Some(text) = map.get("text").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            if let Some(text) = map.get("content").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            for key in ["output", "content", "message", "choices"] {
                if let Some(value) = map.get(key) {
                    collect_response_text(value, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_response_text(item, out);
            }
        }
        _ => {}
    }
}

fn push_observation_text(out: &mut String, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}

fn extract_stop_reason(value: &serde_json::Value) -> String {
    value
        .get("stop_reason")
        .or_else(|| value.get("finish_reason"))
        .or_else(|| value.pointer("/choices/0/finish_reason"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}

fn merge_usage(existing: Option<ResponseUsage>, next: ResponseUsage) -> ResponseUsage {
    let Some(existing) = existing else {
        return next;
    };
    let input_tokens = if next.input_tokens > 0 {
        next.input_tokens
    } else {
        existing.input_tokens
    };
    let output_tokens = if next.output_tokens > 0 {
        next.output_tokens
    } else {
        existing.output_tokens
    };
    let total_tokens =
        if next.total_tokens > 0 && next.total_tokens != next.input_tokens + next.output_tokens {
            next.total_tokens
        } else {
            input_tokens.saturating_add(output_tokens)
        };
    ResponseUsage {
        input_tokens,
        output_tokens,
        total_tokens,
    }
}

#[derive(Debug, Default)]
struct SseUsageTap {
    pending: Vec<u8>,
    usage: Option<ResponseUsage>,
    observation: ResponseObservation,
}

impl SseUsageTap {
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        while let Some((boundary, separator_len)) = find_sse_event_boundary(&self.pending) {
            let event = self.pending.drain(..boundary).collect::<Vec<_>>();
            self.pending.drain(..separator_len);
            if let Some(usage) = extract_sse_event_usage(&event) {
                self.usage = Some(merge_usage(self.usage, usage));
            }
            if let Some(observation) = extract_sse_event_observation(&event) {
                self.merge_observation(observation);
            }
        }
    }

    fn finish(mut self) -> (Option<ResponseUsage>, Option<ResponseObservation>) {
        self.flush_pending();
        let observation = if self.observation.output_content.trim().is_empty() {
            None
        } else {
            self.observation.output_content =
                truncate_gateway_spec(&self.observation.output_content);
            Some(self.observation)
        };
        (self.usage, observation)
    }

    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        if let Some(usage) = extract_sse_event_usage(&pending) {
            self.usage = Some(merge_usage(self.usage, usage));
        }
        if let Some(observation) = extract_sse_event_observation(&pending) {
            self.merge_observation(observation);
        }
    }

    fn merge_observation(&mut self, observation: ResponseObservation) {
        push_observation_text(
            &mut self.observation.output_content,
            &observation.output_content,
        );
        if !observation.stop_reason.is_empty() {
            self.observation.stop_reason = observation.stop_reason;
        }
    }
}

fn find_sse_event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if lf < crlf => Some((lf, 2)),
        (Some(_), Some(crlf)) => Some((crlf, 4)),
        (Some(lf), None) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

fn extract_sse_event_usage(event: &[u8]) -> Option<ResponseUsage> {
    let data = extract_sse_data(event)?;
    extract_response_usage(data.as_bytes())
        .or_else(|| extract_nested_response_usage(data.as_bytes()))
        .or_else(|| extract_nested_message_usage(data.as_bytes()))
}

fn extract_sse_event_observation(event: &[u8]) -> Option<ResponseObservation> {
    let data = extract_sse_data(event)?;
    let value: serde_json::Value = serde_json::from_str(&data).ok()?;
    let mut text = String::new();
    if let Some(delta) = value
        .pointer("/delta/text")
        .and_then(|value| value.as_str())
    {
        push_observation_text(&mut text, delta);
    }
    if let Some(delta) = value.get("delta").and_then(|value| value.as_str()) {
        push_observation_text(&mut text, delta);
    }
    if let Some(text_value) = value
        .pointer("/content_block/text")
        .and_then(|value| value.as_str())
    {
        push_observation_text(&mut text, text_value);
    }
    collect_response_text(&value, &mut text);
    let text = truncate_gateway_spec(text.trim());
    if text.is_empty() {
        return None;
    }
    Some(ResponseObservation {
        output_content: text,
        stop_reason: extract_stop_reason(&value),
    })
}

fn extract_sse_data(event: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(event);
    let mut data = String::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim_start());
        }
    }
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return None;
    }
    Some(data)
}

fn extract_nested_response_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let response = value.get("response")?;
    extract_response_usage(&serde_json::to_vec(response).ok()?)
}

fn extract_nested_message_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let message = value.get("message")?;
    extract_response_usage(&serde_json::to_vec(message).ok()?)
}

fn extract_request_model(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("model")
                .and_then(|model| model.as_str())
                .map(str::to_string)
        })
}

fn extract_gateway_pipeline_spec(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return truncate_gateway_spec(&String::from_utf8_lossy(body));
    };
    let mut parts = Vec::new();
    collect_gateway_spec_text(&value, &mut parts);
    let spec = parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if spec.is_empty() {
        truncate_gateway_spec(&value.to_string())
    } else {
        truncate_gateway_spec(&spec)
    }
}

fn collect_gateway_spec_text(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            if !text.trim().is_empty() {
                parts.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_gateway_spec_text(item, parts);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["input", "instructions", "system", "content", "messages"] {
                if let Some(value) = map.get(key) {
                    collect_gateway_spec_text(value, parts);
                }
            }
            if map.get("type").and_then(|value| value.as_str()) == Some("text")
                && let Some(text) = map.get("text").and_then(|value| value.as_str())
                && !text.trim().is_empty()
            {
                parts.push(text.to_string());
            }
        }
        _ => {}
    }
}

fn truncate_gateway_spec(value: &str) -> String {
    const MAX_GATEWAY_SPEC_CHARS: usize = 4000;
    value.chars().take(MAX_GATEWAY_SPEC_CHARS).collect()
}

fn clamp_i64_to_i32(value: i64) -> i32 {
    value.clamp(0, i32::MAX as i64) as i32
}

async fn response_from_upstream(
    upstream: reqwest::Response,
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: UsageContext,
    response_adapter: ResponseAdapter,
) -> Response<Body> {
    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    let response_headers = upstream.headers().clone();
    for (name, value) in upstream.headers().iter() {
        if should_forward_response_header(name) {
            builder = builder.header(name, value);
        }
    }

    let is_stream = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.starts_with("text/event-stream"))
        .unwrap_or(false);
    if is_stream {
        if response_adapter != ResponseAdapter::Passthrough {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "unsupported_cross_provider_stream",
                "cross-provider streaming response translation is not supported",
            );
        }
        let config = config.clone();
        let identity = identity.clone();
        let context = context.clone();
        let mut upstream_stream = upstream.bytes_stream();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<_, reqwest::Error>>(32);
        tokio::spawn(async move {
            let mut usage_tap = SseUsageTap::new();
            while let Some(chunk) = upstream_stream.next().await {
                if let Ok(bytes) = &chunk {
                    usage_tap.push(bytes);
                }
                if tx.send(chunk).await.is_err() {
                    continue;
                }
            }
            let (usage, observation) = usage_tap.finish();
            record_usage_and_append(&config, &identity, usage, observation, &context, status).await;
        });
        let stream = ReceiverStream::new(rx);
        return builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|err| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_response_error",
                    &format!("failed to build upstream response: {err}"),
                )
            });
    }

    match upstream.bytes().await {
        Ok(bytes) => {
            let usage = extract_response_usage(&bytes);
            let observation = extract_response_observation(&bytes);
            record_usage_and_append(config, identity, usage, observation, &context, status).await;
            let body = match response_adapter {
                ResponseAdapter::Passthrough => bytes.to_vec(),
                ResponseAdapter::OpenAiChatToAnthropicMessage => {
                    match openai_chat_to_anthropic_message(
                        &bytes,
                        context.resolved_model.as_deref(),
                    ) {
                        Ok(body) => body,
                        Err(err) => {
                            return json_error(
                                StatusCode::BAD_GATEWAY,
                                "gateway_response_error",
                                &format!("failed to translate OpenAI response to Anthropic: {err}"),
                            );
                        }
                    }
                }
            };
            builder.body(Body::from(body)).unwrap_or_else(|err| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_response_error",
                    &format!("failed to build upstream response: {err}"),
                )
            })
        }
        Err(err) => json_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            &format!("failed to read upstream response: {err}"),
        ),
    }
}

fn should_forward_request_header(name: &HeaderName, auth_mode: UpstreamAuthMode) -> bool {
    if is_hop_by_hop(name) || name == HOST || name == CONTENT_LENGTH || is_chisei_header(name) {
        return false;
    }
    if auth_mode == UpstreamAuthMode::GatewayKey && (name == AUTHORIZATION || name == X_API_KEY) {
        return false;
    }
    true
}

fn is_chisei_header(name: &HeaderName) -> bool {
    name.as_str().starts_with("x-chisei-")
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !is_hop_by_hop(name) && name != CONTENT_LENGTH
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn json_error(status: StatusCode, error_type: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": {
            "type": error_type,
            "message": message
        }
    });
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::sekai::SekaiDb;
    use crate::grpc::chisei_service::ChiseiServiceImpl;
    use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
    use crate::grpc::pb::chisei::chisei_service_server::ChiseiServiceServer;
    use crate::grpc::pb::chisei::{
        CaseResult, CreateEvalRunRequest, CreateEvalSuiteRequest, EvalCase, EvalRun, EvalSuite,
        SetBudgetLimitRequest, SetNamespacePolicyRequest,
    };
    use crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
    use crate::grpc::sekai_service::SekaiServiceImpl;
    use crate::sekai::dataset::RowQuery;
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::any;
    use std::sync::Mutex;
    use tonic::transport::Server;

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        path: String,
        query: Option<String>,
        authorization: Option<String>,
        x_api_key: Option<String>,
        chisei_agent: Option<String>,
        body: String,
    }

    #[test]
    fn parses_gateway_pricing_table() {
        let pricing = parse_pricing_table("gpt-5.5=1.25:10,claude-sonnet-4-6=3:15.000001").unwrap();

        assert_eq!(
            pricing.get("gpt-5.5"),
            Some(&ModelPricing {
                input_usd_micros_per_million: 1_250_000,
                output_usd_micros_per_million: 10_000_000,
            })
        );
        assert_eq!(
            pricing.get("claude-sonnet-4-6"),
            Some(&ModelPricing {
                input_usd_micros_per_million: 3_000_000,
                output_usd_micros_per_million: 15_000_001,
            })
        );
        assert!(parse_pricing_table("gpt-5.5=1").is_err());
    }

    #[derive(Clone)]
    struct FakeUpstreamState {
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        response_body: &'static str,
        content_type: &'static str,
    }

    async fn fake_upstream(
        State(state): State<FakeUpstreamState>,
        uri: Uri,
        headers: HeaderMap,
        request: Request<Body>,
    ) -> Response<Body> {
        let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap();
        state.requests.lock().unwrap().push(RecordedRequest {
            path: uri.path().to_string(),
            query: uri.query().map(str::to_string),
            authorization: headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            x_api_key: headers
                .get(X_API_KEY)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            chisei_agent: headers
                .get(X_CHISEI_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            body: String::from_utf8(body.to_vec()).unwrap(),
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, state.content_type)
            .body(Body::from(state.response_body))
            .unwrap()
    }

    async fn spawn_fake_upstream(
        response_body: &'static str,
        content_type: &'static str,
    ) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeUpstreamState {
            requests: requests.clone(),
            response_body,
            content_type,
        };
        let app = Router::new()
            .route("/{*path}", any(fake_upstream))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/v1"), requests)
    }

    async fn spawn_gateway(openai_base_url: String) -> String {
        let config = GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        };
        spawn_gateway_with_config(config).await
    }

    async fn spawn_gateway_with_config(config: GatewayConfig) -> String {
        spawn_gateway_with_runtime(
            config,
            GatewayRuntime::new(Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS), None),
        )
        .await
    }

    async fn spawn_gateway_with_runtime(config: GatewayConfig, runtime: GatewayRuntime) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app_with_runtime(config, runtime))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    fn test_config() -> Config {
        Config {
            grpc_port: 0,
            sekai_socket: None,
            db_path: ":memory:".into(),
            anthropic_api_key: Some("test-anthropic-key".into()),
            openai_api_key: Some("test-openai-key".into()),
            ollama_url: "http://127.0.0.1:11434".into(),
            native_llm_url: None,
            auth_token: None,
            sample_rate: 0.0,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "claude-opus-4-8".into(),
            scoring_batch_size: 16,
        }
    }

    async fn spawn_control_plane() -> (String, Arc<SekaiDb>) {
        spawn_control_plane_with_config(test_config()).await
    }

    async fn spawn_control_plane_with_config(config: Config) -> (String, Arc<SekaiDb>) {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        db.migrate_datasets();
        db.migrate_functions();
        db.migrate_grants();
        db.migrate_audit();
        let _ = db.migrate_chisei();
        for (agent, project, secret) in [
            ("codex-app", "default", "sk-chisei-codex-app"),
            ("claude-code", "default", "sk-chisei-claude-code"),
            (
                "codex-app",
                "sekai-chisei",
                "sk-chisei-codex-app-sekai-chisei",
            ),
        ] {
            let _ = db.create_object(&crate::domain::Object {
                id: format!("gateway-key-{agent}-{project}"),
                kind: "gateway_key".to_string(),
                name: agent.to_string(),
                namespace: project.to_string(),
                external_id: format!("gateway_key:{agent}:{project}"),
                properties: HashMap::from([
                    ("agent".to_string(), agent.to_string()),
                    ("project".to_string(), project.to_string()),
                    ("status".to_string(), "active".to_string()),
                    ("key_hash".to_string(), hash_gateway_key(secret)),
                ]),
                created: 0,
                updated: 0,
            });
        }

        let sekai_svc = SekaiServiceImpl::new(db.clone());
        let chisei_svc = ChiseiServiceImpl::new(db.clone(), config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(SekaiServiceServer::new(sekai_svc))
                .add_service(ChiseiServiceServer::new(chisei_svc))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        (format!("http://{addr}"), db)
    }

    async fn seed_regressed_namespace(target: &str, namespace: &str) {
        let channel = connect_sekai(target).await.unwrap();
        let mut chisei = ChiseiServiceClient::new(channel);
        chisei
            .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
                namespace: namespace.to_string(),
                allowed_runtimes: vec!["openai".to_string()],
                allowed_models: vec!["gpt-5.5".to_string(), "gpt-5.5-mini".to_string()],
                default_runtime: "openai".to_string(),
                default_model: "gpt-5.5".to_string(),
            }))
            .await
            .unwrap();
        chisei
            .create_eval_suite(GrpcRequest::new(CreateEvalSuiteRequest {
                suite: Some(EvalSuite {
                    id: "gateway-suite".to_string(),
                    name: "Gateway suite".to_string(),
                    description: String::new(),
                    cases: vec![EvalCase {
                        id: "case-1".to_string(),
                        name: "case".to_string(),
                        namespace: namespace.to_string(),
                        spec: "spec".to_string(),
                        assertions: vec![],
                    }],
                }),
            }))
            .await
            .unwrap();
        for (id, score, timestamp) in [("run-1", 92, 100), ("run-2", 60, 200)] {
            chisei
                .create_eval_run(GrpcRequest::new(CreateEvalRunRequest {
                    run: Some(EvalRun {
                        id: id.to_string(),
                        suite_id: "gateway-suite".to_string(),
                        config_ref: "gpt-5.5".to_string(),
                        results: vec![CaseResult {
                            case_id: "case-1".to_string(),
                            passed: score >= 80,
                            status: if score >= 80 { "done" } else { "failed" }.to_string(),
                            result: "result".to_string(),
                            score,
                            reason: String::new(),
                            elapsed: 10,
                        }],
                        timestamp,
                    }),
                    changed_file: namespace.to_string(),
                    diff_hash: format!("hash-{id}"),
                }))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn responses_proxy_forwards_body_query_and_rewrites_auth() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1","object":"response"}"#, "application/json").await;
        let gateway_base = spawn_gateway(upstream_base).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{gateway_base}/v1/responses?trace=1"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-codex-test", "yes")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.text().await.unwrap(),
            r#"{"id":"resp_1","object":"response"}"#
        );

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/responses");
        assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
        assert!(requests[0].body.contains(r#""model":"gpt-5.5""#));
    }

    #[tokio::test]
    async fn responses_proxy_preserves_sse_body() {
        let sse = "event: response.created\n\
                   data: {\"type\":\"response.created\"}\n\n\
                   event: response.completed\n\
                   data: {\"type\":\"response.completed\"}\n\n";
        let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
        let gateway_base = spawn_gateway(upstream_base).await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello",
                "stream": true
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(resp.text().await.unwrap(), sse);
    }

    #[tokio::test]
    async fn models_proxy_forwards_to_openai_upstream() {
        let upstream_body = r#"{"object":"list","data":[{"id":"gpt-5.5","object":"model"}]}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let gateway_base = spawn_gateway(upstream_base).await;

        let resp = reqwest::Client::new()
            .get(format!("{gateway_base}/v1/models?client_version=0.141.0"))
            .bearer_auth("sk-chisei-codex-app")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), upstream_body);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/models");
        assert_eq!(requests[0].query.as_deref(), Some("client_version=0.141.0"));
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
    }

    #[tokio::test]
    async fn openai_passthrough_preserves_client_auth_and_strips_chisei_headers() {
        let upstream_body = r#"{"id":"resp_1","object":"response"}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: None,
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: None,
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: true,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("native-openai-oauth-token")
            .header(X_CHISEI_AGENT.as_str(), "codex-app")
            .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer native-openai-oauth-token")
        );
        assert_eq!(requests[0].x_api_key, None);
        assert_eq!(requests[0].chisei_agent, None);
    }

    #[tokio::test]
    async fn openai_passthrough_rejects_requests_without_client_auth() {
        let upstream_body = r#"{"id":"resp_1","object":"response"}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: None,
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: None,
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: true,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .header(X_CHISEI_AGENT.as_str(), "codex-app")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn openai_passthrough_can_rewrite_upstream_auth_for_codex_local_login() {
        let upstream_body = r#"{"id":"resp_1","object":"response"}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: None,
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: true,
            rewrite_openai_passthrough_auth: true,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("codex-local-login-token")
            .header(X_CHISEI_AGENT.as_str(), "codex-app")
            .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
        assert_eq!(requests[0].x_api_key, None);
        assert_eq!(requests[0].chisei_agent, None);
    }

    #[tokio::test]
    async fn anthropic_passthrough_preserves_client_auth_and_strips_chisei_headers() {
        let upstream_body = r#"{
            "id":"msg_1",
            "type":"message",
            "usage":{"input_tokens":8,"output_tokens":6}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: "http://127.0.0.1:9/v1".to_string(),
            openai_api_key: None,
            anthropic_base_url: upstream_base,
            anthropic_api_key: None,
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: true,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages"))
            .bearer_auth("native-claude-oauth-token")
            .header(X_CHISEI_AGENT.as_str(), "claude-code")
            .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
            .header("anthropic-version", "2023-06-01")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-6",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer native-claude-oauth-token")
        );
        assert_eq!(requests[0].x_api_key, None);
        assert_eq!(requests[0].chisei_agent, None);
    }

    #[tokio::test]
    async fn chat_completions_proxy_records_usage_and_rewrites_auth() {
        let upstream_body = r#"{
            "id":"chatcmpl_1",
            "object":"chat.completion",
            "usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target.clone()),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/chat/completions?trace=1"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), upstream_body);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/chat/completions");
        assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
        drop(requests);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
        assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("9"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("13"));
    }

    #[tokio::test]
    async fn eval_regression_signal_rewrites_model_and_records_audit() {
        let upstream_body = r#"{
            "id":"resp_1",
            "object":"response",
            "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
            "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        seed_regressed_namespace(&chisei_target, "default").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target.clone()),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(forwarded["model"], "gpt-5.5");
        drop(requests);

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.eval_regression".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "codex-app");
        assert_eq!(decisions[0].outcome, "routed");
        assert_eq!(
            decisions[0]
                .evidence
                .get("requested_model")
                .map(String::as_str),
            Some("gpt-5.5-mini")
        );
        assert_eq!(
            decisions[0]
                .evidence
                .get("resolved_model")
                .map(String::as_str),
            Some("gpt-5.5")
        );
        assert_eq!(
            decisions[0].evidence.get("key_id").map(String::as_str),
            Some("codex-app")
        );
        assert_eq!(
            decisions[0].evidence.get("user_id").map(String::as_str),
            Some("agent:codex-app")
        );
    }

    #[tokio::test]
    async fn gateway_key_policy_scope_rewrites_model() {
        let upstream_body = r#"{
            "id":"resp_1",
            "object":"response",
            "output":[{"type":"message","content":[{"type":"output_text","text":"key scoped answer"}]}],
            "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let channel = connect_sekai(&chisei_target).await.unwrap();
        ChiseiServiceClient::new(channel)
            .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
                namespace: "gateway_key:codex-app".to_string(),
                allowed_runtimes: vec!["openai".to_string()],
                allowed_models: vec!["gpt-5.5".to_string()],
                default_runtime: "openai".to_string(),
                default_model: "gpt-5.5".to_string(),
            }))
            .await
            .unwrap();
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(forwarded["model"], "gpt-5.5");
        drop(requests);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("key_id").map(String::as_str), Some("codex-app"));
        assert_eq!(
            rows[0].get("resolved_model").map(String::as_str),
            Some("gpt-5.5")
        );

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.model_rewrite".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0]
                .evidence
                .get("resolved_model")
                .map(String::as_str),
            Some("gpt-5.5")
        );
    }

    #[tokio::test]
    async fn chat_completions_streaming_response_records_usage_after_passthrough() {
        let sse = "data: {\"id\":\"chatcmpl_1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                   data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n\
                   data: [DONE]\n\n";
        let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/chat/completions"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": true,
                "stream_options": {"include_usage": true}
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), sse);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("3"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("2"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("5"));
    }

    #[tokio::test]
    async fn anthropic_messages_proxy_records_usage_and_rewrites_x_api_key() {
        let upstream_body = r#"{
            "id":"msg_1",
            "type":"message",
            "usage":{"input_tokens":8,"output_tokens":6}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: "http://127.0.0.1:9/v1".to_string(),
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: upstream_base,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages?trace=1"))
            .header(X_API_KEY, "sk-chisei-claude-code")
            .header("anthropic-version", "2023-06-01")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), upstream_body);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/messages");
        assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
        assert_eq!(requests[0].authorization, None);
        assert_eq!(requests[0].x_api_key.as_deref(), Some("real-anthropic-key"));
        drop(requests);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("agent").map(String::as_str),
            Some("claude-code")
        );
        assert_eq!(
            rows[0].get("provider").map(String::as_str),
            Some("anthropic")
        );
        assert_eq!(
            rows[0].get("model").map(String::as_str),
            Some("claude-sonnet-4-20250514")
        );
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
    }

    #[tokio::test]
    async fn anthropic_messages_can_translate_to_openai_chat_when_policy_routes_cross_provider() {
        let upstream_body = r#"{
            "id":"chatcmpl_1",
            "object":"chat.completion",
            "model":"gpt-5.5",
            "choices":[{"index":0,"message":{"role":"assistant","content":"translated ok"},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let channel = connect_sekai(&chisei_target).await.unwrap();
        ChiseiServiceClient::new(channel)
            .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
                namespace: "default".to_string(),
                allowed_runtimes: vec!["openai".to_string()],
                allowed_models: vec!["gpt-5.5".to_string()],
                default_runtime: "openai".to_string(),
                default_model: "gpt-5.5".to_string(),
            }))
            .await
            .unwrap();
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: true,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages"))
            .header(X_API_KEY, "sk-chisei-claude-code")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 64,
                "system": "stay terse",
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["type"], "message");
        assert_eq!(body["model"], "gpt-5.5");
        assert_eq!(body["content"][0]["text"], "translated ok");
        assert_eq!(body["usage"]["input_tokens"], 11);
        assert_eq!(body["usage"]["output_tokens"], 4);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/chat/completions");
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
        assert_eq!(requests[0].x_api_key, None);
        let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(translated["model"], "gpt-5.5");
        assert_eq!(translated["messages"][0]["role"], "system");
        assert_eq!(translated["messages"][0]["content"], "stay terse");
        assert_eq!(translated["messages"][1]["role"], "user");
        assert_eq!(translated["messages"][1]["content"], "hello");
        drop(requests);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("provider").map(String::as_str), Some("openai"));
        assert_eq!(
            rows[0].get("model").map(String::as_str),
            Some("claude-sonnet-4-20250514")
        );
        assert_eq!(
            rows[0].get("resolved_model").map(String::as_str),
            Some("gpt-5.5")
        );
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.cross_provider_translate".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "translated");
    }

    #[tokio::test]
    async fn anthropic_messages_streaming_merges_usage_events() {
        let sse = "event: message_start\n\
                   data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
                   event: content_block_delta\n\
                   data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
                   event: message_delta\n\
                   data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n";
        let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: "http://127.0.0.1:9/v1".to_string(),
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: upstream_base,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages"))
            .header(X_API_KEY, "sk-chisei-claude-code")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 64,
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), sse);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("provider").map(String::as_str),
            Some("anthropic")
        );
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("10"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("7"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("17"));
    }

    #[tokio::test]
    async fn anthropic_count_tokens_proxy_records_input_tokens() {
        let upstream_body = r#"{"input_tokens":17}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: "http://127.0.0.1:9/v1".to_string(),
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: upstream_base,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages/count_tokens"))
            .header(X_API_KEY, "sk-chisei-claude-code")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-20250514",
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), upstream_body);
        assert_eq!(
            requests.lock().unwrap()[0].path,
            "/v1/messages/count_tokens"
        );

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("provider").map(String::as_str),
            Some("anthropic")
        );
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("17"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("0"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("17"));
    }

    #[tokio::test]
    async fn unknown_key_is_rejected_when_allowlist_is_configured() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let mut gateway_keys = HashMap::new();
        gateway_keys.insert(
            "sk-chisei-known".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "sekai-chisei".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
            },
        );
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: None,
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys,
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-unknown")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_key_rejection_records_audit_decision() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let mut gateway_keys = HashMap::new();
        gateway_keys.insert(
            "sk-chisei-known".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "sekai-chisei".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
            },
        );
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: false,
            default_project: "default".to_string(),
            gateway_keys,
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-unknown")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(requests.lock().unwrap().is_empty());

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.auth_failed".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "chisei-gateway");
        assert_eq!(decisions[0].outcome, "denied");
        assert_eq!(decisions[0].target_id, "llm_calls");
        assert_eq!(decisions[0].reason, "unknown chisei gateway key");
        assert_eq!(
            decisions[0]
                .evidence
                .get("presented_key")
                .map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn admin_refresh_clears_gateway_key_cache() {
        let upstream_body =
            r#"{"id":"resp_1","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_runtime(
            GatewayConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                openai_base_url: upstream_base,
                openai_api_key: Some("real-openai-key".to_string()),
                anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
                anthropic_api_key: Some("real-anthropic-key".to_string()),
                chisei_grpc_target: Some(chisei_target),
                fail_closed: true,
                default_project: "default".to_string(),
                gateway_keys: HashMap::new(),
                allow_auth_passthrough: false,
                rewrite_openai_passthrough_auth: false,
                no_preflight: false,
                pricing: HashMap::new(),
                run_pipeline: false,
                allow_cross_provider: false,
            },
            GatewayRuntime::new(
                Duration::from_secs(60 * 60),
                Some("admin-secret".to_string()),
            ),
        )
        .await;
        let client = reqwest::Client::new();
        let new_key = "sk-chisei-new-worker";

        let first = client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth(new_key)
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        assert!(requests.lock().unwrap().is_empty());

        db.create_object(&crate::domain::Object {
            id: "gateway-key-new-worker".to_string(),
            kind: "gateway_key".to_string(),
            name: "new-worker".to_string(),
            namespace: "default".to_string(),
            external_id: "gateway_key:new-worker:default".to_string(),
            properties: HashMap::from([
                ("agent".to_string(), "new-worker".to_string()),
                ("project".to_string(), "default".to_string()),
                ("status".to_string(), "active".to_string()),
                ("key_hash".to_string(), hash_gateway_key(new_key)),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

        let cached_miss = client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth(new_key)
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(cached_miss.status(), StatusCode::UNAUTHORIZED);

        let unauthorized_refresh = client
            .post(format!("{gateway_base}/_chisei/admin/refresh"))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized_refresh.status(), StatusCode::UNAUTHORIZED);

        let refresh = client
            .post(format!("{gateway_base}/_chisei/admin/refresh"))
            .bearer_auth("admin-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(refresh.status(), StatusCode::OK);
        let refresh_body: serde_json::Value = refresh.json().await.unwrap();
        assert_eq!(refresh_body["refreshed"], true);
        assert_eq!(refresh_body["cleared_key_cache_entries"], 1);

        let accepted = client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth(new_key)
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(accepted.text().await.unwrap(), upstream_body);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fail_closed_blocks_when_chisei_preflight_is_unavailable() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some("/tmp/sekai-chisei-missing-test.sock".to_string()),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_preflight_skips_unavailable_control_plane_checks() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some("/tmp/sekai-chisei-missing-test.sock".to_string()),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::from([(
                "sk-chisei-codex-app".to_string(),
                GatewayIdentity {
                    agent: "codex-app".to_string(),
                    project: "default".to_string(),
                    user_id: "agent:codex-app".to_string(),
                    key_id: "codex-app".to_string(),
                },
            )]),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: true,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key")
        );
    }

    #[tokio::test]
    async fn budget_denial_records_audit_decision() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;

        let channel = connect_sekai(&chisei_target).await.unwrap();
        ChiseiServiceClient::new(channel)
            .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
                user_id: "agent:codex-app".to_string(),
                max_tokens: 1,
                period_type: "day".to_string(),
                subject: "agent:codex-app".to_string(),
                project: "default".to_string(),
                agent: "codex-app".to_string(),
                key_id: String::new(),
            }))
            .await
            .unwrap();

        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(requests.lock().unwrap().is_empty());

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.budget_denied".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "codex-app");
        assert_eq!(decisions[0].outcome, "denied");
        assert_eq!(decisions[0].target_id, "llm_calls");
        assert_eq!(
            decisions[0].evidence.get("user_id").map(String::as_str),
            Some("agent:codex-app")
        );

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
        assert_eq!(
            rows[0].get("error_type").map(String::as_str),
            Some("budget_exceeded")
        );
        assert_eq!(
            rows[0]
                .get("refusal_reason")
                .map(|reason| reason.contains("budget exceeded")),
            Some(true)
        );
        assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
        assert_eq!(rows[0].get("provider").map(String::as_str), Some("openai"));
    }

    #[tokio::test]
    async fn project_budget_denial_blocks_gateway_call() {
        let (upstream_base, requests) =
            spawn_fake_upstream(r#"{"id":"resp_1"}"#, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;

        let channel = connect_sekai(&chisei_target).await.unwrap();
        ChiseiServiceClient::new(channel)
            .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
                user_id: "project:default".to_string(),
                max_tokens: 1,
                period_type: "day".to_string(),
                subject: "project:default".to_string(),
                project: "default".to_string(),
                agent: String::new(),
                key_id: String::new(),
            }))
            .await
            .unwrap();

        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(requests.lock().unwrap().is_empty());

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.budget_denied".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0]
                .evidence
                .get("budget_subject")
                .map(String::as_str),
            Some("project:default")
        );

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
        assert_eq!(
            rows[0]
                .get("refusal_reason")
                .map(|reason| reason.contains("project:default")),
            Some(true)
        );
    }

    #[tokio::test]
    async fn referenced_object_context_records_egress_audit() {
        let upstream_body = r#"{
            "id":"resp_1",
            "object":"response",
            "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
            "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        db.create_object(&crate::domain::Object {
            id: "ticker-aapl".to_string(),
            kind: "ticker".to_string(),
            name: "AAPL".to_string(),
            namespace: "sekai-chisei".to_string(),
            external_id: "ticker:AAPL".to_string(),
            properties: HashMap::from([
                ("verdict".to_string(), "bullish".to_string()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                    "score".to_string(),
                ),
                ("score".to_string(), "0.82".to_string()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "sekai-chisei".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "analyze ticker:{AAPL}"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        let forwarded_input = forwarded["input"].as_str().unwrap();
        assert!(forwarded_input.contains("[Object context]"));
        assert!(forwarded_input.contains("score: 0.82"));
        assert!(!forwarded_input.contains("bullish"));
        drop(requests);

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.egress".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "codex-app");
        assert_eq!(decisions[0].outcome, "redacted");
        assert_eq!(
            decisions[0].evidence.get("object_refs").map(String::as_str),
            Some("ticker:AAPL")
        );
        assert_eq!(
            decisions[0]
                .evidence
                .get("included_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            decisions[0]
                .evidence
                .get("redacted_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            decisions[0]
                .evidence
                .get("payload_rewritten")
                .map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn anthropic_object_context_is_injected_as_system_text() {
        let upstream_body = r#"{
            "id":"msg_1",
            "type":"message",
            "usage":{"input_tokens":7,"output_tokens":5}
        }"#;
        let (upstream_base, requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let (chisei_target, db) = spawn_control_plane().await;
        db.create_object(&crate::domain::Object {
            id: "ticker-msft".to_string(),
            kind: "ticker".to_string(),
            name: "MSFT".to_string(),
            namespace: "default".to_string(),
            external_id: "ticker:MSFT".to_string(),
            properties: HashMap::from([
                ("verdict".to_string(), "do not forward".to_string()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                    "score".to_string(),
                ),
                ("score".to_string(), "0.91".to_string()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: "http://127.0.0.1:9/v1".to_string(),
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: upstream_base,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/messages"))
            .header(X_API_KEY.as_str(), "sk-chisei-claude-code")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-8",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "analyze ticker:{MSFT}"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        let system = forwarded["system"].as_str().unwrap();
        assert!(system.contains("[Object context]"));
        assert!(system.contains("score: 0.91"));
        assert!(!system.contains("do not forward"));
    }

    #[tokio::test]
    async fn non_streaming_response_records_usage_and_appends_llm_call() {
        let upstream_body = r#"{
            "id":"resp_1",
            "object":"response",
            "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
            "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
        }"#;
        let (upstream_base, _requests) =
            spawn_fake_upstream(upstream_body, "application/json").await;
        let mut config = test_config();
        config.sample_rate = 1.0;
        config.scoring_enabled = true;
        let (chisei_target, db) = spawn_control_plane_with_config(config).await;
        let pricing = HashMap::from([(
            "gpt-5.5".to_string(),
            ModelPricing {
                input_usd_micros_per_million: 1_000_000,
                output_usd_micros_per_million: 2_000_000,
            },
        )]);
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target.clone()),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing,
            run_pipeline: true,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-work-unit", "wu-cost-1")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), upstream_body);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
        assert_eq!(rows[0].get("project").map(String::as_str), Some("default"));
        assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
        assert_eq!(
            rows[0].get("resolved_model").map(String::as_str),
            Some("gpt-5.5")
        );
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("7"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("12"));
        assert_eq!(
            rows[0].get("cost_usd_micros").map(String::as_str),
            Some("17")
        );
        assert_eq!(
            rows[0].get("cost_usd").map(String::as_str),
            Some("0.000017")
        );
        assert_eq!(
            rows[0].get("work_unit_id").map(String::as_str),
            Some("wu-cost-1")
        );
        let channel = connect_sekai(&chisei_target).await.unwrap();
        let mut chisei = ChiseiServiceClient::new(channel);
        let agent_budget = chisei
            .check_budget(GrpcRequest::new(CheckBudgetRequest {
                user_id: "agent:codex-app".to_string(),
                estimated_tokens: 0,
                subject: "agent:codex-app".to_string(),
                project: "default".to_string(),
                agent: "codex-app".to_string(),
                key_id: "codex-app".to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .usage
            .unwrap();
        let project_budget = chisei
            .check_budget(GrpcRequest::new(CheckBudgetRequest {
                user_id: "project:default".to_string(),
                estimated_tokens: 0,
                subject: "project:default".to_string(),
                project: "default".to_string(),
                agent: "codex-app".to_string(),
                key_id: "codex-app".to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .usage
            .unwrap();
        assert_eq!(agent_budget.tokens_used, 12);
        assert_eq!(project_budget.tokens_used, 12);
        assert_eq!(
            rows[0].get("pipeline_sampled").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            rows[0].get("sample_reason").map(String::as_str),
            Some("base")
        );
        assert_eq!(rows[0].get("sample_rate").map(String::as_str), Some("1"));

        let work_unit = db
            .find_by_external_id("work_unit:wu-cost-1")
            .unwrap()
            .unwrap();
        let request_id = rows[0].get("request_id").unwrap();
        let llm_call = db
            .find_by_external_id(&format!("llm_call:{request_id}"))
            .unwrap()
            .unwrap();
        let links = db
            .get_links(
                &work_unit.id,
                "incurs_usage",
                &crate::domain::Direction::Outgoing,
            )
            .unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].to_id, llm_call.id);

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.sampled".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "base");

        let observations = db.list_unscored_observations(10).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].request_id, *request_id);
        assert_eq!(observations[0].namespace, "default");
        assert_eq!(observations[0].output_content, "gateway sampled answer");
        assert_eq!(observations[0].sample_reason, "base");
    }

    #[tokio::test]
    async fn streaming_response_records_usage_after_passthrough() {
        let sse = "event: response.created\n\
                   data: {\"type\":\"response.created\"}\n\n\
                   event: response.completed\n\
                   data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":13,\"total_tokens\":24}}}\n\n";
        let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
        let (chisei_target, db) = spawn_control_plane().await;
        let gateway_base = spawn_gateway_with_config(GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            fail_closed: true,
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            no_preflight: false,
            pricing: HashMap::new(),
            run_pipeline: false,
            allow_cross_provider: false,
        })
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), sse);

        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
        assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
        assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("13"));
        assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("24"));
    }

    #[test]
    fn rewrite_request_model_updates_only_model_value() {
        let rewritten =
            rewrite_request_model(br#"{"model":"gpt-5.5","input":"hello"}"#, "gpt-5.5-mini")
                .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["model"], "gpt-5.5-mini");
        assert_eq!(value["input"], "hello");
    }

    #[test]
    fn openai_compatibility_accepts_codex_models() {
        assert!(is_openai_compatible_model("gpt-5.5"));
        assert!(is_openai_compatible_model("o3-mini"));
        assert!(is_openai_compatible_model("o5-pro"));
        assert!(is_openai_compatible_model("text-embedding-3-small"));
        assert!(is_openai_compatible_model("tts-1"));
        assert!(is_openai_compatible_model("ft:gpt-4o-mini:personal:abc"));
        assert!(is_openai_compatible_model("mistral-large"));
        assert!(is_openai_compatible_model("deepseek-chat"));
        assert!(is_openai_compatible_model("llama-3.3-70b"));
        assert!(is_openai_compatible_model("codex-mini-latest"));
        assert!(is_openai_compatible_model("qwen2"));
        assert!(is_openai_compatible_model("phi3"));
        assert!(is_openai_compatible_model("mixtral"));
        assert!(!is_openai_compatible_model("claude-sonnet-4"));
        assert!(!is_openai_compatible_model("gemini-pro"));
        assert!(!is_openai_compatible_model("anthropic-3"));
        assert!(is_openai_compatible_model("native-default"));
        assert!(is_openai_compatible_model("ollama/gpt-oss"));
    }
}
