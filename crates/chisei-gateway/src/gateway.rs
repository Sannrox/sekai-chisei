use std::error::Error as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use chrono::Utc;
use futures_util::StreamExt;
use http_body_util::LengthLimitError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request as GrpcRequest;
use tracing::{Instrument, error, info, warn};

#[cfg(test)]
use crate::client::connect_sekai;
use crate::client::{
    GatewayClient, connect_sekai_as_gateway_with_timeout, connect_sekai_with_timeout,
};
use crate::gateway_keys::hash_gateway_key;
use crate::gateway_support::METRIC_REQUESTS;
use crate::llm::HttpTimeouts;
use crate::pricing::lookup_pricing_entry;
pub use crate::pricing::{ModelPricing, parse_pricing_table};
use crate::provider_profile::{
    CAPABILITY_MATRIX_VERSION, CapabilityMatrix, CapabilityRequirements, ProviderProfile,
    ProviderRegistry, normalize_responses_request, provider_registry_snapshot,
    provider_registry_state_path, refresh_provider_registry, validate_provider_registry_storage,
    validate_responses_request_fields,
};
#[cfg(test)]
use sekai_proto::chisei::GetEffectivePolicySummaryRequest;
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_proto::chisei::{
    ClaimGatewayDispatchRequest, DecideGatewayExecutionRequest, RecordUsageRequest,
    SampleObservation,
};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{
    AppendRowsRequest, ColumnDef, ContextRoot as SekaiContextRoot, CreateDatasetRequest,
    CreateLinkRequest, CreateObjectRequest, Dataset, Decision, FindByExternalIdRequest,
    FindByPropertyRequest, Link, ListSchemaTypesRequest, Object as SekaiObject, QueryRowsRequest,
    RecordDecisionRequest, RetrieveContextRequest, Row, RowFilter, RowQuery, UpdateDatasetRequest,
};
use sekai_provider::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind, UncoveredSurface,
};

const DEFAULT_GATEWAY_BIND: &str = "127.0.0.1:8788";
const DELEGATED_PRINCIPAL_HEADER: &str = "x-sekai-delegated-principal";
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com/v1";
const DEFAULT_MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_REQUESTS: u64 = 120;
const DEFAULT_GLOBAL_RATE_LIMIT_REQUESTS: u64 = 1_200;
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const MAX_RATE_LIMIT_SUBJECTS: usize = 10_000;
const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const X_CHISEI_AGENT: HeaderName = HeaderName::from_static("x-chisei-agent");
const X_CHISEI_PROJECT: HeaderName = HeaderName::from_static("x-chisei-project");
const X_CHISEI_WORK_UNIT: HeaderName = HeaderName::from_static("x-chisei-work-unit");
const X_CHISEI_TASK_ID: HeaderName = HeaderName::from_static("x-chisei-task-id");
const X_CHISEI_TASK_CLASS: HeaderName = HeaderName::from_static("x-chisei-task-class");
const X_CHISEI_ADMISSION: HeaderName = HeaderName::from_static("x-chisei-admission");
const X_CHISEI_DATA_CLASS: HeaderName = HeaderName::from_static("x-chisei-data-class");
const X_CHISEI_ROUTE_OVERRIDE: HeaderName = HeaderName::from_static("x-chisei-route-override");
const X_CHISEI_OPERATION_ID: HeaderName = HeaderName::from_static("x-chisei-operation-id");
const X_CHISEI_PARENT_OPERATION_ID: HeaderName =
    HeaderName::from_static("x-chisei-parent-operation-id");
const X_CHISEI_REQUEST_ID: HeaderName = HeaderName::from_static("x-chisei-request-id");
const X_CHISEI_CALLER_SCOPE: HeaderName = HeaderName::from_static("x-chisei-caller-scope");
const X_CHISEI_CAPABILITY_CATALOG: HeaderName =
    HeaderName::from_static("x-chisei-capability-catalog");
const X_CHISEI_TURN_ID: HeaderName = HeaderName::from_static("x-chisei-turn-id");
const X_CHISEI_ATTEMPT: HeaderName = HeaderName::from_static("x-chisei-attempt");
const X_CHISEI_CYCLE_ID: HeaderName = HeaderName::from_static("x-chisei-cycle-id");
const X_CHISEI_RETRY_SAFETY: HeaderName = HeaderName::from_static("x-chisei-retry-safety");
const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");
const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const DEFAULT_KEY_CACHE_TTL_SECS: u64 = 30;
const READINESS_PROBE_CACHE_SECS: u64 = 5;
const PROVIDER_REGISTRY_REFRESH_TTL_MS: u64 = 250;
const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;
const SSE_VALIDATION_WINDOW_BYTES: usize = 64 * 1024;
const STREAM_FORWARD_CHANNEL_CAPACITY: usize = 32;
const STREAM_FORWARD_CHUNK_BYTES: usize = 64 * 1024;
const MAX_PENDING_USAGE_RECOVERIES: usize = 4096;
const DEFAULT_RECOVERY_SPOOL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CONTROL_PLANE_RETRIES: u32 = 2;
const DEFAULT_CONTROL_PLANE_RETRY_BACKOFF_MS: u64 = 25;
const DEFAULT_CONTROL_PLANE_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_CIRCUIT_FAILURE_THRESHOLD: u32 = 3;
const DEFAULT_CIRCUIT_COOLDOWN_SECS: u64 = 5;
const DEFAULT_UPSTREAM_CONNECT_RETRIES: u32 = 1;
const MAX_PROVIDER_RETRY_AFTER_SECS: u64 = 60 * 60;
const RECOVERY_REPLAY_YIELD_INTERVAL: usize = 32;
const SCHEMA_RECONCILIATION_RETRY_MS: u64 = 60_000;
const DEFAULT_GATEWAY_TIER: &str = "standard";
const MIN_ADMIN_TOKEN_BYTES: usize = 32;
const DEFAULT_USAGE_RECOVERY_PATH: &str = "data/chisei-gateway-usage-recovery.json";
const DEFAULT_RECOVERY_SPOOL_PATH: &str = "data/chisei-gateway-recovery.jsonl";
pub(crate) use sekai_provider::gateway_contract::LLM_CALLS_COLUMNS;

#[path = "gateway_runtime.rs"]
mod runtime;
use runtime::*;
pub use runtime::{app, serve};
#[path = "gateway_proxy.rs"]
mod proxy;
use proxy::*;
#[path = "gateway_decision.rs"]
mod decision;
use decision::*;
#[path = "gateway_protocol.rs"]
mod protocol;
use protocol::*;
#[path = "gateway_identity.rs"]
mod identity;
use identity::*;
#[path = "gateway_upstream.rs"]
mod upstream;
use upstream::*;
#[path = "gateway_usage.rs"]
mod usage;
use usage::*;
#[path = "gateway_recovery.rs"]
mod recovery;
use recovery::*;
#[path = "gateway_response.rs"]
mod response;
use response::*;

#[derive(Clone)]
pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub openai_base_url: String,
    pub openai_api_key: Option<String>,
    pub anthropic_base_url: String,
    pub anthropic_api_key: Option<String>,
    pub ollama_base_url: String,
    pub native_base_url: Option<String>,
    pub chisei_grpc_target: Option<String>,
    pub default_project: String,
    pub gateway_keys: HashMap<String, GatewayIdentity>,
    pub allow_auth_passthrough: bool,
    pub rewrite_openai_passthrough_auth: bool,
    pub pricing: HashMap<String, ModelPricing>,
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
        let openai_api_key =
            crate::secrets::resolve_optional("OPENAI_API_KEY", "CHISEI_OPENAI_API_KEY_SECRET")?;
        // Resolve the gateway's own Anthropic upstream from CHISEI_ANTHROPIC_BASE_URL
        // then the built-in default only. ANTHROPIC_BASE_URL is intentionally NOT a
        // fallback here: it is the *client*-facing variable that points clients at
        // the gateway, commonly set to `https://api.anthropic.com` with no `/v1`.
        // Using it as the gateway's upstream misroutes calls to `…/messages`.
        let anthropic_base_url = normalize_anthropic_base_url(
            &std::env::var("CHISEI_ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_ANTHROPIC_BASE_URL.to_string()),
        );
        let anthropic_api_key = crate::secrets::resolve_optional(
            "ANTHROPIC_API_KEY",
            "CHISEI_ANTHROPIC_API_KEY_SECRET",
        )?;
        let ollama_base_url = std::env::var("CHISEI_OLLAMA_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                let base =
                    std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".into());
                format!("{}/v1", base.trim_end_matches('/'))
            });
        let native_base_url = std::env::var("NATIVE_LLM_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let allow_auth_passthrough = matches!(
            std::env::var("CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        let rewrite_openai_passthrough_auth = matches!(
            std::env::var("CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
        let xai_configured =
            std::env::var("XAI_API_KEY").is_ok_and(|value| !value.trim().is_empty());
        let meta_configured = std::env::var("META_MODEL_API_KEY")
            .is_ok_and(|value| !value.trim().is_empty())
            && std::env::var("CHISEI_META_BASE_URL").is_ok_and(|value| !value.trim().is_empty());
        let hosted_key_configured = xai_configured || meta_configured;
        if openai_api_key.is_none()
            && anthropic_api_key.is_none()
            && !hosted_key_configured
            && !allow_auth_passthrough
        {
            return Err("a configured provider API key is required for chisei-gateway".into());
        }
        let chisei_grpc_target = required_control_plane_target(
            std::env::var("CHISEI_GRPC_URL").ok(),
            std::env::var("SEKAI_SOCKET").ok(),
        )?;
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
        let allow_cross_provider = matches!(
            std::env::var("CHISEI_GATEWAY_ALLOW_CROSS_PROVIDER").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );

        validate_gateway_security(
            bind_addr,
            &gateway_keys,
            allow_auth_passthrough,
            std::env::var("CHISEI_GATEWAY_ADMIN_TOKEN").ok().as_deref(),
        )?;

        Ok(Self {
            bind_addr,
            openai_base_url,
            openai_api_key,
            anthropic_base_url,
            anthropic_api_key,
            ollama_base_url,
            native_base_url,
            chisei_grpc_target: Some(chisei_grpc_target),
            default_project,
            gateway_keys,
            allow_auth_passthrough,
            rewrite_openai_passthrough_auth,
            pricing,
            allow_cross_provider,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayIdentity {
    pub agent: String,
    pub project: String,
    pub user_id: String,
    pub key_id: String,
    pub tier: String,
}

impl GatewayIdentity {
    fn context_principal(&self) -> &str {
        if self.key_id.is_empty() {
            "gateway-passthrough"
        } else {
            &self.user_id
        }
    }

    fn can_delegate_principal(&self) -> bool {
        !self.key_id.is_empty() && self.tier != "untrusted"
    }

    fn delegated_principal(&self) -> &str {
        &self.agent
    }
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
    authenticated: crate::enterprise::AuthenticatedContext,
}

impl IdentityContext {
    fn machine(identity: GatewayIdentity, upstream_auth: UpstreamAuthMode) -> Self {
        let authenticated = crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: identity.context_principal().to_string(),
                credential_id: identity.key_id.clone(),
            },
        );
        Self {
            identity,
            upstream_auth,
            authenticated,
        }
    }
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
    http_timeouts: HttpTimeouts,
    max_request_bytes: usize,
    rate_limit_requests: u64,
    global_rate_limit_requests: u64,
    rate_limit_window: Duration,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitWindow>>>,
    usage_recovery: Arc<RwLock<UsageRecoveryState>>,
    usage_recovery_path: Option<PathBuf>,
    usage_recovery_lock: Arc<Mutex<()>>,
    provider_registry_state_path: Option<PathBuf>,
    provider_registry_refresh: Arc<Mutex<ProviderRegistryRefreshState>>,
    provider_registry_refresh_generation: Arc<AtomicU64>,
    recovery_spool_path: Option<PathBuf>,
    recovery_spool_max_bytes: u64,
    recovery_spool_lock: Arc<Mutex<()>>,
    recovery_replay_running: Arc<AtomicBool>,
    llm_calls_schema_reconciled: Arc<AtomicBool>,
    llm_calls_schema_retry_after_ms: Arc<AtomicU64>,
    llm_calls_schema_lock: Arc<Mutex<()>>,
    control_plane_circuit: Arc<RwLock<CircuitBreakerState>>,
    readiness_probe: Arc<Mutex<Option<(Instant, bool)>>>,
    upstream_circuits: Arc<RwLock<HashMap<String, CircuitBreakerState>>>,
    resilience: ResilienceConfig,
}

#[derive(Debug, Clone)]
struct ResilienceConfig {
    control_plane_retries: u32,
    control_plane_retry_backoff: Duration,
    control_plane_timeout: Duration,
    circuit_failure_threshold: u32,
    circuit_cooldown: Duration,
    upstream_connect_retries: u32,
}

#[derive(Default)]
struct ProviderRegistryRefreshState {
    refreshed_at: Option<Instant>,
    result: Option<Result<ProviderRegistry, String>>,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            control_plane_retries: DEFAULT_CONTROL_PLANE_RETRIES,
            control_plane_retry_backoff: Duration::from_millis(
                DEFAULT_CONTROL_PLANE_RETRY_BACKOFF_MS,
            ),
            control_plane_timeout: Duration::from_millis(DEFAULT_CONTROL_PLANE_TIMEOUT_MS),
            circuit_failure_threshold: DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
            circuit_cooldown: Duration::from_secs(DEFAULT_CIRCUIT_COOLDOWN_SECS),
            upstream_connect_retries: DEFAULT_UPSTREAM_CONNECT_RETRIES,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    last_failure: Option<String>,
    health: ProviderHealth,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderHealth {
    #[default]
    Unknown,
    Healthy,
    RateLimited,
    QuotaExhausted,
    Overloaded,
    Unavailable,
}

impl CircuitBreakerState {
    fn is_open(&self) -> bool {
        self.open_until.is_some_and(|until| Instant::now() < until)
    }

    /// Drop an expired cooldown and publish the observed open state.
    ///
    /// The Prometheus gauge is last-observed: it is updated whenever traffic or
    /// status handling inspects the circuit, including after a time-based
    /// cooldown has already expired.
    fn observe(&mut self, provider: &str) -> bool {
        if self.open_until.is_some_and(|until| Instant::now() >= until) {
            self.open_until = None;
        }
        let open = self.is_open();
        crate::obs::signals::set_provider_circuit_open(provider, open);
        open
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
        self.last_failure = None;
        self.health = ProviderHealth::Healthy;
    }

    fn record_failure(&mut self, error: String, config: &ResilienceConfig) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(error);
        self.health = ProviderHealth::Unavailable;
        if self.consecutive_failures >= config.circuit_failure_threshold {
            self.open_until = Some(Instant::now() + config.circuit_cooldown);
        }
    }

    fn publish_metrics(&self, provider: &str) {
        crate::obs::signals::set_provider_circuit_open(provider, self.is_open());
    }

    fn record_http_signal(
        &mut self,
        signal: ProviderHealth,
        retry_after: Option<Duration>,
        config: &ResilienceConfig,
    ) {
        match signal {
            ProviderHealth::Healthy | ProviderHealth::Unknown => self.record_success(),
            ProviderHealth::RateLimited | ProviderHealth::QuotaExhausted => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.health = signal;
                self.last_failure = Some(format!("provider health is {signal:?}"));
                self.open_until =
                    Instant::now().checked_add(retry_after.unwrap_or(config.circuit_cooldown));
            }
            ProviderHealth::Overloaded | ProviderHealth::Unavailable => {
                self.record_failure(format!("provider health is {signal:?}"), config);
                self.health = signal;
                if let Some(retry_after) = retry_after {
                    self.open_until = Instant::now().checked_add(retry_after);
                }
            }
        }
    }
}

#[derive(Default)]
struct UsageRecoveryState {
    pending_usage_records: HashMap<String, RecordUsageRequest>,
    usage_recovery_saturated: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingUsageRecovery {
    user_id: String,
    tokens_used: i32,
    subject: String,
    project: String,
    agent: String,
    key_id: String,
    work_unit: String,
    metric: String,
    idempotency_key: String,
    #[serde(default)]
    operation_receipt_json: String,
}

impl From<RecordUsageRequest> for PendingUsageRecovery {
    fn from(request: RecordUsageRequest) -> Self {
        Self {
            user_id: request.user_id,
            tokens_used: request.tokens_used,
            subject: request.subject,
            project: request.project,
            agent: request.agent,
            key_id: request.key_id,
            work_unit: request.work_unit,
            metric: request.metric,
            idempotency_key: request.idempotency_key,
            operation_receipt_json: request.operation_receipt_json,
        }
    }
}

impl From<PendingUsageRecovery> for RecordUsageRequest {
    fn from(request: PendingUsageRecovery) -> Self {
        Self {
            user_id: request.user_id,
            tokens_used: request.tokens_used,
            subject: request.subject,
            project: request.project,
            agent: request.agent,
            key_id: request.key_id,
            work_unit: request.work_unit,
            metric: request.metric,
            idempotency_key: request.idempotency_key,
            operation_receipt_json: request.operation_receipt_json,
            sample_observation: None,
        }
    }
}

impl GatewayRuntime {
    fn from_env() -> Self {
        let key_cache_ttl = std::env::var("CHISEI_GATEWAY_KEY_CACHE_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS));
        let resilience = ResilienceConfig {
            control_plane_retries: env_u32(
                "CHISEI_GATEWAY_CONTROL_PLANE_RETRIES",
                DEFAULT_CONTROL_PLANE_RETRIES,
            ),
            control_plane_retry_backoff: Duration::from_millis(env_u64(
                "CHISEI_GATEWAY_CONTROL_PLANE_RETRY_BACKOFF_MS",
                DEFAULT_CONTROL_PLANE_RETRY_BACKOFF_MS,
            )),
            control_plane_timeout: configured_control_plane_timeout(),
            circuit_failure_threshold: env_u32(
                "CHISEI_GATEWAY_CIRCUIT_FAILURE_THRESHOLD",
                DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
            )
            .max(1),
            circuit_cooldown: Duration::from_secs(env_u64(
                "CHISEI_GATEWAY_CIRCUIT_COOLDOWN_SECS",
                DEFAULT_CIRCUIT_COOLDOWN_SECS,
            )),
            upstream_connect_retries: env_u32(
                "CHISEI_GATEWAY_UPSTREAM_CONNECT_RETRIES",
                DEFAULT_UPSTREAM_CONNECT_RETRIES,
            ),
        };
        let mut runtime = Self::new(
            key_cache_ttl,
            std::env::var("CHISEI_GATEWAY_ADMIN_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        )
        .with_resilience(resilience)
        .with_usage_recovery_path(Some(resolve_usage_recovery_path(
            std::env::var("CHISEI_GATEWAY_USAGE_RECOVERY_PATH").ok(),
        )))
        // Registry state sits beside the Sekai (or shared) file. The gateway
        // does not open a third durable store.
        .with_provider_registry_state_path(Some(provider_registry_state_path(
            &std::env::var("SEKAI_DB_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| std::env::var("DB_PATH").ok())
                .unwrap_or_else(|| "./data/sekai.db".to_string()),
        )))
        .with_recovery_spool_path(Some(resolve_recovery_spool_path(
            std::env::var("CHISEI_GATEWAY_RECOVERY_SPOOL_PATH").ok(),
        )))
        .with_http_timeouts(HttpTimeouts::from_env());
        runtime.recovery_spool_max_bytes = std::env::var("CHISEI_GATEWAY_RECOVERY_SPOOL_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RECOVERY_SPOOL_MAX_BYTES)
            .max(1);
        runtime.max_request_bytes =
            positive_env("CHISEI_GATEWAY_MAX_REQUEST_BYTES").unwrap_or(DEFAULT_MAX_REQUEST_BYTES);
        runtime.rate_limit_requests = positive_env("CHISEI_GATEWAY_RATE_LIMIT_REQUESTS")
            .unwrap_or(DEFAULT_RATE_LIMIT_REQUESTS as usize)
            as u64;
        runtime.global_rate_limit_requests =
            positive_env("CHISEI_GATEWAY_GLOBAL_RATE_LIMIT_REQUESTS")
                .unwrap_or(DEFAULT_GLOBAL_RATE_LIMIT_REQUESTS as usize) as u64;
        runtime.rate_limit_window = Duration::from_secs(
            positive_env("CHISEI_GATEWAY_RATE_LIMIT_WINDOW_SECS")
                .unwrap_or(DEFAULT_RATE_LIMIT_WINDOW_SECS as usize) as u64,
        );
        runtime
    }

    fn new(key_cache_ttl: Duration, admin_token: Option<String>) -> Self {
        Self {
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            key_cache_ttl,
            admin_token,
            http_timeouts: HttpTimeouts::default(),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            rate_limit_requests: DEFAULT_RATE_LIMIT_REQUESTS,
            global_rate_limit_requests: DEFAULT_GLOBAL_RATE_LIMIT_REQUESTS,
            rate_limit_window: Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            usage_recovery: Arc::new(RwLock::new(UsageRecoveryState::default())),
            usage_recovery_path: None,
            usage_recovery_lock: Arc::new(Mutex::new(())),
            provider_registry_state_path: None,
            provider_registry_refresh: Arc::new(
                Mutex::new(ProviderRegistryRefreshState::default()),
            ),
            provider_registry_refresh_generation: Arc::new(AtomicU64::new(0)),
            recovery_spool_path: None,
            recovery_spool_max_bytes: DEFAULT_RECOVERY_SPOOL_MAX_BYTES,
            recovery_spool_lock: Arc::new(Mutex::new(())),
            recovery_replay_running: Arc::new(AtomicBool::new(false)),
            llm_calls_schema_reconciled: Arc::new(AtomicBool::new(false)),
            llm_calls_schema_retry_after_ms: Arc::new(AtomicU64::new(0)),
            llm_calls_schema_lock: Arc::new(Mutex::new(())),
            control_plane_circuit: Arc::new(RwLock::new(CircuitBreakerState::default())),
            readiness_probe: Arc::new(Mutex::new(None)),
            upstream_circuits: Arc::new(RwLock::new(HashMap::new())),
            resilience: ResilienceConfig::default(),
        }
    }

    fn with_http_timeouts(mut self, http_timeouts: HttpTimeouts) -> Self {
        self.http_timeouts = http_timeouts;
        self
    }

    fn with_resilience(mut self, resilience: ResilienceConfig) -> Self {
        self.resilience = resilience;
        self
    }

    fn with_usage_recovery_path(mut self, path: Option<PathBuf>) -> Self {
        self.usage_recovery_path = path;
        if let Some(path) = self.usage_recovery_path.as_ref() {
            let cache = Arc::get_mut(&mut self.usage_recovery)
                .expect("new gateway runtime cache is not shared")
                .get_mut();
            match std::fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<Vec<PendingUsageRecovery>>(&bytes) {
                    Ok(entries) => {
                        for entry in entries {
                            let request = RecordUsageRequest::from(entry);
                            cache
                                .pending_usage_records
                                .insert(usage_recovery_key(&request), request);
                        }
                    }
                    Err(error) => {
                        error!(path = %path.display(), %error, "usage recovery journal is invalid");
                        cache.usage_recovery_saturated = true;
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match initialize_usage_recovery_journal(path) {
                        Ok(entries) => {
                            for entry in entries {
                                let request = RecordUsageRequest::from(entry);
                                cache
                                    .pending_usage_records
                                    .insert(usage_recovery_key(&request), request);
                            }
                        }
                        Err(error) => {
                            error!(path = %path.display(), %error, "usage recovery journal cannot be initialized");
                            cache.usage_recovery_saturated = true;
                        }
                    }
                }
                Err(error) => {
                    error!(path = %path.display(), %error, "usage recovery journal is unreadable");
                    cache.usage_recovery_saturated = true;
                }
            }
        }
        self
    }

    fn with_provider_registry_state_path(mut self, path: Option<PathBuf>) -> Self {
        self.provider_registry_state_path = path;
        self
    }

    async fn refresh_registry_snapshot(&self, force: bool) -> Result<ProviderRegistry, String> {
        let observed_generation = self
            .provider_registry_refresh_generation
            .load(Ordering::Acquire);
        self.refresh_registry_snapshot_after_generation(force, observed_generation)
            .await
    }

    async fn refresh_registry_snapshot_after_generation(
        &self,
        force: bool,
        observed_generation: u64,
    ) -> Result<ProviderRegistry, String> {
        let Some(path) = self.provider_registry_state_path.clone() else {
            return Ok(provider_registry_snapshot());
        };
        let mut refresh = self.provider_registry_refresh.lock().await;
        let refresh_completed_while_waiting = self
            .provider_registry_refresh_generation
            .load(Ordering::Acquire)
            != observed_generation;
        let reusable = refresh_completed_while_waiting
            || !force
                && refresh.refreshed_at.is_some_and(|refreshed_at| {
                    refreshed_at.elapsed() < Duration::from_millis(PROVIDER_REGISTRY_REFRESH_TTL_MS)
                });
        if reusable && let Some(result) = refresh.result.as_ref() {
            return result.clone();
        }
        let result = crate::provider_resolution::snapshot_for_execution(Some(&path)).await;
        refresh.refreshed_at = Some(Instant::now());
        refresh.result = Some(result.clone());
        self.provider_registry_refresh_generation
            .fetch_add(1, Ordering::Release);
        result
    }

    #[cfg(test)]
    async fn invalidate_registry_snapshot(&self) {
        let mut refresh = self.provider_registry_refresh.lock().await;
        refresh.refreshed_at = None;
        refresh.result = None;
        self.provider_registry_refresh_generation
            .fetch_add(1, Ordering::Release);
    }
    fn with_recovery_spool_path(mut self, path: Option<PathBuf>) -> Self {
        self.recovery_spool_path = path;
        self
    }
}

#[derive(Debug, Clone)]
struct RateLimitWindow {
    started_at: Instant,
    requests: u64,
}

#[derive(Debug, Clone)]
struct KeyCacheEntry {
    identity: Option<GatewayIdentity>,
    cached_at: Instant,
}

pub const COMMUNITY_GATEWAY_ROUTES: &[&str] = &[
    "/healthz",
    "/readyz",
    "/statusz",
    "/_chisei/admin/refresh",
    "/{*path}",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayCorrelation {
    caller_scope: String,
    operation_id: String,
    parent_operation_id: Option<String>,
    request_id: String,
    lookup_request_id: Option<String>,
    turn_id: Option<String>,
    attempt: u32,
    cycle_id: Option<String>,
    traceparent: Option<String>,
}

impl GatewayCorrelation {
    fn generated(caller_scope: &str) -> Self {
        let request_id = format!("chisei:{caller_scope}:{}", uuid::Uuid::new_v4());
        Self {
            caller_scope: caller_scope.into(),
            operation_id: request_id.clone(),
            parent_operation_id: None,
            request_id,
            lookup_request_id: None,
            turn_id: None,
            attempt: 1,
            cycle_id: None,
            traceparent: None,
        }
    }

    fn from_headers(headers: &HeaderMap, caller_scope: &str) -> Result<Self, String> {
        let mut correlation = Self::generated(caller_scope);
        let supplied_operation_id = correlation_header(headers, &X_CHISEI_OPERATION_ID)?;
        if let Some(value) = supplied_operation_id.as_deref() {
            correlation.operation_id = scoped_operation_id(value, caller_scope)?;
        }
        if let Some(value) = correlation_header(headers, &X_CHISEI_REQUEST_ID)? {
            if value.starts_with("chisei:") {
                return Err("x-chisei-request-id uses the reserved chisei namespace".into());
            }
            correlation.lookup_request_id = Some(value.clone());
            correlation.request_id = scoped_request_id(&value, caller_scope);
            if supplied_operation_id.is_none() {
                correlation.operation_id = correlation.request_id.clone();
            }
        }
        correlation.parent_operation_id =
            correlation_header(headers, &X_CHISEI_PARENT_OPERATION_ID)?
                .map(|value| scoped_operation_id(&value, caller_scope))
                .transpose()?;
        correlation.turn_id = correlation_header(headers, &X_CHISEI_TURN_ID)?;
        correlation.cycle_id = correlation_header(headers, &X_CHISEI_CYCLE_ID)?;
        if let Some(value) = correlation_header(headers, &X_CHISEI_ATTEMPT)? {
            correlation.attempt = value
                .parse::<u32>()
                .ok()
                .filter(|attempt| *attempt > 0)
                .ok_or_else(|| "x-chisei-attempt must be a positive integer".to_string())?;
        }
        correlation.traceparent = header_str(headers, &TRACEPARENT)
            .map(validate_traceparent)
            .transpose()?;
        Ok(correlation)
    }

    fn apply_response_headers(&self, response: &mut Response<Body>) {
        let headers = response.headers_mut();
        insert_header(headers, &X_CHISEI_OPERATION_ID, &self.operation_id);
        insert_header(
            headers,
            &X_CHISEI_REQUEST_ID,
            self.lookup_request_id
                .as_deref()
                .unwrap_or(&self.request_id),
        );
        insert_header(headers, &X_CHISEI_ATTEMPT, &self.attempt.to_string());
        if let Some(value) = &self.parent_operation_id {
            insert_header(headers, &X_CHISEI_PARENT_OPERATION_ID, value);
        }
        if let Some(value) = &self.turn_id {
            insert_header(headers, &X_CHISEI_TURN_ID, value);
        }
        if let Some(value) = &self.cycle_id {
            insert_header(headers, &X_CHISEI_CYCLE_ID, value);
        }
        if let Some(value) = &self.traceparent {
            insert_header(headers, &TRACEPARENT, value);
        }
    }
}

#[derive(Debug, Clone)]
struct UsageContext {
    request_id: String,
    lookup_request_id: Option<String>,
    caller_scope: String,
    operation_id: String,
    parent_operation_id: Option<String>,
    turn_id: Option<String>,
    attempt: u32,
    /// Internal mid-request provider ordinal (1-based). Distinct from the
    /// client-controlled attempt so failover receipts never collide with a
    /// later client retry at attempt+1.
    provider_ordinal: u32,
    cycle_id: Option<String>,
    traceparent: Option<String>,
    responses_profile: bool,
    responses_terminal_required: bool,
    provider: ProviderKind,
    requested_model: Option<String>,
    resolved_model: Option<String>,
    route_override: Option<String>,
    requested_alias: Option<String>,
    profile_version: Option<String>,
    capability_snapshot_version: Option<String>,
    pricing_snapshot_version: Option<String>,
    governance_metadata_status: Option<String>,
    work_unit_id: Option<String>,
    pipeline_observation: Option<GatewayPipelineObservation>,
    request_bytes: usize,
    started_ms: i64,
    route_bias: Option<String>,
    policy_scope: Option<String>,
    policy_version: Option<String>,
    context_admission_policy_version: Option<String>,
    context_admission_descriptor_version: Option<String>,
    context_admission_decision: Option<String>,
    context_admission_reasons: Vec<String>,
    task_class: String,
    data_class: String,
    request_hash: String,
    budget_subject: Option<String>,
    budget_status: String,
    egress_applied: bool,
    cache_requested: bool,
}

#[derive(Debug)]
struct GatewayRejection {
    status: StatusCode,
    error_type: String,
    reason: String,
    retry_safety: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct ReceiptRejection<'a> {
    rejection: &'a GatewayRejection,
    model_attempted: bool,
}

impl GatewayRejection {
    fn json(status: StatusCode, error_type: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            status,
            error_type: error_type.to_string(),
            reason,
            retry_safety: None,
        }
    }

    fn with_retry_safety(mut self, retry_safety: &'static str) -> Self {
        self.retry_safety = Some(retry_safety);
        self
    }

    fn response(&self) -> Response<Body> {
        match self.retry_safety {
            Some(retry_safety) => json_error_with_retry_safety(
                self.status,
                &self.error_type,
                &self.reason,
                retry_safety,
            ),
            None => json_error(self.status, &self.error_type, &self.reason),
        }
    }
}

/// Admit payload returned by the gateway's canonical governance decision.
#[derive(Debug, Clone)]
struct GatewayDecisionAdmit {
    resolved_model: String,
    resolved_runtime: String,
    policy_version: String,
    budget_scope: String,
    /// Reserved for usage/receipt correlation once post-call accounting binds it.
    #[allow(dead_code)]
    budget_grant_id: String,
    route_bias: Option<String>,
    provisional_local_free: bool,
    policy_scope: Option<String>,
    data_class: Option<String>,
    fallback_models: Vec<String>,
    eval_regressed: bool,
    eval_regression_reason: String,
    context_admission_policy_version: Option<String>,
    context_admission_descriptor_version: Option<String>,
    context_admission_decision: Option<String>,
    context_admission_reasons: Vec<String>,
    pipeline_observation: Option<GatewayPipelineObservation>,
    metadata_operation: bool,
}

#[derive(Debug, Clone, Default)]
struct BudgetPreflight {
    provisional_local_free: bool,
    budget_subject: Option<String>,
}

#[derive(Debug, Clone)]
struct PolicyPreflight {
    body: Vec<u8>,
    resolved_model: Option<String>,
    resolved_provider: ProviderKind,
    route_bias: Option<String>,
    policy_scope: Option<String>,
    policy_version: Option<String>,
    fallback_models: Vec<String>,
    data_class: Option<String>,
    context_admission_policy_version: Option<String>,
    context_admission_descriptor_version: Option<String>,
    context_admission_decision: Option<String>,
    context_admission_reasons: Vec<String>,
}

/// Maximum distinct upstream providers tried for one client call (primary + failover).
const MAX_MID_REQUEST_PROVIDER_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone)]
struct ContextEgressPreflight {
    body: Vec<u8>,
}

const MAX_CONTEXT_OBJECT_SELECTORS: usize = 32;
const MAX_CONTEXT_FIELDS_PER_OBJECT: usize = 32;
const MAX_CONTEXT_RETRIEVAL_RELATIONS: usize = 8;
const MAX_CONTEXT_RETRIEVAL_KINDS: usize = 8;
const MAX_CONTEXT_RETRIEVAL_DEPTH: i32 = 3;
const MAX_CONTEXT_RETRIEVAL_OBJECTS: i32 = 32;
const MAX_CONTEXT_RETRIEVAL_LINKS: i32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayContextRequest {
    objects: Vec<GatewayContextObject>,
    retrieval: Option<GatewayContextRetrieval>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayContextObject {
    root: GatewayContextRoot,
    fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GatewayContextRoot {
    External(String),
    Object(String),
    Link(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayContextRetrieval {
    relations: Vec<String>,
    direction: String,
    max_depth: i32,
    max_objects: i32,
    max_links: i32,
    kinds: Vec<String>,
    fields: Vec<String>,
}

struct ResolvedGatewayContextObject {
    object: crate::domain::Object,
    fields: Vec<String>,
    expanded: bool,
}

#[derive(Default)]
struct GatewayContextResolution {
    objects: Vec<ResolvedGatewayContextObject>,
    unresolved_roots: u32,
    denied_objects: u32,
    truncated_objects: u32,
    truncated_links: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGatewayContextRequest {
    objects: Vec<RawGatewayContextObject>,
    #[serde(default)]
    retrieval: Option<RawGatewayContextRetrieval>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGatewayContextObject {
    #[serde(rename = "ref", default)]
    external_id: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    link_id: Option<String>,
    fields: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGatewayContextRetrieval {
    relations: Vec<String>,
    direction: String,
    max_depth: i32,
    max_objects: i32,
    max_links: i32,
    kinds: Vec<String>,
    fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseAdapter {
    Passthrough,
    OpenAiChatToAnthropicMessage,
    /// Translate an OpenAI-compatible chat-completions SSE stream into an
    /// Anthropic Messages SSE stream (message_start / content_block_* /
    /// message_delta / message_stop).
    OpenAiChatStreamToAnthropicMessage,
}

#[derive(Debug, Clone)]
struct PreparedUpstreamRequest {
    provider: ProviderKind,
    url: String,
    body: Vec<u8>,
    response_adapter: ResponseAdapter,
    client_response_model: Option<String>,
    /// True when the request was translated across provider families (client
    /// provider differs from the resolved upstream provider). The client's
    /// credential must not be forwarded to a different provider's upstream.
    cross_provider: bool,
}

/// Incrementally translates an OpenAI-compatible chat-completions SSE stream
/// into an Anthropic Messages SSE stream. Feed upstream bytes via `push` (which
/// returns any Anthropic events ready to forward) and call `finish` at end of
/// stream to emit the closing events.
///
/// Client-facing token fidelity note: `message_start.usage.input_tokens` is
/// emitted as 0 because OpenAI reports usage only in its trailing chunk, after
/// `message_start` must already have been flushed to keep the stream responsive.
/// The trailing `completion_tokens` is captured and surfaced on the closing
/// `message_delta`. Server-side metering is unaffected: the gateway taps the
/// upstream OpenAI stream (which carries both prompt and completion tokens)
/// separately for `RecordUsage`.
struct AnthropicMessageStreamTranslator {
    pending: Vec<u8>,
    model: String,
    message_id: String,
    started: bool,
    finished: bool,
    stop_reason: String,
    output_tokens: i64,
}

impl AnthropicMessageStreamTranslator {
    fn new(model: String) -> Self {
        Self {
            pending: Vec::new(),
            model,
            message_id: "msg_chisei_stream".to_string(),
            started: false,
            finished: false,
            stop_reason: "end_turn".to_string(),
            output_tokens: 0,
        }
    }

    fn push_window(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if bytes.len() > SSE_VALIDATION_WINDOW_BYTES {
            return Err("internal SSE translation window exceeds the gateway limit".into());
        }
        let mut out = Vec::new();
        self.pending.extend_from_slice(bytes);
        while let Some((boundary, separator_len)) = find_sse_event_boundary(&self.pending) {
            if boundary > MAX_SSE_FRAME_BYTES {
                self.pending.clear();
                return Err("upstream SSE frame exceeds the gateway limit".into());
            }
            let event = self.pending.drain(..boundary).collect::<Vec<_>>();
            self.pending.drain(..separator_len);
            self.translate_event(&event, &mut out);
        }
        if self.pending.len() > MAX_SSE_FRAME_BYTES {
            self.pending.clear();
            return Err("upstream SSE frame exceeds the gateway limit".into());
        }
        Ok(out)
    }

    fn finish(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.pending.is_empty() {
            let event = std::mem::take(&mut self.pending);
            self.translate_event(&event, &mut out);
        }
        self.emit_close(&mut out);
        out
    }

    fn translate_event(&mut self, event: &[u8], out: &mut Vec<u8>) {
        let Some(data) = extract_sse_data(event) else {
            return;
        };
        if data.trim() == "[DONE]" {
            return;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else {
            return;
        };
        // OpenAI streams usage in a trailing chunk (with stream_options) that has
        // an empty choices array; carry completion_tokens to the client's
        // message_delta so its own token accounting is non-zero.
        if let Some(completion_tokens) = value
            .pointer("/usage/completion_tokens")
            .and_then(|value| value.as_i64())
        {
            self.output_tokens = completion_tokens;
        }
        if let Some(choice) = value.pointer("/choices/0") {
            if let Some(text) = choice
                .pointer("/delta/content")
                .and_then(|value| value.as_str())
                && !text.is_empty()
            {
                self.ensure_started(out);
                push_anthropic_event(
                    out,
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": text}
                    }),
                );
            }
            if let Some(reason) = choice.get("finish_reason").and_then(|value| value.as_str()) {
                self.stop_reason = match reason {
                    "length" => "max_tokens",
                    "tool_calls" | "function_call" => "tool_use",
                    _ => "end_turn",
                }
                .to_string();
            }
        }
    }

    fn ensure_started(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        push_anthropic_event(
            out,
            "message_start",
            &serde_json::json!({
                "type": "message_start",
                "message": {
                    "id": self.message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": self.model,
                    "content": [],
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {"input_tokens": 0, "output_tokens": 0}
                }
            }),
        );
        push_anthropic_event(
            out,
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            }),
        );
    }

    fn emit_close(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.finished = true;
        // Always emit a well-formed message even for an empty stream.
        self.ensure_started(out);
        push_anthropic_event(
            out,
            "content_block_stop",
            &serde_json::json!({"type": "content_block_stop", "index": 0}),
        );
        push_anthropic_event(
            out,
            "message_delta",
            &serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": self.stop_reason, "stop_sequence": null},
                "usage": {"output_tokens": self.output_tokens}
            }),
        );
        push_anthropic_event(
            out,
            "message_stop",
            &serde_json::json!({"type": "message_stop"}),
        );
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenAiRuntime {
    OpenAi,
    Ollama,
    Native,
    Xai,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    OpenAi(OpenAiRuntime),
    Anthropic,
}

#[derive(Debug)]
enum UpstreamSendError {
    CircuitOpen {
        health: ProviderHealth,
    },
    Request {
        error: reqwest::Error,
        snapshot_version: String,
    },
    Governance {
        rejection: GatewayRejection,
        snapshot_version: String,
        model_attempted: bool,
    },
}

struct ProviderContactGuard {
    provider: ProviderKind,
    resolved_model: Option<String>,
    requirements: Option<CapabilityRequirements>,
}

impl ProviderContactGuard {
    async fn enforce(
        &self,
        runtime: &GatewayRuntime,
    ) -> Result<String, (GatewayRejection, String)> {
        let registry = runtime
            .refresh_registry_snapshot(true)
            .await
            .map_err(|reason| {
                (
                    GatewayRejection::json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "provider_registry_unavailable",
                        reason,
                    ),
                    capability_snapshot_identifier(&provider_registry_snapshot()),
                )
            })?;
        let snapshot_version = capability_snapshot_identifier(&registry);
        let provider_id = capability_provider_id(self.provider);
        registry
            .ensure_provider_available(provider_id)
            .map_err(|reason| {
                (
                    GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", reason),
                    snapshot_version.clone(),
                )
            })?;
        if let Some(model) = self.resolved_model.as_deref() {
            let resolved = registry.resolve_model(model).map_err(|reason| {
                (
                    GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", reason),
                    snapshot_version.clone(),
                )
            })?;
            if resolved.provider != provider_id {
                return Err((
                    GatewayRejection::json(
                        StatusCode::FORBIDDEN,
                        "policy_denied",
                        format!(
                            "resolved model provider {:?} does not match routed provider {provider_id:?}",
                            resolved.provider
                        ),
                    ),
                    snapshot_version,
                ));
            }
        }
        if let Some(requirements) = &self.requirements {
            let profile = registry.effective_profile(provider_id).ok_or_else(|| {
                (
                    GatewayRejection::json(
                        StatusCode::BAD_REQUEST,
                        "capability_unsupported",
                        format!("provider {provider_id} has no capability profile"),
                    ),
                    snapshot_version.clone(),
                )
            })?;
            let missing = requirements.unsupported_by(&profile.capabilities);
            if !missing.is_empty() {
                return Err((
                    GatewayRejection::json(
                        StatusCode::BAD_REQUEST,
                        "capability_unsupported",
                        format!(
                            "provider {provider_id} cannot preserve required capabilities: {}",
                            missing.join(", ")
                        ),
                    ),
                    snapshot_version,
                ));
            }
        }
        Ok(snapshot_version)
    }
}

impl ProviderKind {
    fn from_runtime(runtime: &str) -> Option<Self> {
        match runtime {
            "openai" => Some(Self::OpenAi(OpenAiRuntime::OpenAi)),
            "ollama" => Some(Self::OpenAi(OpenAiRuntime::Ollama)),
            "native" => Some(Self::OpenAi(OpenAiRuntime::Native)),
            "xai" => Some(Self::OpenAi(OpenAiRuntime::Xai)),
            "meta" => Some(Self::OpenAi(OpenAiRuntime::Meta)),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }

    /// Derives the concrete backend from a model name. Used to pick the upstream
    /// per resolved model (e.g. `ollama/llama3.2` routes to the Ollama backend),
    /// which is more reliable than the runtime string carried by policy.
    fn from_model(model: &str) -> Result<Self, String> {
        match crate::provider_profile::resolve_provider_id(model)? {
            "anthropic" => Ok(Self::Anthropic),
            "ollama" => Ok(Self::OpenAi(OpenAiRuntime::Ollama)),
            "native" => Ok(Self::OpenAi(OpenAiRuntime::Native)),
            "openai" => Ok(Self::OpenAi(OpenAiRuntime::OpenAi)),
            "xai" => Ok(Self::OpenAi(OpenAiRuntime::Xai)),
            "meta" => Ok(Self::OpenAi(OpenAiRuntime::Meta)),
            provider => Err(format!("unsupported provider {provider:?}")),
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
}

#[derive(Clone, Copy)]
enum CapabilityRequestSurface {
    Responses,
    OpenAiChat,
    AnthropicMessages,
}

#[derive(Clone)]
enum GatewayUsageOutcome {
    Success(StatusCode),
    Incomplete(StatusCode, String),
    TerminalFailure(StatusCode, String),
    Interrupted(StatusCode, String),
    AccountingOnly(StatusCode),
}

#[derive(Clone, Copy)]
enum ReceiptTerminalOutcome<'a> {
    Incomplete(&'a str),
    Failed,
    Cancelled,
    Interrupted(&'a str),
}

impl<'a> ReceiptTerminalOutcome<'a> {
    fn status(self) -> &'static str {
        match self {
            Self::Incomplete(_) => "incomplete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted(_) => "interrupted",
        }
    }

    fn reason(self) -> &'a str {
        match self {
            Self::Incomplete(reason) => reason,
            Self::Failed => "response_failed",
            Self::Cancelled => "response_cancelled",
            Self::Interrupted(reason) => reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct GatewayPipelineObservation {
    sampled: bool,
    reason: String,
    rate: f64,
    prepared_spec: String,
}

enum AliasReservationError {
    Conflict(String),
    Unavailable(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GatewayRecoveryRecord {
    Receipt {
        actor: String,
        operation_id: String,
        receipt_json: String,
        outcome: String,
    },
    LlmRow {
        values: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ResponseUsage {
    input_tokens: i32,
    output_tokens: i32,
    total_tokens: i32,
    /// Prompt tokens served from the provider's prompt cache at the discounted
    /// cache-read rate. Anthropic reports these as `cache_read_input_tokens`;
    /// OpenAI reports them under `usage.prompt_tokens_details.cached_tokens`.
    cache_read_input_tokens: i32,
    /// Prompt tokens written into the provider's prompt cache on this call
    /// (Anthropic `cache_creation_input_tokens`). Billed at the normal (or
    /// cache-write) input rate; tracked for reporting completeness.
    cache_creation_input_tokens: i32,
    /// Cache writes split by provider price class. Presence is tracked
    /// separately so an explicit zero is not confused with an unsupported or
    /// malformed field.
    cache_creation_5m_input_tokens: i32,
    cache_creation_1h_input_tokens: i32,
    cache_read_reported: bool,
    cache_read_included_in_input: bool,
    cache_creation_reported: bool,
    cache_creation_5m_reported: bool,
    cache_creation_1h_reported: bool,
    /// Provider-reported total, kept separate from the normalized total
    /// because provider definitions differ.
    provider_total_tokens: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResponseObservation {
    output_content: String,
    stop_reason: String,
}

/// Whether the tapped body has been identified as an SSE event stream. Event
/// boundaries must only be drained once the stream positively looks like SSE:
/// splitting a non-SSE body (e.g. pretty-printed JSON with a blank line) on
/// `\n\n` would discard the fragments and lose usage at flush.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
enum SseTapMode {
    #[default]
    Undetected,
    Sse,
    Raw,
}

#[derive(Debug, Default)]
struct SseUsageTap {
    pending: Vec<u8>,
    mode: SseTapMode,
    usage: Option<ResponseUsage>,
    observation: ResponseObservation,
    terminal: Option<ResponsesTerminal>,
    overflow_reason: Option<&'static str>,
}

#[derive(Debug, Default)]
struct ResponsesStreamValidator {
    pending: Vec<u8>,
    terminal_bytes: Vec<u8>,
    terminal_seen: bool,
    sse: Option<bool>,
}

#[derive(Debug)]
struct ResponsesStreamError {
    reason: String,
    validated: Vec<u8>,
}

impl ResponsesStreamValidator {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ResponsesStreamError> {
        if self.sse == Some(false) {
            self.pending.extend_from_slice(bytes);
            if self.pending.len() > DEFAULT_MAX_REQUEST_BYTES {
                return Err(ResponsesStreamError {
                    reason: "upstream JSON response exceeds the gateway limit".into(),
                    validated: Vec::new(),
                });
            }
            return Ok(Vec::new());
        }
        let mut validated = Vec::new();
        for window in bytes.chunks(SSE_VALIDATION_WINDOW_BYTES) {
            if self.sse == Some(false) {
                self.pending.extend_from_slice(window);
                if self.pending.len() > DEFAULT_MAX_REQUEST_BYTES {
                    return Err(ResponsesStreamError {
                        reason: "upstream JSON response exceeds the gateway limit".into(),
                        validated: Vec::new(),
                    });
                }
                continue;
            }
            self.pending.extend_from_slice(window);
            if self.sse.is_none()
                && let Some(sse) = body_prefix_is_sse(&self.pending)
            {
                self.sse = Some(sse);
                if !sse {
                    continue;
                }
            }
            let mut consumed = 0;
            let mut withheld_from = 0;
            while let Some((frame_end, separator_end)) =
                crate::harness::find_frame_boundary(&self.pending[consumed..])
            {
                if frame_end > MAX_SSE_FRAME_BYTES {
                    if !self.terminal_seen {
                        validated.extend_from_slice(&self.pending[withheld_from..consumed]);
                    }
                    return Err(ResponsesStreamError {
                        reason: "upstream SSE frame exceeds the gateway limit".into(),
                        validated,
                    });
                }
                let frame_start = consumed;
                let frame_end = frame_start + frame_end;
                let frame = &self.pending[frame_start..frame_end];
                let semantic_frame = frame.strip_prefix(b"\xef\xbb\xbf").unwrap_or(frame);
                let has_data = match validate_responses_sse_frame(semantic_frame) {
                    Ok(has_data) => has_data,
                    Err(reason) => {
                        if !self.terminal_seen {
                            validated.extend_from_slice(&self.pending[withheld_from..frame_start]);
                        }
                        return Err(ResponsesStreamError { reason, validated });
                    }
                };
                if self.terminal_seen && has_data {
                    return Err(ResponsesStreamError {
                        reason: "upstream emitted data after a terminal response event".into(),
                        validated,
                    });
                }
                let frame_boundary = frame_start + separator_end;
                if has_data {
                    match sse_event_terminal(semantic_frame) {
                        Some(ResponsesTerminal::Invalid) => {
                            if !self.terminal_seen {
                                validated
                                    .extend_from_slice(&self.pending[withheld_from..frame_start]);
                            }
                            return Err(ResponsesStreamError {
                                reason: "upstream emitted inconsistent terminal response metadata"
                                    .into(),
                                validated,
                            });
                        }
                        Some(_) if self.terminal_seen => {
                            return Err(ResponsesStreamError {
                                reason: "upstream emitted duplicate terminal response events"
                                    .into(),
                                validated,
                            });
                        }
                        Some(_) => {
                            validated.extend_from_slice(&self.pending[withheld_from..frame_start]);
                            self.terminal_bytes
                                .extend_from_slice(&self.pending[frame_start..frame_boundary]);
                            withheld_from = frame_boundary;
                            self.terminal_seen = true;
                        }
                        None => {}
                    }
                } else if self.terminal_seen {
                    withheld_from = frame_boundary;
                }
                consumed = frame_boundary;
            }
            if !self.terminal_seen {
                validated.extend_from_slice(&self.pending[..consumed]);
            }
            self.pending.drain(..consumed);
            if self.pending.len() > MAX_SSE_FRAME_BYTES {
                return Err(ResponsesStreamError {
                    reason: "upstream SSE frame exceeds the gateway limit".into(),
                    validated,
                });
            }
        }
        Ok(validated)
    }

    fn finish(&self) -> Result<Vec<u8>, String> {
        if self.sse == Some(false) {
            return match buffered_responses_terminal(&self.pending) {
                Some(ResponsesTerminal::Invalid) | None => {
                    Err("upstream Responses body is missing a valid terminal status".into())
                }
                Some(_) => Ok(self.pending.clone()),
            };
        }
        if self.pending.iter().all(u8::is_ascii_whitespace) {
            Ok(self.terminal_bytes.clone())
        } else {
            Err("upstream stream ended within an SSE frame".into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponsesTerminal {
    Completed,
    Incomplete(String),
    Failed,
    Cancelled,
    Interrupted,
    Invalid,
}

impl SseUsageTap {
    fn new() -> Self {
        Self::default()
    }

    fn sse() -> Self {
        Self {
            mode: SseTapMode::Sse,
            ..Self::default()
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.overflow_reason.is_some() {
            return;
        }
        if bytes.len() > DEFAULT_MAX_REQUEST_BYTES {
            self.mark_overflow("upstream streaming chunk exceeds the gateway limit");
            return;
        }
        for window in bytes.chunks(SSE_VALIDATION_WINDOW_BYTES) {
            self.pending.extend_from_slice(window);
            if self.mode == SseTapMode::Undetected
                && let Some(is_sse) = body_prefix_is_sse(&self.pending)
            {
                self.mode = if is_sse {
                    SseTapMode::Sse
                } else {
                    SseTapMode::Raw
                };
            }
            if self.mode == SseTapMode::Sse {
                while let Some((boundary, separator_len)) = find_sse_event_boundary(&self.pending) {
                    if boundary > MAX_SSE_FRAME_BYTES {
                        self.mark_overflow("upstream SSE frame exceeds the gateway limit");
                        return;
                    }
                    let event = self.pending.drain(..boundary).collect::<Vec<_>>();
                    self.pending.drain(..separator_len);
                    if self.terminal.is_some() && extract_sse_data(&event).is_some() {
                        self.terminal = Some(ResponsesTerminal::Invalid);
                        continue;
                    }
                    self.terminal = sse_event_terminal(&event).or_else(|| self.terminal.take());
                    if let Some(usage) = extract_sse_event_usage(&event) {
                        self.usage = Some(merge_usage(self.usage, usage));
                    }
                    if let Some(observation) = extract_sse_event_observation(&event) {
                        self.merge_observation(observation);
                    }
                }
                if self.pending.len() > MAX_SSE_FRAME_BYTES {
                    self.mark_overflow("upstream SSE frame exceeds the gateway limit");
                    return;
                }
            } else if self.pending.len() > DEFAULT_MAX_REQUEST_BYTES {
                self.mark_overflow("upstream JSON response exceeds the gateway limit");
                return;
            }
        }
    }

    fn overflow_reason(&self) -> Option<&'static str> {
        self.overflow_reason
    }

    fn mark_overflow(&mut self, reason: &'static str) {
        self.pending.clear();
        self.overflow_reason = Some(reason);
        self.terminal = Some(ResponsesTerminal::Invalid);
    }

    fn finish(self) -> (Option<ResponseUsage>, Option<ResponseObservation>) {
        let (usage, observation, _, _) = self.finish_with_terminal();
        (usage, observation)
    }

    fn finish_with_terminal(
        mut self,
    ) -> (
        Option<ResponseUsage>,
        Option<ResponseObservation>,
        Option<ResponsesTerminal>,
        SseTapMode,
    ) {
        let raw_terminal = (self.mode == SseTapMode::Raw)
            .then(|| buffered_responses_terminal(&self.pending))
            .flatten();
        self.flush_pending();
        if self.terminal.is_none() {
            self.terminal = raw_terminal;
        }
        let terminal = self.terminal.clone();
        let mode = self.mode;
        let observation = if self.observation.output_content.trim().is_empty() {
            None
        } else {
            self.observation.output_content =
                truncate_gateway_spec(&self.observation.output_content);
            Some(self.observation)
        };
        (self.usage, observation, terminal, mode)
    }

    #[cfg(test)]
    fn terminal(&self) -> Option<ResponsesTerminal> {
        self.terminal.clone()
    }

    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        if self.terminal.is_some() && extract_sse_data(&pending).is_some() {
            self.terminal = Some(ResponsesTerminal::Invalid);
            return;
        }
        self.terminal = sse_event_terminal(&pending).or_else(|| self.terminal.take());
        // Non-SSE passthrough bodies (no Content-Type header) arrive here as
        // one pending blob; fall back to whole-JSON extraction for those.
        if let Some(usage) = extract_sse_event_usage(&pending).or_else(|| {
            extract_response_usage(&pending)
                .or_else(|| extract_nested_response_usage(&pending))
                .or_else(|| extract_nested_message_usage(&pending))
        }) {
            self.usage = Some(merge_usage(self.usage, usage));
        }
        if let Some(observation) = extract_sse_event_observation(&pending)
            .or_else(|| extract_response_observation(&pending))
        {
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

/// An object's governed context prepared for injection, with the audit
/// metadata needed to reconcile the egress record with what was actually
/// forwarded.
struct InjectableObject {
    line: String,
    included_fields: usize,
    object_ref: String,
}

enum BoundedResponseError {
    Transfer(reqwest::Error),
    TooLarge,
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
