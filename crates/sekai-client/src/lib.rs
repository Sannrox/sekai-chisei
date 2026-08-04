//! Thin, versioned Rust client facade for the native Sekai Chisei core loop.
//!
//! The facade owns transport and request plumbing only. The control plane
//! remains authoritative for credentials, authorization, policy, budgets,
//! provider behavior, persistence, and operation receipts.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_stream::stream;
use async_trait::async_trait;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{Uri, uri::PathAndQuery};
use hyper_util::rt::TokioIo;
use prost::Message;
pub use sekai_proto as protocol;
pub use sekai_proto::chisei::{
    ExecutePlanRequest, ExecutePlanStreamEvent, ExecutionInput, ExecutionPlan,
    GetOperationReceiptRequest, GetOperationReceiptResponse, PlanExecutionRequest,
    PlanExecutionResponse, ReportOperationEventRequest, ReportOperationEventResponse,
};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Response, Status};
use tower::service_fn;
use uuid::Uuid;

/// Version of the typed client contract, independent of the wire protocol.
pub const SDK_CONTRACT_VERSION: &str = "sekai.sdk-core-loop/v1";

/// The protocol package consumed by this crate. The generated source lives in
/// `sekai-proto`; this crate intentionally does not carry a second snapshot.
pub const PROTOCOL_COMPATIBILITY: &str = "sekai-proto/1.x";

pub const AUTHORIZATION_METADATA: &str = "authorization";
pub const PRINCIPAL_METADATA: &str = "x-principal";
pub const NAMESPACE_METADATA: &str = "x-sekai-namespace";
pub const CAPABILITY_METADATA: &str = "x-sekai-capability";
pub const OPERATION_METADATA: &str = "x-sekai-operation-id";
pub const WORK_UNIT_METADATA: &str = "x-chisei-work-unit";
pub const CATALOG_VERSION_METADATA: &str = "x-sekai-catalog-version";
pub const REQUEST_ID_METADATA: &str = "x-chisei-request-id";

/// Metadata that the SDK owns and callers cannot replace through custom
/// metadata or the raw escape hatch.
pub const RESERVED_METADATA_KEYS: &[&str] = &[
    AUTHORIZATION_METADATA,
    PRINCIPAL_METADATA,
    NAMESPACE_METADATA,
    CAPABILITY_METADATA,
    OPERATION_METADATA,
    WORK_UNIT_METADATA,
    CATALOG_VERSION_METADATA,
    REQUEST_ID_METADATA,
];

const PLAN_CAPABILITY: &str = "chisei.plan.execute";
const EVENT_CAPABILITY: &str = "chisei.operation.report";
const RECEIPT_CAPABILITY: &str = "chisei.receipt.read";
const MAX_METADATA_VALUE_LENGTH: usize = 4096;
const MAX_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_MAX_STREAM_EVENTS: usize = 1024;
const DEFAULT_MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAM_EVENTS: usize = 100_000;
const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;

/// Service identity retained in typed errors without exposing wire details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceName {
    Sekai,
    Chisei,
    Raw,
}

impl fmt::Display for ServiceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sekai => "sekai",
            Self::Chisei => "chisei",
            Self::Raw => "raw",
        })
    }
}

/// Bounded error taxonomy exposed by the SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SdkErrorCode {
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    Unavailable,
    Unimplemented,
    Internal,
    Unauthenticated,
}

impl SdkErrorCode {
    fn from_status(code: tonic::Code) -> Self {
        match code {
            tonic::Code::Cancelled => Self::Cancelled,
            tonic::Code::Unknown => Self::Unknown,
            tonic::Code::InvalidArgument => Self::InvalidArgument,
            tonic::Code::DeadlineExceeded => Self::DeadlineExceeded,
            tonic::Code::NotFound => Self::NotFound,
            tonic::Code::AlreadyExists => Self::AlreadyExists,
            tonic::Code::PermissionDenied => Self::PermissionDenied,
            tonic::Code::ResourceExhausted => Self::ResourceExhausted,
            tonic::Code::FailedPrecondition => Self::FailedPrecondition,
            tonic::Code::Aborted => Self::Aborted,
            tonic::Code::Unavailable => Self::Unavailable,
            tonic::Code::Unimplemented => Self::Unimplemented,
            tonic::Code::Internal => Self::Internal,
            tonic::Code::Unauthenticated => Self::Unauthenticated,
            tonic::Code::DataLoss | tonic::Code::Ok | tonic::Code::OutOfRange => Self::Unknown,
        }
    }

    fn default_message(self) -> &'static str {
        match self {
            Self::Cancelled => "RPC cancelled",
            Self::Unknown => "Sekai/Chisei returned an unknown RPC error",
            Self::InvalidArgument => "RPC request was invalid",
            Self::DeadlineExceeded => "RPC deadline exceeded",
            Self::NotFound => "RPC resource was not found",
            Self::AlreadyExists => "RPC resource already exists",
            Self::PermissionDenied => "RPC permission denied",
            Self::ResourceExhausted => "RPC resource or budget exhausted",
            Self::FailedPrecondition => "RPC policy or state precondition failed",
            Self::Aborted => "RPC was aborted",
            Self::Unavailable => "Sekai/Chisei is unavailable",
            Self::Unimplemented => "RPC is not implemented",
            Self::Internal => "Sekai/Chisei returned an internal error",
            Self::Unauthenticated => "Sekai/Chisei authentication failed",
        }
    }

    fn retryable_by_default(self) -> bool {
        matches!(
            self,
            Self::Aborted | Self::DeadlineExceeded | Self::ResourceExhausted | Self::Unavailable
        )
    }
}

/// A safe, bounded error. Server status text is deliberately not retained:
/// it may contain provider or credential material and the status code already
/// preserves the authorization/policy distinction callers need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkError {
    pub code: SdkErrorCode,
    pub service: Option<ServiceName>,
    pub method: Option<String>,
    pub operation_id: Option<String>,
    pub request_id: Option<String>,
    pub retryable: bool,
}

impl SdkError {
    pub fn invalid_argument() -> Self {
        Self::new(SdkErrorCode::InvalidArgument)
    }

    pub fn new(code: SdkErrorCode) -> Self {
        Self {
            code,
            service: None,
            method: None,
            operation_id: None,
            request_id: None,
            retryable: code.retryable_by_default(),
        }
    }

    fn for_call(
        code: SdkErrorCode,
        service: ServiceName,
        method: impl Into<String>,
        options: &CallOptions,
        request_id: &str,
    ) -> Self {
        Self {
            code,
            service: Some(service),
            method: Some(method.into()),
            operation_id: options.context.operation_id.clone(),
            request_id: (!request_id.is_empty()).then(|| request_id.to_string()),
            retryable: code.retryable_by_default(),
        }
    }

    fn from_status(
        status: Status,
        service: ServiceName,
        method: &str,
        options: &CallOptions,
        request_id: &str,
    ) -> Self {
        Self::for_call(
            SdkErrorCode::from_status(status.code()),
            service,
            method,
            options,
            request_id,
        )
    }

    pub fn is_authorization(&self) -> bool {
        matches!(
            self.code,
            SdkErrorCode::Unauthenticated | SdkErrorCode::PermissionDenied
        )
    }

    pub fn is_policy_or_budget(&self) -> bool {
        matches!(
            self.code,
            SdkErrorCode::FailedPrecondition | SdkErrorCode::ResourceExhausted
        )
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.code.default_message())?;
        if let (Some(service), Some(method)) = (self.service, self.method.as_deref()) {
            write!(formatter, " ({service}/{method})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SdkError {}

/// A bearer credential held only in memory. Its debug representation is
/// intentionally redacted.
#[derive(Clone)]
pub struct Credential(String);

impl Credential {
    pub fn new(token: impl Into<String>) -> Result<Self, SdkError> {
        let token = token.into();
        validate_text("credential", &token, 4096)?;
        Ok(Self(token))
    }

    fn authorization_value(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential(REDACTED)")
    }
}

/// Retry policy for explicitly retryable unary calls.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub retryable_codes: Vec<SdkErrorCode>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            retryable_codes: vec![
                SdkErrorCode::Aborted,
                SdkErrorCode::DeadlineExceeded,
                SdkErrorCode::ResourceExhausted,
                SdkErrorCode::Unavailable,
            ],
        }
    }
}

impl RetryPolicy {
    fn validate(&self) -> Result<(), SdkError> {
        if !(1..=8).contains(&self.max_attempts) {
            return Err(SdkError::invalid_argument());
        }
        if self.initial_backoff > self.max_backoff {
            return Err(SdkError::invalid_argument());
        }
        Ok(())
    }
}

/// Connection and identity configuration. `credential` is never serialized
/// or logged by this crate.
#[derive(Clone)]
pub struct ClientConfig {
    pub target: String,
    pub principal: String,
    pub credential: Option<Credential>,
    pub namespace: Option<String>,
    pub catalog_version: Option<String>,
    pub default_timeout: Duration,
    pub retry: RetryPolicy,
    pub allow_insecure_remote: bool,
    pub tls_ca_certificate: Option<Vec<u8>>,
    pub max_stream_events: usize,
    pub max_stream_bytes: usize,
}

impl ClientConfig {
    pub fn new(target: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            principal: principal.into(),
            credential: None,
            namespace: None,
            catalog_version: None,
            default_timeout: Duration::from_secs(30),
            retry: RetryPolicy::default(),
            allow_insecure_remote: false,
            tls_ca_certificate: None,
            max_stream_events: DEFAULT_MAX_STREAM_EVENTS,
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
        }
    }

    /// Configuration helper for an injected transport. It avoids making a
    /// fake test invent an endpoint that will never be dialed.
    pub fn for_injected(principal: impl Into<String>) -> Self {
        Self::new("injected://transport", principal)
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Result<Self, SdkError> {
        self.credential = Some(Credential::new(token)?);
        Ok(self)
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn with_catalog_version(mut self, version: impl Into<String>) -> Self {
        self.catalog_version = Some(version.into());
        self
    }

    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn allow_insecure_remote(mut self, allow: bool) -> Self {
        self.allow_insecure_remote = allow;
        self
    }

    pub fn with_tls_ca_certificate(mut self, certificate_pem: Vec<u8>) -> Self {
        self.tls_ca_certificate = Some(certificate_pem);
        self
    }

    pub fn with_stream_limits(mut self, max_events: usize, max_bytes: usize) -> Self {
        self.max_stream_events = max_events;
        self.max_stream_bytes = max_bytes;
        self
    }

    fn validate(&self) -> Result<(), SdkError> {
        validate_text("principal", &self.principal, 200)?;
        validate_optional_text("namespace", self.namespace.as_deref(), 200)?;
        validate_optional_text("catalog_version", self.catalog_version.as_deref(), 200)?;
        if self.target.trim().is_empty() {
            return Err(SdkError::invalid_argument());
        }
        if self.default_timeout.is_zero() || self.default_timeout > MAX_TIMEOUT {
            return Err(SdkError::invalid_argument());
        }
        if self.max_stream_events == 0
            || self.max_stream_events > MAX_STREAM_EVENTS
            || self.max_stream_bytes == 0
            || self.max_stream_bytes > MAX_STREAM_BYTES
        {
            return Err(SdkError::invalid_argument());
        }
        self.retry.validate()
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("target", &self.target)
            .field("principal", &self.principal)
            .field("credential", &self.credential)
            .field("namespace", &self.namespace)
            .field("catalog_version", &self.catalog_version)
            .field("default_timeout", &self.default_timeout)
            .field("retry", &self.retry)
            .field("allow_insecure_remote", &self.allow_insecure_remote)
            .field(
                "tls_ca_certificate",
                &self.tls_ca_certificate.as_ref().map(|_| "configured"),
            )
            .field("max_stream_events", &self.max_stream_events)
            .field("max_stream_bytes", &self.max_stream_bytes)
            .finish()
    }
}

/// Per-call identity and extension metadata. Reserved authority fields are
/// filled by the client and rejected if present in `metadata`.
#[derive(Clone, Debug, Default)]
pub struct CallContext {
    pub namespace: Option<String>,
    pub capability: Option<String>,
    pub operation_id: Option<String>,
    pub work_unit_id: Option<String>,
    pub catalog_version: Option<String>,
    pub metadata: Vec<(String, String)>,
}

impl CallContext {
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }

    pub fn with_operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    pub fn with_work_unit_id(mut self, work_unit_id: impl Into<String>) -> Self {
        self.work_unit_id = Some(work_unit_id.into());
        self
    }

    pub fn with_catalog_version(mut self, version: impl Into<String>) -> Self {
        self.catalog_version = Some(version.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}

/// Options shared by typed and raw calls.
#[derive(Clone, Debug, Default)]
pub struct CallOptions {
    pub context: CallContext,
    pub timeout: Option<Duration>,
    /// `None` uses the method default. Typed receipt reads default to safe
    /// unary retries; `Some(false)` is an explicit opt-out.
    pub retryable: Option<bool>,
    pub request_id: Option<String>,
    pub cancellation: Option<CancellationToken>,
}

impl CallOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_context(mut self, context: CallContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.context.namespace = Some(namespace.into());
        self
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.context.capability = Some(capability.into());
        self
    }

    pub fn with_operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.context.operation_id = Some(operation_id.into());
        self
    }

    pub fn with_work_unit_id(mut self, work_unit_id: impl Into<String>) -> Self {
        self.context.work_unit_id = Some(work_unit_id.into());
        self
    }

    pub fn with_catalog_version(mut self, version: impl Into<String>) -> Self {
        self.context.catalog_version = Some(version.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = Some(retryable);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

/// Transport seam for deterministic tests and alternate native hosts.
#[async_trait]
pub trait CoreLoopTransport: Send + Sync + 'static {
    type Stream: Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send + 'static;

    async fn plan_execution(
        &self,
        request: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status>;

    async fn execute_plan_stream(
        &self,
        request: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::Stream>, Status>;

    async fn report_operation_event(
        &self,
        request: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status>;

    async fn get_operation_receipt(
        &self,
        request: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status>;
}

/// A cancellable, error-mapped stream returned by typed and raw streaming
/// calls. Cancellation is cooperative at the transport boundary and is also
/// exposed as an explicit handle for hosts that stop consuming the stream.
pub struct CancellableStream<T> {
    inner: Pin<Box<dyn Stream<Item = Result<T, SdkError>> + Send>>,
    cancellation: CancellationToken,
}

impl<T> CancellableStream<T> {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl<T> Stream for CancellableStream<T> {
    type Item = Result<T, SdkError>;

    fn poll_next(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

/// Result of the typed core-loop convenience method.
pub struct CoreLoopResult {
    pub operation_id: String,
    pub request_id: String,
    pub plan: ExecutionPlan,
    pub events: Vec<ExecutePlanStreamEvent>,
    pub receipt: GetOperationReceiptResponse,
}

/// Native tonic transport over the canonical generated protocol crate.
#[derive(Clone)]
pub struct GrpcTransport {
    channel: Channel,
}

impl GrpcTransport {
    async fn connect(config: &ClientConfig) -> Result<Self, SdkError> {
        config.validate()?;
        if config.target.starts_with("unix://") {
            let socket = config.target.trim_start_matches("unix://");
            if socket.trim().is_empty() {
                return Err(SdkError::invalid_argument());
            }
            let socket_path = PathBuf::from(socket);
            let endpoint =
                Endpoint::from_static("http://[::]:50051").connect_timeout(config.default_timeout);
            let channel = endpoint
                .connect_with_connector(service_fn(move |_: Uri| {
                    let socket_path = socket_path.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(
                            UnixStream::connect(socket_path).await?,
                        ))
                    }
                }))
                .await
                .map_err(|_| SdkError::new(SdkErrorCode::Unavailable))?;
            return Ok(Self { channel });
        }

        let uri = Uri::from_str(&config.target).map_err(|_| SdkError::invalid_argument())?;
        let scheme = uri.scheme_str().unwrap_or_default();
        if scheme != "http" && scheme != "https" {
            return Err(SdkError::invalid_argument());
        }
        if scheme == "http"
            && !config.allow_insecure_remote
            && !is_loopback_host(uri.host().unwrap_or_default())
        {
            return Err(SdkError::invalid_argument());
        }

        let mut endpoint = Endpoint::from_shared(config.target.clone())
            .map_err(|_| SdkError::invalid_argument())?
            .connect_timeout(config.default_timeout);
        if scheme == "https" {
            let mut tls = ClientTlsConfig::new().with_native_roots();
            if let Some(certificate) = config.tls_ca_certificate.as_ref() {
                tls = tls.ca_certificate(Certificate::from_pem(certificate.clone()));
            }
            endpoint = endpoint
                .tls_config(tls)
                .map_err(|_| SdkError::invalid_argument())?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|_| SdkError::new(SdkErrorCode::Unavailable))?;
        Ok(Self { channel })
    }

    async fn raw_unary<Req, Resp>(
        &self,
        request: Request<Req>,
        path: PathAndQuery,
    ) -> Result<Response<Resp>, Status>
    where
        Req: Message + Default + 'static,
        Resp: Message + Default + 'static,
    {
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready()
            .await
            .map_err(|_| Status::unavailable("transport unavailable"))?;
        grpc.unary(request, path, tonic_prost::ProstCodec::default())
            .await
    }

    async fn raw_server_streaming<Req, Resp>(
        &self,
        request: Request<Req>,
        path: PathAndQuery,
    ) -> Result<Response<tonic::codec::Streaming<Resp>>, Status>
    where
        Req: Message + Default + 'static,
        Resp: Message + Default + 'static,
    {
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready()
            .await
            .map_err(|_| Status::unavailable("transport unavailable"))?;
        grpc.server_streaming(request, path, tonic_prost::ProstCodec::default())
            .await
    }
}

#[async_trait]
impl CoreLoopTransport for GrpcTransport {
    type Stream = Pin<Box<dyn Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

    async fn plan_execution(
        &self,
        request: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let mut client = sekai_proto::chisei::chisei_service_client::ChiseiServiceClient::new(
            self.channel.clone(),
        );
        client.plan_execution(request).await
    }

    async fn execute_plan_stream(
        &self,
        request: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::Stream>, Status> {
        let mut client = sekai_proto::chisei::chisei_service_client::ChiseiServiceClient::new(
            self.channel.clone(),
        );
        let response = client.execute_plan_stream(request).await?;
        Ok(Response::new(Box::pin(response.into_inner())))
    }

    async fn report_operation_event(
        &self,
        request: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        let mut client = sekai_proto::chisei::chisei_service_client::ChiseiServiceClient::new(
            self.channel.clone(),
        );
        client.report_operation_event(request).await
    }

    async fn get_operation_receipt(
        &self,
        request: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        let mut client = sekai_proto::chisei::chisei_service_client::ChiseiServiceClient::new(
            self.channel.clone(),
        );
        client.get_operation_receipt(request).await
    }
}

/// Typed client over an injected or native transport.
pub struct CoreLoopClient<T> {
    config: Arc<ClientConfig>,
    transport: T,
}

impl<T> CoreLoopClient<T>
where
    T: CoreLoopTransport,
{
    pub fn new(config: ClientConfig, transport: T) -> Result<Self, SdkError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            transport,
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Construct the final request metadata for inspection by an injected
    /// transport. Callers cannot use this to replace reserved authority keys.
    pub fn metadata(
        &self,
        options: &CallOptions,
        request_id: &str,
    ) -> Result<MetadataMap, SdkError> {
        self.build_metadata(options, request_id)
    }

    pub async fn plan_execution(
        &self,
        mut input: ExecutionInput,
        options: CallOptions,
    ) -> Result<ExecutionPlan, SdkError> {
        let namespace = required_text("input.namespace", &input.namespace, 200)?;
        let operation_id = input
            .logical_operation_id
            .trim()
            .is_empty()
            .then(|| options.context.operation_id.clone())
            .flatten()
            .or_else(|| {
                (!input.logical_operation_id.trim().is_empty())
                    .then(|| input.logical_operation_id.clone())
            })
            .unwrap_or_else(new_id);
        let mut options = self.call_options(
            options,
            Some(&namespace),
            Some(PLAN_CAPABILITY),
            Some(&operation_id),
        )?;
        let input_request_id =
            (!input.request_id.trim().is_empty()).then(|| input.request_id.clone());
        if let (Some(option_request_id), Some(input_request_id)) =
            (options.request_id.as_deref(), input_request_id.as_deref())
        {
            if option_request_id != input_request_id {
                return Err(SdkError::invalid_argument());
            }
        }
        let request_id = options
            .request_id
            .clone()
            .or(input_request_id)
            .unwrap_or_else(new_id);
        options.request_id = Some(request_id.clone());
        input.request_id = request_id;
        if input.logical_operation_id.trim().is_empty() {
            input.logical_operation_id = operation_id;
        }
        let response = self
            .unary_call(
                ServiceName::Chisei,
                "PlanExecution",
                PlanExecutionRequest {
                    input: Some(input),
                    gunshi_allocation: None,
                },
                options,
                |transport, request| Box::pin(transport.plan_execution(request)),
            )
            .await?;
        response
            .plan
            .ok_or_else(|| SdkError::new(SdkErrorCode::Internal))
    }

    pub async fn execute_plan_stream(
        &self,
        plan: ExecutionPlan,
        options: CallOptions,
    ) -> Result<CancellableStream<ExecutePlanStreamEvent>, SdkError> {
        let namespace = plan
            .input
            .as_ref()
            .map(|input| input.namespace.as_str())
            .filter(|value| !value.trim().is_empty());
        let plan_operation_id = plan.input.as_ref().and_then(|input| {
            (!input.logical_operation_id.trim().is_empty())
                .then(|| input.logical_operation_id.clone())
        });
        if let (Some(option_operation_id), Some(plan_operation_id)) = (
            options.context.operation_id.as_deref(),
            plan_operation_id.as_deref(),
        ) {
            if option_operation_id != plan_operation_id {
                return Err(SdkError::invalid_argument());
            }
        }
        let operation_id = options
            .context
            .operation_id
            .clone()
            .or_else(|| plan_operation_id.clone())
            .or_else(|| (!plan.plan_id.trim().is_empty()).then(|| plan.plan_id.clone()));
        let mut options = self.call_options(
            options,
            namespace,
            Some(PLAN_CAPABILITY),
            operation_id.as_deref(),
        )?;
        let plan_request_id = plan.input.as_ref().and_then(|input| {
            (!input.request_id.trim().is_empty()).then(|| input.request_id.clone())
        });
        if let (Some(option_request_id), Some(plan_request_id)) =
            (options.request_id.as_deref(), plan_request_id.as_deref())
        {
            if option_request_id != plan_request_id {
                return Err(SdkError::invalid_argument());
            }
        }
        let request_id = options
            .request_id
            .clone()
            .or(plan_request_id)
            .unwrap_or_else(new_id);
        options.request_id = Some(request_id.clone());
        let timeout = self.call_timeout(&options)?;
        let deadline = Instant::now() + timeout;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let cancellation = options.cancellation.clone().unwrap_or_default();
        let metadata = self.build_metadata(&options, &request_id)?;
        let mut request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        *request.metadata_mut() = metadata;
        request.set_timeout(remaining);
        let identity = CallIdentity::new(
            ServiceName::Chisei,
            "ExecutePlanStream",
            &options,
            &request_id,
        );
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(identity.error(SdkErrorCode::Cancelled));
            }
            _ = tokio::time::sleep(remaining) => {
                return Err(identity.error(SdkErrorCode::DeadlineExceeded));
            }
            response = self.transport.execute_plan_stream(request) => response
                .map_err(|status| identity.status_error(status)),
        }?;
        Ok(map_cancellable_stream(
            response.into_inner(),
            cancellation,
            identity,
            deadline,
        ))
    }

    pub async fn report_operation_event(
        &self,
        event: ReportOperationEventRequest,
        options: CallOptions,
    ) -> Result<ReportOperationEventResponse, SdkError> {
        let operation_id = required_text("event.operation_id", &event.operation_id, 200)?;
        required_text("event.event_id", &event.event_id, 200)?;
        let options =
            self.call_options(options, None, Some(EVENT_CAPABILITY), Some(&operation_id))?;
        let response = self
            .unary_call(
                ServiceName::Chisei,
                "ReportOperationEvent",
                event,
                options,
                |transport, request| Box::pin(transport.report_operation_event(request)),
            )
            .await?;
        Ok(response)
    }

    pub async fn get_operation_receipt(
        &self,
        request: GetOperationReceiptRequest,
        options: CallOptions,
    ) -> Result<GetOperationReceiptResponse, SdkError> {
        let has_operation = !request.operation_id.trim().is_empty();
        let has_request = !request.request_id.trim().is_empty();
        if has_operation == has_request {
            return Err(SdkError::invalid_argument());
        }
        if has_operation {
            required_text("request.operation_id", &request.operation_id, 200)?;
        }
        if has_request {
            required_text("request.request_id", &request.request_id, 200)?;
        }
        validate_optional_text("caller_scope", Some(&request.caller_scope), 200)?;
        let mut options = self.call_options(options, None, Some(RECEIPT_CAPABILITY), None)?;
        if has_request {
            if let Some(existing) = options.request_id.as_deref() {
                if existing != request.request_id {
                    return Err(SdkError::invalid_argument());
                }
            }
            options.request_id = Some(request.request_id.clone());
        }
        if options.retryable.is_none() {
            options.retryable = Some(true);
        }
        let response = self
            .unary_call(
                ServiceName::Chisei,
                "GetOperationReceipt",
                request,
                options,
                |transport, request| Box::pin(transport.get_operation_receipt(request)),
            )
            .await?;
        Ok(response)
    }

    /// Execute the canonical plan → stream → receipt path. Operation events
    /// are deliberately reported separately because the host owns event
    /// interpretation and may need to attach bounded evidence references.
    pub async fn run_core_loop(
        &self,
        mut input: ExecutionInput,
        options: CallOptions,
    ) -> Result<CoreLoopResult, SdkError> {
        let namespace = required_text("input.namespace", &input.namespace, 200)?;
        if let Some(option_namespace) = options.context.namespace.as_deref() {
            if option_namespace != namespace {
                return Err(SdkError::invalid_argument());
            }
        }
        let input_operation_id = (!input.logical_operation_id.trim().is_empty())
            .then(|| input.logical_operation_id.clone());
        if let (Some(option_operation_id), Some(input_operation_id)) = (
            options.context.operation_id.as_deref(),
            input_operation_id.as_deref(),
        ) {
            if option_operation_id != input_operation_id {
                return Err(SdkError::invalid_argument());
            }
        }
        let operation_id = options
            .context
            .operation_id
            .clone()
            .or(input_operation_id)
            .unwrap_or_else(new_id);
        let input_request_id =
            (!input.request_id.trim().is_empty()).then(|| input.request_id.clone());
        if let (Some(option_request_id), Some(input_request_id)) =
            (options.request_id.as_deref(), input_request_id.as_deref())
        {
            if option_request_id != input_request_id {
                return Err(SdkError::invalid_argument());
            }
        }
        let request_id = options
            .request_id
            .clone()
            .or(input_request_id)
            .unwrap_or_else(new_id);
        input.logical_operation_id = operation_id.clone();
        input.request_id = request_id.clone();
        let base = options
            .with_namespace(namespace)
            .with_operation_id(operation_id.clone())
            .with_request_id(request_id.clone());
        let plan = self.plan_execution(input, base.clone()).await?;
        let mut events = Vec::new();
        if plan.executable {
            let mut stream = self.execute_plan_stream(plan.clone(), base.clone()).await?;
            let request_id = base.request_id.clone().unwrap_or_else(new_id);
            let identity =
                CallIdentity::new(ServiceName::Chisei, "ExecutePlanStream", &base, &request_id);
            let mut event_bytes = 0usize;
            while let Some(event) = stream.next().await {
                let event = event?;
                let encoded_len = event.encoded_len();
                if events.len() >= self.config.max_stream_events
                    || event_bytes.saturating_add(encoded_len) > self.config.max_stream_bytes
                {
                    return Err(identity.error(SdkErrorCode::ResourceExhausted));
                }
                event_bytes = event_bytes.saturating_add(encoded_len);
                events.push(event);
            }
        }
        let receipt = self
            .get_operation_receipt(
                GetOperationReceiptRequest {
                    operation_id: plan.plan_id.clone(),
                    request_id: String::new(),
                    caller_scope: String::new(),
                    attempt: 0,
                },
                base,
            )
            .await?;
        Ok(CoreLoopResult {
            operation_id,
            request_id,
            plan,
            events,
            receipt,
        })
    }

    fn call_options(
        &self,
        mut options: CallOptions,
        namespace: Option<&str>,
        capability: Option<&str>,
        operation_id: Option<&str>,
    ) -> Result<CallOptions, SdkError> {
        if let Some(namespace) = namespace {
            required_text("namespace", namespace, 200)?;
            if let Some(existing) = options.context.namespace.as_deref() {
                if existing != namespace {
                    return Err(SdkError::invalid_argument());
                }
            }
            if let Some(configured) = self.config.namespace.as_deref() {
                if configured != namespace {
                    return Err(SdkError::invalid_argument());
                }
            }
            options.context.namespace = Some(namespace.to_string());
        }
        if let Some(capability) = capability {
            if let Some(existing) = options.context.capability.as_deref() {
                if existing != capability {
                    return Err(SdkError::invalid_argument());
                }
            }
            options.context.capability = Some(capability.to_string());
        }
        if let Some(operation_id) = operation_id {
            required_text("operation_id", operation_id, 200)?;
            if let Some(existing) = options.context.operation_id.as_deref() {
                if existing != operation_id {
                    return Err(SdkError::invalid_argument());
                }
            }
            options.context.operation_id = Some(operation_id.to_string());
            if options.context.work_unit_id.is_none() {
                options.context.work_unit_id = Some(operation_id.to_string());
            }
        }
        Ok(options)
    }

    fn call_timeout(&self, options: &CallOptions) -> Result<Duration, SdkError> {
        let timeout = options.timeout.unwrap_or(self.config.default_timeout);
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(SdkError::invalid_argument());
        }
        Ok(timeout)
    }

    fn build_metadata(
        &self,
        options: &CallOptions,
        request_id: &str,
    ) -> Result<MetadataMap, SdkError> {
        let principal = required_text("principal", &self.config.principal, 200)?;
        if let (Some(configured), Some(requested)) = (
            self.config.namespace.as_deref(),
            options.context.namespace.as_deref(),
        ) {
            if configured != requested {
                return Err(SdkError::invalid_argument());
            }
        }
        let mut metadata = MetadataMap::new();
        insert_metadata(&mut metadata, PRINCIPAL_METADATA, &principal)?;
        if let Some(credential) = self.config.credential.as_ref() {
            insert_metadata(
                &mut metadata,
                AUTHORIZATION_METADATA,
                &credential.authorization_value(),
            )?;
        }
        let namespace = options
            .context
            .namespace
            .as_deref()
            .or(self.config.namespace.as_deref());
        if let Some(namespace) = namespace {
            insert_metadata(&mut metadata, NAMESPACE_METADATA, namespace)?;
        }
        if let Some(capability) = options.context.capability.as_deref() {
            insert_metadata(&mut metadata, CAPABILITY_METADATA, capability)?;
        }
        if let Some(operation_id) = options.context.operation_id.as_deref() {
            insert_metadata(&mut metadata, OPERATION_METADATA, operation_id)?;
            insert_metadata(
                &mut metadata,
                WORK_UNIT_METADATA,
                options
                    .context
                    .work_unit_id
                    .as_deref()
                    .unwrap_or(operation_id),
            )?;
        }
        let catalog_version = options
            .context
            .catalog_version
            .as_deref()
            .or(self.config.catalog_version.as_deref());
        if let Some(catalog_version) = catalog_version {
            insert_metadata(&mut metadata, CATALOG_VERSION_METADATA, catalog_version)?;
        }
        if !request_id.trim().is_empty() {
            insert_metadata(&mut metadata, REQUEST_ID_METADATA, request_id)?;
        }
        for (key, value) in &options.context.metadata {
            let normalized = key.to_ascii_lowercase();
            if RESERVED_METADATA_KEYS.contains(&normalized.as_str()) {
                return Err(SdkError::invalid_argument());
            }
            if normalized.ends_with("-bin")
                || normalized.is_empty()
                || normalized.len() > 256
                || !normalized
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(SdkError::invalid_argument());
            }
            validate_text("metadata value", value, MAX_METADATA_VALUE_LENGTH)?;
            insert_metadata(&mut metadata, &normalized, value)?;
        }
        Ok(metadata)
    }

    async fn unary_call<Req, Resp, F>(
        &self,
        service: ServiceName,
        method: &str,
        body: Req,
        options: CallOptions,
        call: F,
    ) -> Result<Resp, SdkError>
    where
        Req: Clone + Send + 'static,
        Resp: Send + 'static,
        F: for<'a> Fn(
                &'a T,
                Request<Req>,
            )
                -> Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send + 'a>>
            + Send
            + Sync,
    {
        let request_id = options.request_id.clone().unwrap_or_else(new_id);
        let timeout = self.call_timeout(&options)?;
        let deadline = Instant::now() + timeout;
        let cancellation = options.cancellation.clone().unwrap_or_default();
        let attempts = if options.retryable.unwrap_or(false) {
            self.config.retry.max_attempts
        } else {
            1
        };
        let identity = CallIdentity::new(service, method, &options, &request_id);

        for attempt in 0..attempts {
            if cancellation.is_cancelled() {
                return Err(identity.error(SdkErrorCode::Cancelled));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(identity.error(SdkErrorCode::DeadlineExceeded));
            }
            let mut request = Request::new(body.clone());
            *request.metadata_mut() = self.build_metadata(&options, &request_id)?;
            request.set_timeout(remaining);
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(identity.error(SdkErrorCode::Cancelled)),
                _ = tokio::time::sleep(remaining) => Err(identity.error(SdkErrorCode::DeadlineExceeded)),
                response = call(&self.transport, request) => response
                    .map(|response| response.into_inner())
                    .map_err(|status| identity.status_error(status)),
            };
            match result {
                Ok(response) => return Ok(response),
                Err(error)
                    if attempt + 1 < attempts
                        && error.retryable
                        && self.config.retry.retryable_codes.contains(&error.code) =>
                {
                    let exponent = u32::from(attempt).min(6);
                    let backoff = self
                        .config
                        .retry
                        .initial_backoff
                        .checked_mul(1u32 << exponent)
                        .unwrap_or(self.config.retry.max_backoff)
                        .min(self.config.retry.max_backoff);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(identity.error(SdkErrorCode::DeadlineExceeded));
                    }
                    let wait = backoff.min(remaining);
                    tokio::select! {
                        _ = cancellation.cancelled() => return Err(identity.error(SdkErrorCode::Cancelled)),
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(identity.error(SdkErrorCode::Unknown))
    }
}

impl CoreLoopClient<GrpcTransport> {
    pub async fn connect(config: ClientConfig) -> Result<Self, SdkError> {
        let transport = GrpcTransport::connect(&config).await?;
        Self::new(config, transport)
    }

    pub fn raw(&self) -> RawGrpcClient<'_> {
        RawGrpcClient { client: self }
    }
}

/// Raw tonic escape hatch for generated messages on surfaces without a typed
/// helper. Metadata still comes from `CoreLoopClient`, so authority-bearing
/// keys cannot be replaced by raw callers.
pub struct RawGrpcClient<'a> {
    client: &'a CoreLoopClient<GrpcTransport>,
}

impl<'a> RawGrpcClient<'a> {
    pub async fn unary<Req, Resp>(
        &self,
        path: &str,
        request: Req,
        options: CallOptions,
    ) -> Result<Resp, SdkError>
    where
        Req: Message + Default + Clone + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        let path = raw_path(path)?;
        self.client
            .unary_call(
                ServiceName::Raw,
                path.as_str(),
                request,
                options,
                |transport, request| {
                    let path = path.clone();
                    Box::pin(transport.raw_unary(request, path))
                },
            )
            .await
    }

    pub async fn server_streaming<Req, Resp>(
        &self,
        path: &str,
        request: Req,
        options: CallOptions,
    ) -> Result<CancellableStream<Resp>, SdkError>
    where
        Req: Message + Default + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        let path = raw_path(path)?;
        let request_id = options.request_id.clone().unwrap_or_else(new_id);
        let timeout = self.client.call_timeout(&options)?;
        let deadline = Instant::now() + timeout;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let cancellation = options.cancellation.clone().unwrap_or_default();
        let mut request = Request::new(request);
        *request.metadata_mut() = self.client.build_metadata(&options, &request_id)?;
        request.set_timeout(remaining);
        let identity = CallIdentity::new(ServiceName::Raw, path.as_str(), &options, &request_id);
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(identity.error(SdkErrorCode::Cancelled)),
            _ = tokio::time::sleep(remaining) => return Err(identity.error(SdkErrorCode::DeadlineExceeded)),
            response = self.client.transport.raw_server_streaming(request, path) => response
                .map_err(|status| identity.status_error(status)),
        }?;
        Ok(map_cancellable_stream(
            response.into_inner(),
            cancellation,
            identity,
            deadline,
        ))
    }
}

#[derive(Clone)]
struct CallIdentity {
    service: ServiceName,
    method: String,
    options: CallOptions,
    request_id: String,
}

impl CallIdentity {
    fn new(
        service: ServiceName,
        method: impl Into<String>,
        options: &CallOptions,
        request_id: &str,
    ) -> Self {
        Self {
            service,
            method: method.into(),
            options: options.clone(),
            request_id: request_id.to_string(),
        }
    }

    fn error(&self, code: SdkErrorCode) -> SdkError {
        SdkError::for_call(
            code,
            self.service,
            &self.method,
            &self.options,
            &self.request_id,
        )
    }

    fn status_error(&self, status: Status) -> SdkError {
        SdkError::from_status(
            status,
            self.service,
            &self.method,
            &self.options,
            &self.request_id,
        )
    }
}

fn map_cancellable_stream<T, S>(
    source: S,
    cancellation: CancellationToken,
    identity: CallIdentity,
    deadline: Instant,
) -> CancellableStream<T>
where
    T: Send + 'static,
    S: Stream<Item = Result<T, Status>> + Send + 'static,
{
    let stream_cancellation = cancellation.clone();
    let inner = Box::pin(stream! {
        let mut source = Box::pin(source);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                yield Err(identity.error(SdkErrorCode::DeadlineExceeded));
                break;
            }
            tokio::select! {
                biased;
                _ = stream_cancellation.cancelled() => {
                    yield Err(identity.error(SdkErrorCode::Cancelled));
                    break;
                }
                _ = tokio::time::sleep(remaining) => {
                    yield Err(identity.error(SdkErrorCode::DeadlineExceeded));
                    break;
                }
                item = source.next() => {
                    match item {
                        Some(Ok(item)) => yield Ok(item),
                        Some(Err(status)) => {
                            yield Err(identity.status_error(status));
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    });
    CancellableStream {
        inner,
        cancellation,
    }
}

fn raw_path(path: &str) -> Result<PathAndQuery, SdkError> {
    if path.len() > 512 || !path.starts_with('/') || path.contains('\n') || path.contains('\r') {
        return Err(SdkError::invalid_argument());
    }
    PathAndQuery::try_from(path.to_owned()).map_err(|_| SdkError::invalid_argument())
}

fn insert_metadata(metadata: &mut MetadataMap, key: &str, value: &str) -> Result<(), SdkError> {
    let key = MetadataKey::from_bytes(key.as_bytes()).map_err(|_| SdkError::invalid_argument())?;
    let value = MetadataValue::try_from(value).map_err(|_| SdkError::invalid_argument())?;
    metadata.insert(key, value);
    Ok(())
}

fn validate_text(name: &str, value: &str, max_length: usize) -> Result<String, SdkError> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > max_length
        || value.contains(['\0', '\r', '\n'])
    {
        let _ = name;
        return Err(SdkError::invalid_argument());
    }
    Ok(value.to_string())
}

fn required_text(name: &str, value: &str, max_length: usize) -> Result<String, SdkError> {
    validate_text(name, value, max_length)
}

fn validate_optional_text(
    name: &str,
    value: Option<&str>,
    max_length: usize,
) -> Result<(), SdkError> {
    if let Some(value) = value {
        if !value.is_empty() {
            validate_text(name, value, max_length)?;
        }
    }
    Ok(())
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let ip = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    ip.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::stream;

    #[derive(Clone, Debug)]
    struct ObservedCall {
        method: &'static str,
        metadata: MetadataMap,
    }

    #[derive(Clone)]
    struct FixtureTransport {
        calls: Arc<Mutex<Vec<ObservedCall>>>,
        plan_failures: Arc<AtomicUsize>,
        receipt_failures: Arc<AtomicUsize>,
        plan_status: Arc<Mutex<Option<Status>>>,
        hang_plan: bool,
        hang_stream_open: bool,
        hang_stream_items: bool,
    }

    impl FixtureTransport {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                plan_failures: Arc::new(AtomicUsize::new(0)),
                receipt_failures: Arc::new(AtomicUsize::new(0)),
                plan_status: Arc::new(Mutex::new(None)),
                hang_plan: false,
                hang_stream_open: false,
                hang_stream_items: false,
            }
        }

        fn record(&self, method: &'static str, metadata: &MetadataMap) {
            self.calls.lock().unwrap().push(ObservedCall {
                method,
                metadata: metadata.clone(),
            });
        }

        fn calls(&self) -> Vec<ObservedCall> {
            self.calls.lock().unwrap().clone()
        }

        fn plan(&self, input: ExecutionInput) -> ExecutionPlan {
            ExecutionPlan {
                plan_id: "plan-fixture-1".into(),
                input: Some(input),
                executable: true,
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl CoreLoopTransport for FixtureTransport {
        type Stream = Pin<Box<dyn Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

        async fn plan_execution(
            &self,
            request: Request<PlanExecutionRequest>,
        ) -> Result<Response<PlanExecutionResponse>, Status> {
            self.record("PlanExecution", request.metadata());
            if self.hang_plan {
                return std::future::pending::<Result<Response<PlanExecutionResponse>, Status>>()
                    .await;
            }
            if self
                .plan_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    if value > 0 { Some(value - 1) } else { None }
                })
                .is_ok()
            {
                return Err(Status::unavailable("secret-token-must-not-escape"));
            }
            if let Some(status) = self.plan_status.lock().unwrap().clone() {
                return Err(status);
            }
            let input = request.get_ref().input.clone().unwrap_or_default();
            Ok(Response::new(PlanExecutionResponse {
                plan: Some(self.plan(input)),
            }))
        }

        async fn execute_plan_stream(
            &self,
            request: Request<ExecutePlanRequest>,
        ) -> Result<Response<Self::Stream>, Status> {
            self.record("ExecutePlanStream", request.metadata());
            if self.hang_stream_open {
                return std::future::pending::<Result<Response<Self::Stream>, Status>>().await;
            }
            if self.hang_stream_items {
                return Ok(Response::new(Box::pin(stream::pending())));
            }
            let events = vec![
                Ok(ExecutePlanStreamEvent {
                    content_delta: "one".into(),
                    ..Default::default()
                }),
                Ok(ExecutePlanStreamEvent {
                    content_delta: "two".into(),
                    done: true,
                    ..Default::default()
                }),
            ];
            Ok(Response::new(Box::pin(stream::iter(events))))
        }

        async fn report_operation_event(
            &self,
            request: Request<ReportOperationEventRequest>,
        ) -> Result<Response<ReportOperationEventResponse>, Status> {
            self.record("ReportOperationEvent", request.metadata());
            let event_id = request.get_ref().event_id.clone();
            Ok(Response::new(ReportOperationEventResponse {
                event_id,
                recorded: true,
                complete: false,
                missing_surfaces: vec!["outcome".into()],
            }))
        }

        async fn get_operation_receipt(
            &self,
            request: Request<GetOperationReceiptRequest>,
        ) -> Result<Response<GetOperationReceiptResponse>, Status> {
            self.record("GetOperationReceipt", request.metadata());
            if self
                .receipt_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    if value > 0 { Some(value - 1) } else { None }
                })
                .is_ok()
            {
                return Err(Status::unavailable("receipt transport unavailable"));
            }
            assert_eq!(request.get_ref().operation_id, "plan-fixture-1");
            Ok(Response::new(GetOperationReceiptResponse {
                receipt_json: "{\"operation_id\":\"plan-fixture-1\"}".into(),
                complete: true,
                missing_surfaces: Vec::new(),
            }))
        }
    }

    fn make_client(transport: FixtureTransport) -> CoreLoopClient<FixtureTransport> {
        let config = ClientConfig::for_injected("shikigami")
            .with_token("secret-token")
            .unwrap()
            .with_namespace("tenant-a")
            .with_catalog_version("catalog-v1");
        CoreLoopClient::new(config, transport).unwrap()
    }

    #[tokio::test]
    async fn fixture_covers_plan_stream_event_and_receipt_correlation() {
        let transport = FixtureTransport::new();
        let client = make_client(transport.clone());
        let plan = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    spec: "summarize the fixture".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
            .unwrap();
        let mut stream = client
            .execute_plan_stream(plan.clone(), CallOptions::new())
            .await
            .unwrap();
        let mut content = Vec::new();
        while let Some(event) = stream.next().await {
            content.push(event.unwrap().content_delta);
        }
        assert_eq!(content, ["one", "two"]);
        client
            .report_operation_event(
                ReportOperationEventRequest {
                    operation_id: plan.plan_id.clone(),
                    event_id: "event-fixture-1".into(),
                    kind: "outcome".into(),
                    ..Default::default()
                },
                CallOptions::new().with_request_id("event-request-1"),
            )
            .await
            .unwrap();
        let receipt = client
            .get_operation_receipt(
                GetOperationReceiptRequest {
                    operation_id: plan.plan_id,
                    ..Default::default()
                },
                CallOptions::new().with_request_id("receipt-request-1"),
            )
            .await
            .unwrap();
        assert!(receipt.complete);
        assert_eq!(
            receipt.receipt_json,
            "{\"operation_id\":\"plan-fixture-1\"}"
        );

        let calls = transport.calls();
        assert_eq!(
            calls.iter().map(|call| call.method).collect::<Vec<_>>(),
            [
                "PlanExecution",
                "ExecutePlanStream",
                "ReportOperationEvent",
                "GetOperationReceipt"
            ]
        );
        for call in calls {
            assert_eq!(call.metadata.get(PRINCIPAL_METADATA).unwrap(), "shikigami");
            assert_eq!(
                call.metadata.get(AUTHORIZATION_METADATA).unwrap(),
                "Bearer secret-token"
            );
            assert_eq!(call.metadata.get(NAMESPACE_METADATA).unwrap(), "tenant-a");
            assert!(call.metadata.get(CAPABILITY_METADATA).is_some());
            assert!(call.metadata.get(REQUEST_ID_METADATA).is_some());
            assert!(call.metadata.get("grpc-timeout").is_some());
        }
        let debug = format!("{:?}", client.config());
        assert!(!debug.contains("secret-token"));
    }

    #[tokio::test]
    async fn run_core_loop_keeps_one_request_and_operation_identity() {
        let transport = FixtureTransport::new();
        let client = make_client(transport.clone());
        let result = client
            .run_core_loop(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    spec: "fixture".into(),
                    ..Default::default()
                },
                CallOptions::new()
                    .with_operation_id("operation-run-1")
                    .with_request_id("request-run-1"),
            )
            .await
            .unwrap();
        assert_eq!(result.operation_id, "operation-run-1");
        assert_eq!(result.request_id, "request-run-1");
        assert_eq!(result.events.len(), 2);
        assert!(result.receipt.complete);
        let calls = transport.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0].metadata.get(OPERATION_METADATA).unwrap(),
            "operation-run-1"
        );
        assert_eq!(
            calls[1].metadata.get(OPERATION_METADATA).unwrap(),
            "operation-run-1"
        );
        assert_eq!(
            calls[2].metadata.get(OPERATION_METADATA).unwrap(),
            "operation-run-1"
        );
    }

    #[tokio::test]
    async fn retries_are_opt_in_and_reuse_the_idempotency_metadata() {
        let transport = FixtureTransport::new();
        transport.plan_failures.store(2, Ordering::SeqCst);
        let client = make_client(transport.clone());
        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new().with_request_id("request-retry-1"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Unavailable);
        assert_eq!(transport.calls().len(), 1);

        let transport = FixtureTransport::new();
        transport.plan_failures.store(2, Ordering::SeqCst);
        let client = make_client(transport.clone());
        client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new()
                    .with_request_id("request-retry-2")
                    .retryable(true),
            )
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 3);
        assert!(
            calls.iter().all(|call| {
                call.metadata.get(REQUEST_ID_METADATA).unwrap() == "request-retry-2"
            })
        );

        let transport = FixtureTransport::new();
        transport.receipt_failures.store(2, Ordering::SeqCst);
        let client = make_client(transport.clone());
        client
            .get_operation_receipt(
                GetOperationReceiptRequest {
                    operation_id: "plan-fixture-1".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
            .unwrap();
        assert_eq!(transport.calls().len(), 3);

        let transport = FixtureTransport::new();
        transport.receipt_failures.store(2, Ordering::SeqCst);
        let client = make_client(transport.clone());
        let error = client
            .get_operation_receipt(
                GetOperationReceiptRequest {
                    operation_id: "plan-fixture-1".into(),
                    ..Default::default()
                },
                CallOptions::new().retryable(false),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Unavailable);
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn typed_errors_preserve_auth_and_policy_boundaries_without_server_text() {
        let transport = FixtureTransport::new();
        *transport.plan_status.lock().unwrap() =
            Some(Status::permission_denied("credential=secret-token"));
        let client = make_client(transport);
        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::PermissionDenied);
        assert!(error.is_authorization());
        assert!(!error.to_string().contains("secret-token"));

        let transport = FixtureTransport::new();
        *transport.plan_status.lock().unwrap() =
            Some(Status::failed_precondition("policy secret-token"));
        let client = make_client(transport);
        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::FailedPrecondition);
        assert!(error.is_policy_or_budget());
    }

    #[tokio::test]
    async fn cancellation_stops_a_stream_without_replaying_it() {
        let transport = FixtureTransport::new();
        let client = make_client(transport.clone());
        let token = CancellationToken::new();
        let mut stream = client
            .execute_plan_stream(
                ExecutionPlan {
                    plan_id: "plan-fixture-1".into(),
                    input: Some(ExecutionInput {
                        namespace: "tenant-a".into(),
                        ..Default::default()
                    }),
                    executable: true,
                    ..Default::default()
                },
                CallOptions::new()
                    .with_cancellation(token.clone())
                    .with_request_id("request-cancel-1"),
            )
            .await
            .unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().content_delta, "one");
        token.cancel();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Cancelled);
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn local_deadlines_bound_injected_unary_and_stream_calls() {
        let mut transport = FixtureTransport::new();
        transport.hang_plan = true;
        let client = make_client(transport);
        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new().with_timeout(Duration::from_millis(20)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::DeadlineExceeded);

        let mut transport = FixtureTransport::new();
        transport.hang_stream_open = true;
        let client = make_client(transport);
        let error = match client
            .execute_plan_stream(
                ExecutionPlan {
                    plan_id: "plan-fixture-1".into(),
                    input: Some(ExecutionInput {
                        namespace: "tenant-a".into(),
                        ..Default::default()
                    }),
                    executable: true,
                    ..Default::default()
                },
                CallOptions::new().with_timeout(Duration::from_millis(20)),
            )
            .await
        {
            Ok(_) => panic!("hanging stream connection exceeded its deadline"),
            Err(error) => error,
        };
        assert_eq!(error.code, SdkErrorCode::DeadlineExceeded);

        let mut transport = FixtureTransport::new();
        transport.hang_stream_items = true;
        let client = make_client(transport);
        let mut stream = client
            .execute_plan_stream(
                ExecutionPlan {
                    plan_id: "plan-fixture-1".into(),
                    input: Some(ExecutionInput {
                        namespace: "tenant-a".into(),
                        ..Default::default()
                    }),
                    executable: true,
                    ..Default::default()
                },
                CallOptions::new().with_timeout(Duration::from_millis(20)),
            )
            .await
            .unwrap();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code, SdkErrorCode::DeadlineExceeded);
    }

    #[tokio::test]
    async fn core_loop_buffering_has_event_count_and_byte_bounds() {
        let config = ClientConfig::for_injected("shikigami")
            .with_namespace("tenant-a")
            .with_stream_limits(1, DEFAULT_MAX_STREAM_BYTES);
        let client = CoreLoopClient::new(config, FixtureTransport::new()).unwrap();
        let error = match client
            .run_core_loop(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
        {
            Ok(_) => panic!("event count bound was not enforced"),
            Err(error) => error,
        };
        assert_eq!(error.code, SdkErrorCode::ResourceExhausted);

        let config = ClientConfig::for_injected("shikigami")
            .with_namespace("tenant-a")
            .with_stream_limits(DEFAULT_MAX_STREAM_EVENTS, 1);
        let client = CoreLoopClient::new(config, FixtureTransport::new()).unwrap();
        let error = match client
            .run_core_loop(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
        {
            Ok(_) => panic!("event byte bound was not enforced"),
            Err(error) => error,
        };
        assert_eq!(error.code, SdkErrorCode::ResourceExhausted);
    }

    #[tokio::test]
    async fn reserved_metadata_and_namespace_mismatch_fail_before_transport() {
        let transport = FixtureTransport::new();
        let client = make_client(transport.clone());
        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new()
                    .with_context(CallContext::default().with_metadata("authorization", "forged")),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());

        let error = match client
            .run_core_loop(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new().with_namespace("tenant-b"),
            )
            .await
        {
            Ok(_) => panic!("namespace mismatch was not rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());

        let error = client
            .get_operation_receipt(
                GetOperationReceiptRequest {
                    request_id: "lookup-alias".into(),
                    ..Default::default()
                },
                CallOptions::new().with_request_id("different-alias"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());

        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    ..Default::default()
                },
                CallOptions::new().with_capability("forged.capability"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());

        let error = client
            .metadata(&CallOptions::new().with_namespace("tenant-b"), "request-1")
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);

        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-a".into(),
                    request_id: "input-request".into(),
                    ..Default::default()
                },
                CallOptions::new().with_request_id("different-request"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());

        let error = client
            .plan_execution(
                ExecutionInput {
                    namespace: "tenant-b".into(),
                    ..Default::default()
                },
                CallOptions::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::InvalidArgument);
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn endpoint_policy_rejects_remote_plaintext_by_default() {
        let config = ClientConfig::new("http://192.0.2.10:50051", "agent");
        assert!(!config.allow_insecure_remote);
        assert!(!is_loopback_host("192.0.2.10"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.255.255.254"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("[::1]"));
    }
}
