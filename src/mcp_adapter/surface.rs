use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::time::timeout;
use tonic::Request;

use crate::capability_projection::{ProjectedError, ProjectionContext, SdkInvocation};
use crate::grpc::chisei_service::ChiseiServiceImpl;
use crate::grpc::client::connect_sekai_with_token;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::chisei_service_server::ChiseiService;
use crate::grpc::pb::chisei::{GetOperationReceiptRequest, GetOperationReceiptResponse};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    CreateLinkRequest, DescribeObjectActionRequest, DiscoverCapabilitiesRequest,
    EvaluateObjectSetRequest, GetLinksRequest, GetObjectRequest, Link, PreviewObjectActionRequest,
    SubmitActionInstanceRequest, SubmitActionInstanceResponse,
};
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::capability::CONTRACT_VERSION;

use super::AdapterConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRpc {
    GetObject,
    EvaluateObjectSet,
    DescribeObjectAction,
    PreviewObjectAction,
    SubmitActionInstance,
    GetOperationReceipt,
    GetLinks,
    CreateLink,
}

#[derive(Debug, Clone)]
pub struct CatalogSnapshot {
    pub context: ProjectionContext,
}

#[derive(Debug)]
pub enum AdapterError {
    Projected(ProjectedError),
    Protocol(String),
    Deadline,
    Cancelled,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Projected(error) => write!(formatter, "{}: {}", error.code, error.message),
            Self::Protocol(message) => write!(formatter, "{message}"),
            Self::Deadline => write!(formatter, "deadline exceeded"),
            Self::Cancelled => write!(formatter, "cancelled"),
        }
    }
}

impl std::error::Error for AdapterError {}

#[async_trait]
pub trait NativeSurface: Send + Sync {
    async fn discover(&self) -> Result<CatalogSnapshot, AdapterError>;
    async fn dispatch(
        &self,
        rpc: NativeRpc,
        invocation: SdkInvocation,
    ) -> Result<Value, AdapterError>;
}

pub async fn dispatch_native(
    sekai: &SekaiServiceImpl,
    chisei: &ChiseiServiceImpl,
    rpc: NativeRpc,
    invocation: SdkInvocation,
) -> Result<Value, AdapterError> {
    match rpc {
        NativeRpc::GetObject => {
            let request = invocation
                .bind(GetObjectRequest {
                    id: invocation
                        .input
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = sekai
                .get_object(request)
                .await
                .map_err(status_error)?
                .into_inner();
            let object = response
                .object
                .ok_or_else(|| AdapterError::Protocol("object missing from GetObject".into()))?;
            Ok(json!({
                "object": {
                    "id": object.id,
                    "kind": object.kind,
                    "name": object.name,
                    "namespace": object.namespace,
                    "properties": object.properties,
                }
            }))
        }
        NativeRpc::GetLinks => {
            let request = invocation
                .bind(get_links_request(&invocation)?)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = sekai
                .get_links(request)
                .await
                .map_err(status_error)?
                .into_inner();
            Ok(json!({"links": response.links.iter().map(link_json).collect::<Vec<_>>()}))
        }
        NativeRpc::CreateLink => {
            let request = invocation
                .bind(create_link_request(&invocation)?)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = sekai
                .create_link(request)
                .await
                .map_err(status_error)?
                .into_inner();
            let link = response
                .link
                .ok_or_else(|| AdapterError::Protocol("link missing from CreateLink".into()))?;
            Ok(json!({"link": link_json(&link)}))
        }
        NativeRpc::EvaluateObjectSet => {
            let payload =
                serde_json::from_value::<EvaluateObjectSetRequest>(invocation.input.clone())
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let request = invocation
                .bind(payload)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = sekai
                .evaluate_object_set(request)
                .await
                .map_err(status_error)?
                .into_inner();
            serde_json::to_value(response)
                .map_err(|error| AdapterError::Protocol(error.to_string()))
        }
        NativeRpc::DescribeObjectAction => {
            let payload =
                serde_json::from_value::<DescribeObjectActionRequest>(invocation.input.clone())
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let request = invocation
                .bind(payload)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = sekai
                .describe_object_action(request)
                .await
                .map_err(status_error)?
                .into_inner();
            serde_json::to_value(response)
                .map_err(|error| AdapterError::Protocol(error.to_string()))
        }
        NativeRpc::PreviewObjectAction => {
            let payload =
                serde_json::from_value::<PreviewObjectActionRequest>(invocation.input.clone())
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let request = invocation
                .bind(payload)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = timeout(
                preview_fill_deadline(),
                sekai.preview_object_action(request),
            )
            .await
            .map_err(|_| AdapterError::Deadline)?
            .map_err(status_error)?
            .into_inner();
            serde_json::to_value(response)
                .map_err(|error| AdapterError::Protocol(error.to_string()))
        }
        NativeRpc::SubmitActionInstance => {
            let request = invocation
                .bind(submit_request(&invocation)?)
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = timeout(
                Duration::from_secs(5),
                sekai.submit_action_instance(request),
            )
            .await
            .map_err(|_| AdapterError::Deadline)?
            .map_err(status_error)?
            .into_inner();
            Ok(submit_output(response))
        }
        NativeRpc::GetOperationReceipt => {
            let request = invocation
                .bind(GetOperationReceiptRequest {
                    operation_id: invocation
                        .input
                        .get("operation_id")
                        .or_else(|| invocation.input.get("operationId"))
                        .and_then(Value::as_str)
                        .unwrap_or(&invocation.operation_id)
                        .to_string(),
                    request_id: String::new(),
                    caller_scope: String::new(),
                    attempt: 0,
                })
                .map_err(|error| AdapterError::Protocol(error.to_string()))?;
            let response = chisei
                .get_operation_receipt(request)
                .await
                .map_err(status_error)?
                .into_inner();
            Ok(receipt_output(response))
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixtureObject {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct FixtureAction {
    pub instance_id: String,
    pub status: String,
    pub operation_id: String,
    pub replay: bool,
}

/// Deterministic native surface for protocol tests and the synthetic example.
#[derive(Debug, Clone)]
pub struct FixtureSurface {
    pub principal: String,
    pub namespace: String,
    pub catalog_version: String,
    pub revoked: bool,
    pub objects: BTreeMap<String, FixtureObject>,
    pub actions: BTreeMap<String, FixtureAction>,
    pub receipts: BTreeMap<String, Value>,
    pub hidden_fields: BTreeMap<String, String>,
}

impl FixtureSurface {
    pub fn new(principal: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            namespace: namespace.into(),
            catalog_version: "sha256:fixture-catalog".into(),
            revoked: false,
            objects: BTreeMap::new(),
            actions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            hidden_fields: BTreeMap::new(),
        }
    }

    pub fn insert_object(&mut self, object: FixtureObject) {
        self.objects.insert(object.id.clone(), object);
    }
}

#[async_trait]
impl NativeSurface for FixtureSurface {
    async fn discover(&self) -> Result<CatalogSnapshot, AdapterError> {
        if self.revoked {
            return Err(projected(
                "permission_denied",
                "capability discovery denied",
                "",
                "",
            ));
        }
        Ok(CatalogSnapshot {
            context: ProjectionContext {
                namespace: self.namespace.clone(),
                principal: self.principal.clone(),
                contract_version: CONTRACT_VERSION.into(),
                catalog_version: self.catalog_version.clone(),
            },
        })
    }

    async fn dispatch(
        &self,
        rpc: NativeRpc,
        invocation: SdkInvocation,
    ) -> Result<Value, AdapterError> {
        match rpc {
            NativeRpc::GetObject => {
                let id = invocation
                    .input
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let object = self.objects.get(id).ok_or_else(|| {
                    projected(
                        "not_found",
                        "object not found",
                        &invocation.capability,
                        &invocation.operation_id,
                    )
                })?;
                if object.namespace != self.namespace {
                    return Err(projected(
                        "permission_denied",
                        "access denied",
                        &invocation.capability,
                        &invocation.operation_id,
                    ));
                }
                Ok(json!({
                    "object": {
                        "id": object.id,
                        "kind": object.kind,
                        "name": object.name,
                        "namespace": object.namespace,
                        "properties": object.properties,
                    }
                }))
            }
            NativeRpc::SubmitActionInstance => {
                let key = invocation
                    .input
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .unwrap_or(&invocation.operation_id)
                    .to_string();
                if let Some(existing) = self.actions.get(&key) {
                    return Ok(json!({
                        "instance": {
                            "instance_id": existing.instance_id,
                            "status": existing.status,
                            "operation_id": existing.operation_id,
                        },
                        "replay": true
                    }));
                }
                let status = invocation
                    .input
                    .get("force_status")
                    .and_then(Value::as_str)
                    .unwrap_or("admitted");
                Ok(json!({
                    "instance": {
                        "instance_id": format!("act-{}", invocation.operation_id),
                        "status": status,
                        "operation_id": invocation.operation_id,
                        "namespace": self.namespace,
                    },
                    "replay": false
                }))
            }
            NativeRpc::GetOperationReceipt => {
                let operation_id = invocation
                    .input
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .unwrap_or(&invocation.operation_id);
                if let Some(receipt) = self.receipts.get(operation_id) {
                    return Ok(receipt.clone());
                }
                Ok(json!({
                    "receipt_json": json!({
                        "operation_id": operation_id,
                        "status": "admitted"
                    }).to_string(),
                    "complete": true,
                    "missing_surfaces": []
                }))
            }
            NativeRpc::GetLinks => Ok(json!({
                "links": [{
                    "id": "link-fixture",
                    "from_id": required_string(&invocation.input, "object_id")?,
                    "to_id": "fixture-target",
                    "relation": "affects",
                    "created": 0,
                }]
            })),
            NativeRpc::CreateLink => Ok(json!({
                "link": {
                    "id": "link-fixture",
                    "from_id": required_string(&invocation.input, "from_id")?,
                    "to_id": required_string(&invocation.input, "to_id")?,
                    "relation": required_string(&invocation.input, "relation")?,
                    "created": 0,
                }
            })),
            NativeRpc::EvaluateObjectSet => Ok(json!({
                "members": [],
                "total": 0,
                "authority": false
            })),
            NativeRpc::DescribeObjectAction => Ok(json!({
                "namespace": self.namespace,
                "enabled": true,
                "previewSupported": true
            })),
            NativeRpc::PreviewObjectAction => Ok(json!({
                "outcome": "ready",
                "reasonCode": "preview"
            })),
        }
    }
}

pub struct SdkSurface {
    config: AdapterConfig,
}

impl SdkSurface {
    pub async fn connect(config: AdapterConfig) -> Result<Self, AdapterError> {
        if config.principal.trim().is_empty() || config.namespace.trim().is_empty() {
            return Err(AdapterError::Protocol(
                "adapter principal and namespace are required".into(),
            ));
        }
        Ok(Self { config })
    }

    async fn channel(&self) -> Result<crate::grpc::client::GatewayClient, AdapterError> {
        let credential = self.config.credential.clone().or_else(|| {
            std::env::var("SEKAI_CREDENTIAL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
        connect_sekai_with_token(&self.config.target, credential, Some(self.config.timeout))
            .await
            .map_err(|error| AdapterError::Protocol(error.to_string()))
    }
}

#[async_trait]
impl NativeSurface for SdkSurface {
    async fn discover(&self) -> Result<CatalogSnapshot, AdapterError> {
        let channel = self.channel().await?;
        let mut client = SekaiServiceClient::new(channel);
        let mut request = Request::new(DiscoverCapabilitiesRequest {
            namespace: self.config.namespace.clone(),
            product_tier_filter: "all".into(),
            page_size: 200,
            ..Default::default()
        });
        bind_session(
            &mut request,
            &self.config,
            "sekai.catalog.discover",
            "discover",
        )?;
        let response =
            with_timeout(self.config.timeout, client.discover_capabilities(request)).await?;
        Ok(CatalogSnapshot {
            context: ProjectionContext {
                namespace: self.config.namespace.clone(),
                principal: self.config.principal.clone(),
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
        rpc: NativeRpc,
        invocation: SdkInvocation,
    ) -> Result<Value, AdapterError> {
        match rpc {
            NativeRpc::GetObject => {
                let request = invocation
                    .bind(GetObjectRequest {
                        id: required_string(&invocation.input, "id")?,
                    })
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.get_object(request)).await?;
                let object = response.object.ok_or_else(|| {
                    projected(
                        "not_found",
                        "object not found",
                        &invocation.capability,
                        &invocation.operation_id,
                    )
                })?;
                Ok(json!({
                    "object": {
                        "id": object.id,
                        "kind": object.kind,
                        "name": object.name,
                        "namespace": object.namespace,
                        "external_id": object.external_id,
                        "properties": object.properties,
                        "created": object.created,
                        "updated": object.updated,
                    }
                }))
            }
            NativeRpc::SubmitActionInstance => {
                let request = invocation
                    .bind(submit_request(&invocation)?)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.submit_action_instance(request))
                        .await?;
                Ok(submit_output(response))
            }
            NativeRpc::GetOperationReceipt => {
                let request = invocation
                    .bind(GetOperationReceiptRequest {
                        operation_id: json_string(&invocation.input, "operation_id", "operationId")
                            .unwrap_or_else(|| invocation.operation_id.clone()),
                        request_id: json_string(&invocation.input, "request_id", "requestId")
                            .unwrap_or_default(),
                        caller_scope: json_string(&invocation.input, "caller_scope", "callerScope")
                            .unwrap_or_default(),
                        attempt: invocation
                            .input
                            .get("attempt")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                    })
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = ChiseiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.get_operation_receipt(request))
                        .await?;
                Ok(receipt_output(response))
            }
            NativeRpc::GetLinks => {
                let request = invocation
                    .bind(get_links_request(&invocation)?)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response = with_timeout(self.config.timeout, client.get_links(request)).await?;
                Ok(json!({"links": response.links.iter().map(link_json).collect::<Vec<_>>()}))
            }
            NativeRpc::CreateLink => {
                let request = invocation
                    .bind(create_link_request(&invocation)?)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.create_link(request)).await?;
                let link = response
                    .link
                    .ok_or_else(|| AdapterError::Protocol("link missing from CreateLink".into()))?;
                Ok(json!({"link": link_json(&link)}))
            }
            NativeRpc::EvaluateObjectSet => {
                let payload =
                    serde_json::from_value::<EvaluateObjectSetRequest>(invocation.input.clone())
                        .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let request = invocation
                    .bind(payload)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.evaluate_object_set(request)).await?;
                serde_json::to_value(response)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))
            }
            NativeRpc::DescribeObjectAction => {
                let payload =
                    serde_json::from_value::<DescribeObjectActionRequest>(invocation.input.clone())
                        .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let request = invocation
                    .bind(payload)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response =
                    with_timeout(self.config.timeout, client.describe_object_action(request))
                        .await?;
                serde_json::to_value(response)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))
            }
            NativeRpc::PreviewObjectAction => {
                let payload =
                    serde_json::from_value::<PreviewObjectActionRequest>(invocation.input.clone())
                        .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let request = invocation
                    .bind(payload)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))?;
                let channel = self.channel().await?;
                let mut client = SekaiServiceClient::new(channel);
                let response = with_timeout(
                    preview_deadline(self.config.timeout),
                    client.preview_object_action(request),
                )
                .await?;
                serde_json::to_value(response)
                    .map_err(|error| AdapterError::Protocol(error.to_string()))
            }
        }
    }
}

fn get_links_request(invocation: &SdkInvocation) -> Result<GetLinksRequest, AdapterError> {
    Ok(GetLinksRequest {
        object_id: required_string(&invocation.input, "object_id")?,
        relation: json_string(&invocation.input, "relation", "relation").unwrap_or_default(),
        direction: json_string(&invocation.input, "direction", "direction").unwrap_or_default(),
    })
}

fn create_link_request(invocation: &SdkInvocation) -> Result<CreateLinkRequest, AdapterError> {
    Ok(CreateLinkRequest {
        link: Some(Link {
            id: String::new(),
            from_id: required_string(&invocation.input, "from_id")?,
            to_id: required_string(&invocation.input, "to_id")?,
            relation: required_string(&invocation.input, "relation")?,
            created: 0,
        }),
        fail_if_exists: false,
    })
}

fn link_json(link: &Link) -> Value {
    json!({
        "id": link.id,
        "from_id": link.from_id,
        "to_id": link.to_id,
        "relation": link.relation,
        "created": link.created,
    })
}

fn submit_request(invocation: &SdkInvocation) -> Result<SubmitActionInstanceRequest, AdapterError> {
    Ok(SubmitActionInstanceRequest {
        namespace: invocation.namespace.clone(),
        type_id: required_string(&invocation.input, "type_id")?,
        version: required_string(&invocation.input, "version")?,
        parameters_json: invocation
            .input
            .get("parameters_json")
            .or_else(|| invocation.input.get("parametersJson"))
            .map(|value| match value {
                Value::String(raw) => raw.clone(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "{}".into()),
        idempotency_key: json_string(&invocation.input, "idempotency_key", "idempotencyKey")
            .unwrap_or_else(|| invocation.operation_id.clone()),
        evidence_submission_ids: invocation
            .input
            .get("evidence_submission_ids")
            .or_else(|| invocation.input.get("evidenceSubmissionIds"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        request_id: invocation.operation_id.clone(),
        ontology_digest: json_string(&invocation.input, "ontology_digest", "ontologyDigest")
            .unwrap_or_default(),
    })
}

pub(super) fn submit_output(response: SubmitActionInstanceResponse) -> Value {
    let instance = response.instance;
    json!({
        "instance": instance.as_ref().map(|instance| json!({
            "instance_id": instance.instance_id,
            "namespace": instance.namespace,
            "type_id": instance.type_id,
            "version": instance.version,
            "status": instance.status,
            "deny_reason": instance.deny_reason,
            "operation_id": instance.operation_id,
            "request_digest": instance.request_digest,
            "idempotency_key": instance.idempotency_key,
            "system_one_fill_json": instance.system_one_fill_json,
        })),
        "replay": response.replay
    })
}

pub(super) fn receipt_output(response: GetOperationReceiptResponse) -> Value {
    json!({
        "receipt_json": response.receipt_json,
        "complete": response.complete,
        "missing_surfaces": response.missing_surfaces,
    })
}

fn bind_session<T>(
    request: &mut Request<T>,
    config: &AdapterConfig,
    capability: &str,
    operation_id: &str,
) -> Result<(), AdapterError> {
    for (key, value) in [
        ("x-principal", config.principal.as_str()),
        ("x-sekai-namespace", config.namespace.as_str()),
        ("x-sekai-capability", capability),
        ("x-sekai-operation-id", operation_id),
        ("x-chisei-work-unit", operation_id),
    ] {
        let metadata = tonic::metadata::MetadataValue::try_from(value)
            .map_err(|_| AdapterError::Protocol("ASCII metadata".into()))?;
        request.metadata_mut().insert(key, metadata);
    }
    Ok(())
}

/// MCP Preview may invoke System One fill. Use the Function host request
/// timeout (`LLM_HTTP_REQUEST_TIMEOUT_SECS`, default 120s) so the adapter
/// cannot deadline a fill that native Preview would complete.
pub(crate) fn preview_fill_deadline() -> Duration {
    crate::llm::HttpTimeouts::from_env().request_timeout
}

fn preview_deadline(configured: Duration) -> Duration {
    preview_fill_deadline().max(configured)
}

async fn with_timeout<F, T>(limit: Duration, future: F) -> Result<T, AdapterError>
where
    F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    match timeout(limit, future).await {
        Ok(Ok(response)) => Ok(response.into_inner()),
        Ok(Err(status)) => Err(status_error(status)),
        Err(_) => Err(AdapterError::Deadline),
    }
}

pub fn status_error(status: tonic::Status) -> AdapterError {
    AdapterError::Projected(ProjectedError {
        code: grpc_code_name(status.code()).into(),
        message: status.message().into(),
        capability: String::new(),
        operation_id: String::new(),
        retryable: matches!(
            status.code(),
            tonic::Code::Aborted | tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
        ),
    })
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

fn projected(code: &str, message: &str, capability: &str, operation_id: &str) -> AdapterError {
    AdapterError::Projected(ProjectedError {
        code: code.into(),
        message: message.into(),
        capability: capability.into(),
        operation_id: operation_id.into(),
        retryable: false,
    })
}

fn json_string(input: &Value, snake: &str, camel: &str) -> Option<String> {
    input
        .get(snake)
        .or_else(|| input.get(camel))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn required_string(input: &Value, field: &str) -> Result<String, AdapterError> {
    let camel = field
        .split('_')
        .enumerate()
        .map(|(index, part)| {
            if index == 0 {
                part.to_string()
            } else {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            }
        })
        .collect::<String>();
    json_string(input, field, &camel)
        .ok_or_else(|| AdapterError::Protocol(format!("{field} is required")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_string_accepts_protobuf_json_names() {
        let input = json!({"typeId":"review.intake","parametersJson":"{}"});
        assert_eq!(required_string(&input, "type_id").unwrap(), "review.intake");
        assert_eq!(
            json_string(&input, "parameters_json", "parametersJson").unwrap(),
            "{}"
        );
    }

    #[test]
    fn preview_fill_deadline_matches_function_host_request_timeout() {
        assert_eq!(
            preview_fill_deadline(),
            crate::llm::HttpTimeouts::from_env().request_timeout
        );
        assert_eq!(
            preview_deadline(Duration::from_secs(5)),
            preview_fill_deadline()
        );
        let longer = preview_fill_deadline() + Duration::from_secs(30);
        assert_eq!(preview_deadline(longer), longer);
    }
}
