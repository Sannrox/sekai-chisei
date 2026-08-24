use std::sync::Arc;

use futures_util::StreamExt;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::pb::chisei::{ChatMessage, ToolCall as ChiseiToolCall, ToolDef};
use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::content;
use crate::db::runtime_db::RuntimeDb;
use crate::llm;
use crate::obs::correlation::Stage;
use crate::provider_credentials::{
    ProcessEnvProviderCredentialResolver, TenantProviderCredentialResolver,
};
use tracing::{Instrument, info_span};

#[derive(Clone, Debug, Default)]
pub(super) struct ProviderExecutionRequest {
    pub(super) model: String,
    pub(super) system: String,
    pub(super) messages: Vec<ChatMessage>,
    pub(super) tools: Vec<ToolDef>,
    pub(super) max_tokens: i32,
    pub(super) user_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct ProviderContentExecutionRequest {
    pub(super) model: String,
    pub(super) system: String,
    pub(super) messages: Vec<content::ContentMessage>,
    pub(super) tools: Vec<ToolDef>,
    pub(super) max_tokens: i32,
    pub(super) user_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ProviderExecutionChunk {
    pub(super) content_delta: String,
    pub(super) content: String,
    pub(super) tool_calls: Vec<ChiseiToolCall>,
    pub(super) input_tokens: i32,
    pub(super) output_tokens: i32,
    pub(super) stop_reason: String,
    pub(super) done: bool,
    pub(super) cache_read_input_tokens: i32,
    pub(super) cache_creation_input_tokens: i32,
}

#[derive(Clone, Copy)]
struct ExecutionAuthentication<'a> {
    db: &'a RuntimeDb,
    context: Option<&'a crate::enterprise::AuthenticatedContext>,
}

pub type ProviderExecutionStream = Pin<
    Box<dyn futures_util::Stream<Item = Result<ProviderExecutionChunk, Status>> + Send + 'static>,
>;

pub async fn execute_native_chat_request_stream(
    config: &Config,
    budget: Arc<BudgetTracker>,
    db: &RuntimeDb,
    authenticated_context: Option<&crate::enterprise::AuthenticatedContext>,
    r: ProviderExecutionRequest,
    cacheable_message_count: usize,
) -> Result<ProviderExecutionStream, Status> {
    execute_chat_request_stream_with_cache(
        config,
        budget,
        r,
        llm::PromptCacheIntent {
            enabled: true,
            cacheable_message_count,
        },
        Some(ExecutionAuthentication {
            db,
            context: authenticated_context,
        }),
    )
    .await
}

pub async fn execute_native_content_request_stream(
    config: &Config,
    budget: Arc<BudgetTracker>,
    db: &RuntimeDb,
    authenticated_context: Option<&crate::enterprise::AuthenticatedContext>,
    request: ProviderContentExecutionRequest,
) -> Result<ProviderExecutionStream, Status> {
    let registry = refresh_provider_registry(config).await?;
    let provider_name = registry
        .resolve_model(&request.model)
        .map(|resolved| resolved.provider)
        .unwrap_or_else(|_| "unknown".to_string());
    let registry_state_path =
        crate::provider_profile::provider_registry_state_path(&config.db_path);
    let user_id = request
        .user_id
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let estimated = estimate_content_request(&request);
    let provider_credential = execution_provider_credential(
        Some(ExecutionAuthentication {
            db,
            context: authenticated_context,
        }),
        &registry,
        &request.model,
    )?;
    budget
        .check_and_reserve(&user_id, estimated)
        .map_err(Status::resource_exhausted)?;
    let provider = match llm::resolve_with_registry_and_provider_credential(
        &request.model,
        &registry,
        Some(&registry_state_path),
        config.anthropic_api_key.as_deref(),
        config.openai_api_key.as_deref(),
        &config.ollama_url,
        config.native_llm_url.as_deref(),
        provider_credential
            .as_ref()
            .map(|credential| credential.secret.expose()),
    ) {
        Ok(provider) => provider,
        Err(error) => {
            budget.adjust(&user_id, estimated, 0);
            return Err(Status::failed_precondition(error));
        }
    };
    let domain_request = content::ContentChatRequest {
        model: request.model,
        system: request.system,
        messages: request.messages,
        tools: request
            .tools
            .iter()
            .map(|tool| llm::ToolDef {
                name: tool.name.clone(),
                description: tool.description.clone(),
                input_schema: serde_json::from_str(&tool.input_schema_json)
                    .unwrap_or(serde_json::json!({})),
            })
            .collect(),
        max_tokens: request.max_tokens,
    };
    let provider_span = info_span!(
        "stage",
        stage = Stage::ProviderRequest.as_str(),
        provider = %provider_name,
        streaming = true,
        content_contract = content::CONTENT_CONTRACT_VERSION,
        otel.kind = "client",
    );
    let stream = match provider
        .content_chat_stream(&domain_request)
        .instrument(provider_span)
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            budget.adjust(&user_id, estimated, 0);
            return Err(provider_error_status(error));
        }
    };
    let budget_for_stream = budget.clone();
    let (tx, rx) = mpsc::channel::<Result<ProviderExecutionChunk, Status>>(16);
    let stream_span = info_span!(
        "stage",
        stage = Stage::ProviderRequest.as_str(),
        provider = %provider_name,
        streaming = true,
        stream_consume = true,
        content_contract = content::CONTENT_CONTRACT_VERSION,
        otel.kind = "client",
    );
    tokio::spawn(
        async move {
            let mut stream = stream;
            let mut last_tokens = 0;
            while let Some(next) = stream.next().await {
                match next {
                    Ok(chunk) => {
                        let actual_tokens = chunk
                            .input_tokens
                            .saturating_add(chunk.output_tokens)
                            .saturating_add(chunk.cache_read_input_tokens)
                            .saturating_add(chunk.cache_creation_input_tokens);
                        if actual_tokens > 0 {
                            last_tokens = actual_tokens;
                        }
                        let done = chunk.done;
                        if tx.send(Ok(domain_chunk_to_execution(chunk))).await.is_err() {
                            budget_for_stream.adjust(&user_id, estimated, last_tokens);
                            return;
                        }
                        if done {
                            budget_for_stream.adjust(&user_id, estimated, last_tokens);
                            return;
                        }
                    }
                    Err(error) => {
                        budget_for_stream.adjust(&user_id, estimated, 0);
                        let _ = tx.send(Err(Status::internal(error))).await;
                        return;
                    }
                }
            }
            budget_for_stream.adjust(&user_id, estimated, last_tokens);
        }
        .instrument(stream_span),
    );
    Ok(Box::pin(ReceiverStream::new(rx)))
}

async fn execute_chat_request_stream_with_cache(
    config: &Config,
    budget: Arc<BudgetTracker>,
    r: ProviderExecutionRequest,
    prompt_cache: llm::PromptCacheIntent,
    execution_authentication: Option<ExecutionAuthentication<'_>>,
) -> Result<ProviderExecutionStream, Status> {
    let registry = refresh_provider_registry(config).await?;
    let prompt_cache = eligible_prompt_cache_intent(&registry, &r, prompt_cache)?;
    let provider_name = registry
        .resolve_model(&r.model)
        .map(|resolved| resolved.provider)
        .unwrap_or_else(|_| "unknown".to_string());
    let registry_state_path =
        crate::provider_profile::provider_registry_state_path(&config.db_path);
    let user_id = r.user_id.clone().unwrap_or_else(|| "default".to_string());
    let estimated = estimate_chat_request(&r);
    let provider_credential =
        execution_provider_credential(execution_authentication, &registry, &r.model)?;
    budget
        .check_and_reserve(&user_id, estimated)
        .map_err(Status::resource_exhausted)?;
    let provider = match llm::resolve_with_registry_and_provider_credential(
        &r.model,
        &registry,
        Some(&registry_state_path),
        config.anthropic_api_key.as_deref(),
        config.openai_api_key.as_deref(),
        &config.ollama_url,
        config.native_llm_url.as_deref(),
        provider_credential
            .as_ref()
            .map(|credential| credential.secret.expose()),
    ) {
        Ok(p) => p,
        Err(e) => {
            budget.adjust(&user_id, estimated, 0);
            return Err(Status::failed_precondition(e));
        }
    };
    let chat_req = provider_request_to_domain(r, prompt_cache);
    let provider_span = info_span!(
        "stage",
        stage = Stage::ProviderRequest.as_str(),
        provider = %provider_name,
        streaming = true,
        otel.kind = "client",
    );
    let stream = match provider
        .chat_stream(&chat_req)
        .instrument(provider_span)
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            budget.adjust(&user_id, estimated, 0);
            return Err(provider_error_status(e));
        }
    };
    let budget_for_stream = budget.clone();
    let (tx, rx) = mpsc::channel::<Result<ProviderExecutionChunk, Status>>(16);
    let user_id_for_stream = user_id.clone();
    let stream_span = info_span!(
        "stage",
        stage = Stage::ProviderRequest.as_str(),
        provider = %provider_name,
        streaming = true,
        stream_consume = true,
        otel.kind = "client",
    );

    tokio::spawn(
        async move {
            let mut stream = stream;
            let mut last_tokens = 0;
            while let Some(next) = stream.next().await {
                match next {
                    Ok(chunk) => {
                        let actual_tokens = chunk
                            .input_tokens
                            .saturating_add(chunk.output_tokens)
                            .saturating_add(chunk.cache_read_input_tokens)
                            .saturating_add(chunk.cache_creation_input_tokens);
                        if actual_tokens > 0 {
                            last_tokens = actual_tokens;
                        }
                        let done = chunk.done;
                        let execution_chunk = domain_chunk_to_execution(chunk);
                        if tx.send(Ok(execution_chunk)).await.is_err() {
                            budget_for_stream.adjust(&user_id_for_stream, estimated, last_tokens);
                            return;
                        }
                        if done {
                            budget_for_stream.adjust(&user_id_for_stream, estimated, last_tokens);
                            return;
                        }
                    }
                    Err(err) => {
                        budget_for_stream.adjust(&user_id_for_stream, estimated, 0);
                        let _ = tx.send(Err(Status::internal(err))).await;
                        return;
                    }
                }
            }
            budget_for_stream.adjust(&user_id_for_stream, estimated, last_tokens);
        }
        .instrument(stream_span),
    );

    Ok(Box::pin(ReceiverStream::new(rx)))
}

fn execution_provider_credential(
    authentication: Option<ExecutionAuthentication<'_>>,
    registry: &crate::provider_profile::ProviderRegistry,
    model: &str,
) -> Result<Option<crate::provider_credentials::ResolvedProviderCredential>, Status> {
    let Some(authentication) = authentication else {
        return Ok(None);
    };
    let Some(context) = authentication.context else {
        return Ok(None);
    };
    let expected_tenant_id = context
        .tenant
        .as_ref()
        .map(|tenant| tenant.tenant_id.as_str());
    let resolved = registry
        .resolve_model(model)
        .map_err(Status::failed_precondition)?;
    let profile = registry
        .effective_profile(&resolved.provider)
        .ok_or_else(|| Status::failed_precondition("provider profile unavailable"))?;
    if profile.endpoint.api_key_env.is_none() {
        return Ok(None);
    }
    let credential = match authentication.db.enterprise_extension() {
        Some(extension) => match extension.resolve_provider_credential(context, &resolved.provider)
        {
            Ok(credential) => credential,
            Err(crate::enterprise::ExtensionError::CredentialNotFound) => {
                ProcessEnvProviderCredentialResolver
                    .resolve(context, &resolved.provider)
                    .map_err(|_| Status::unavailable("provider credential unavailable"))?
            }
            Err(_) => return Err(Status::unavailable("provider credential unavailable")),
        },
        None => ProcessEnvProviderCredentialResolver
            .resolve(context, &resolved.provider)
            .map_err(|_| Status::unavailable("provider credential unavailable"))?,
    };
    if credential.provider != resolved.provider
        || !instance_or_matching_tenant(credential.tenant_id.as_deref(), expected_tenant_id)
        || credential.secret.expose().trim().is_empty()
    {
        return Err(Status::unavailable("provider credential unavailable"));
    }
    Ok(Some(credential))
}

fn instance_or_matching_tenant(
    credential_tenant: Option<&str>,
    expected_tenant: Option<&str>,
) -> bool {
    match (credential_tenant, expected_tenant) {
        (None, _) => true,
        (Some(actual), Some(expected)) => actual == expected,
        (Some(_), None) => false,
    }
}

fn provider_error_status(error: String) -> Status {
    match llm::decode_provider_error(error) {
        llm::ProviderError::Precondition(message) => Status::failed_precondition(message),
        llm::ProviderError::Unavailable(message) => Status::unavailable(message),
        llm::ProviderError::Upstream(message) => Status::internal(message),
    }
}

fn provider_request_to_domain(
    r: ProviderExecutionRequest,
    prompt_cache: llm::PromptCacheIntent,
) -> llm::ChatRequest {
    llm::ChatRequest {
        model: r.model,
        system: r.system,
        messages: r
            .messages
            .iter()
            .map(|m| llm::Message {
                role: m.role.clone(),
                content: m.content.clone(),
                tool_call_id: m.tool_call_id.clone(),
                tool_calls: m
                    .tool_calls
                    .iter()
                    .map(|tc| llm::ToolCall {
                        id: tc.id.clone(),
                        name: tc.name.clone(),
                        args: serde_json::from_str(&tc.args_json).unwrap_or(serde_json::json!({})),
                    })
                    .collect(),
            })
            .collect(),
        tools: r
            .tools
            .iter()
            .map(|t| llm::ToolDef {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: serde_json::from_str(&t.input_schema_json)
                    .unwrap_or(serde_json::json!({})),
            })
            .collect(),
        max_tokens: r.max_tokens,
        prompt_cache,
    }
}

fn eligible_prompt_cache_intent(
    registry: &crate::provider_profile::ProviderRegistry,
    request: &ProviderExecutionRequest,
    requested: llm::PromptCacheIntent,
) -> Result<llm::PromptCacheIntent, Status> {
    use crate::chisei::cache_policy::{
        CacheDecisionKind, CachePolicyInput, POLICY_VERSION, evaluate,
    };
    if !requested.enabled {
        return Ok(requested);
    }
    let Ok(resolved) = registry.resolve_model(&request.model) else {
        return Ok(llm::PromptCacheIntent::default());
    };
    let Some(profile) = registry.effective_profile(&resolved.provider) else {
        return Ok(llm::PromptCacheIntent::default());
    };
    let stable_bytes = request.system.len()
        + request
            .tools
            .iter()
            .map(|tool| tool.name.len() + tool.description.len() + tool.input_schema_json.len())
            .sum::<usize>()
        + request
            .messages
            .iter()
            .take(requested.cacheable_message_count)
            .map(|message| {
                message.role.len()
                    + message.content.len()
                    + message.tool_call_id.len()
                    + message
                        .tool_calls
                        .iter()
                        .map(|call| call.id.len() + call.name.len() + call.args_json.len())
                        .sum::<usize>()
            })
            .sum::<usize>();
    let estimated_tokens = stable_bytes.div_ceil(4) as u64;
    let decision = evaluate(CachePolicyInput {
        requested: true,
        provider_supported: profile.prompt_cache.explicit_breakpoints,
        model_supported: profile.prompt_cache.explicit_breakpoints,
        // Registry resolution has already enforced experimental/canary
        // admission. Only a disabled effective profile is unavailable here.
        provider_enabled: profile.lifecycle != "disabled",
        stable_prefix_tokens: estimated_tokens,
        minimum_cacheable_tokens: profile.prompt_cache.minimum_cacheable_tokens,
        // Native execution reaches this boundary only after Chisei privacy and
        // egress checks. The provider adapter never broadens that decision.
        data_class_allowed: true,
        controls_valid: requested.cacheable_message_count <= request.messages.len(),
        accounting_available: !profile.prompt_cache.usage_fields.is_empty(),
        uncached_fallback_allowed: true,
        // Native caching is selected for stable conversation history expected
        // to be reused; provider profiles currently expose price classes, not
        // numeric ratios, so break-even remains unquantified here.
        expected_requests: 2,
        write_price_ratio_millionths: None,
        read_price_ratio_millionths: None,
    });
    tracing::info!(
        policy_version = POLICY_VERSION,
        outcome = decision.kind.as_str(),
        reason = decision.reason.as_str(),
        stable_prefix_tokens = estimated_tokens,
        break_even_requests = decision.break_even_requests,
        "prompt cache policy evaluated"
    );
    if decision.kind == CacheDecisionKind::Invalid {
        Err(Status::failed_precondition(format!(
            "prompt cache policy rejected request: {}",
            decision.reason.as_str()
        )))
    } else if decision.enabled() {
        Ok(requested)
    } else {
        Ok(llm::PromptCacheIntent::default())
    }
}

fn domain_chunk_to_execution(chunk: llm::ChatStreamChunk) -> ProviderExecutionChunk {
    ProviderExecutionChunk {
        content_delta: chunk.content_delta,
        content: chunk.content,
        tool_calls: chunk
            .tool_calls
            .into_iter()
            .map(|tc| ChiseiToolCall {
                id: tc.id,
                name: tc.name,
                args_json: tc.args.to_string(),
            })
            .collect(),
        input_tokens: chunk.input_tokens,
        output_tokens: chunk.output_tokens,
        stop_reason: chunk.stop_reason,
        done: chunk.done,
        cache_read_input_tokens: chunk.cache_read_input_tokens,
        cache_creation_input_tokens: chunk.cache_creation_input_tokens,
    }
}

pub fn estimate_chat_request(r: &ProviderExecutionRequest) -> i32 {
    let system_tokens = r.system.len() as i32 / 4;
    let message_tokens = r
        .messages
        .iter()
        .map(|m| {
            let tool_calls_size = m
                .tool_calls
                .iter()
                .map(|tc| tc.id.len() + tc.name.len() + tc.args_json.len())
                .sum::<usize>();
            ((m.role.len() + m.content.len() + m.tool_call_id.len() + tool_calls_size) as i32) / 4
        })
        .sum::<i32>();
    let tool_defs_tokens = r
        .tools
        .iter()
        .map(|t| ((t.name.len() + t.description.len() + t.input_schema_json.len()) as i32) / 4)
        .sum::<i32>();
    system_tokens + message_tokens + tool_defs_tokens + r.max_tokens
}

fn estimate_content_request(request: &ProviderContentExecutionRequest) -> i32 {
    let bytes = request.system.len()
        + request
            .messages
            .iter()
            .map(|message| {
                message.role.len()
                    + message.tool_call_id.len()
                    + message
                        .parts
                        .iter()
                        .map(|part| part.descriptor.byte_length as usize)
                        .sum::<usize>()
            })
            .sum::<usize>()
        + request
            .tools
            .iter()
            .map(|tool| tool.name.len() + tool.description.len() + tool.input_schema_json.len())
            .sum::<usize>();
    i32::try_from(bytes.div_ceil(4))
        .unwrap_or(i32::MAX)
        .saturating_add(request.max_tokens.max(0))
}

async fn refresh_provider_registry(
    config: &Config,
) -> Result<crate::provider_profile::ProviderRegistry, Status> {
    let path = crate::provider_profile::provider_registry_state_path(&config.db_path);
    refresh_provider_registry_at(&path).await
}

async fn refresh_provider_registry_at(
    path: &std::path::Path,
) -> Result<crate::provider_profile::ProviderRegistry, Status> {
    crate::provider_resolution::snapshot_for_execution(Some(path))
        .await
        .map_err(|error| Status::unavailable(format!("provider registry unavailable: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct TenantCredentialExtension;

    impl crate::enterprise::EnterpriseExtension for TenantCredentialExtension {
        fn authenticate_bearer(
            &self,
            _bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            _bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn tenant_context(
            &self,
            _principal: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::Unauthenticated)
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
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn resolve_provider_credential(
            &self,
            context: &crate::enterprise::AuthenticatedContext,
            provider: &str,
        ) -> Result<
            crate::provider_credentials::ResolvedProviderCredential,
            crate::enterprise::ExtensionError,
        > {
            let (tenant_id, credential_id, secret) = match (context.tenant.as_ref(), provider) {
                (Some(tenant), "openai") if tenant.tenant_id == "tenant-a" => (
                    Some(tenant.tenant_id.clone()),
                    "credential:tenant-a:openai",
                    "synthetic-secret-a",
                ),
                (Some(tenant), "openai") if tenant.tenant_id == "tenant-b" => (
                    Some(tenant.tenant_id.clone()),
                    "credential:tenant-b:openai",
                    "synthetic-secret-b",
                ),
                (None, "openai") => (
                    None,
                    "credential:unscoped:openai",
                    "synthetic-unscoped-secret",
                ),
                _ => return Err(crate::enterprise::ExtensionError::CredentialNotFound),
            };
            Ok(crate::provider_credentials::ResolvedProviderCredential {
                credential_id: credential_id.into(),
                tenant_id,
                provider: provider.into(),
                generation: 1,
                secret: crate::enterprise::SecretValue::new(secret),
            })
        }
    }

    fn tenant_context(tenant_id: &str) -> crate::enterprise::AuthenticatedContext {
        crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            principal: crate::enterprise::AuthenticatedPrincipal {
                subject: "service:managed-shikigami".into(),
                credential_id: format!("credential:{tenant_id}"),
            },
            credential_kind: crate::enterprise::CredentialKind::Machine,
            tenant: Some(crate::enterprise::TenantContext {
                tenant_id: tenant_id.into(),
                subject: "service:managed-shikigami".into(),
            }),
            scopes: vec!["chisei.execute".into()],
            issuer: "https://issuer.test".into(),
            resource: "sekai:control-plane".into(),
            expires_at: i64::MAX,
        }
    }

    #[tokio::test]
    async fn registry_state_loss_is_reported_as_unavailable() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-llm-provider-registry-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        crate::provider_profile::refresh_provider_registry(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let status = refresh_provider_registry_at(&path).await.unwrap_err();

        assert_eq!(status.code(), tonic::Code::Unavailable);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_preconditions_are_not_reported_as_server_faults() {
        let precondition = provider_error_status(llm::encode_provider_error(
            llm::ProviderError::Precondition("provider disabled".into()),
        ));
        let upstream = provider_error_status(llm::encode_provider_error(
            llm::ProviderError::Upstream("provider timed out".into()),
        ));
        let unavailable = provider_error_status(llm::encode_provider_error(
            llm::ProviderError::Unavailable("registry unavailable".into()),
        ));

        assert_eq!(precondition.code(), tonic::Code::FailedPrecondition);
        assert_eq!(unavailable.code(), tonic::Code::Unavailable);
        assert_eq!(upstream.code(), tonic::Code::Internal);
    }

    #[test]
    fn execution_provider_credentials_are_selected_by_authenticated_tenant() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TenantCredentialExtension)),
            )
            .unwrap(),
        ));
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        let tenant_a = tenant_context("tenant-a");
        let tenant_b = tenant_context("tenant-b");

        let credential_a = execution_provider_credential(
            Some(ExecutionAuthentication {
                db: &db,
                context: Some(&tenant_a),
            }),
            &registry,
            "openai/gpt-5.5",
        )
        .unwrap()
        .unwrap();
        let credential_b = execution_provider_credential(
            Some(ExecutionAuthentication {
                db: &db,
                context: Some(&tenant_b),
            }),
            &registry,
            "openai/gpt-5.5",
        )
        .unwrap()
        .unwrap();

        assert_eq!(credential_a.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(credential_b.tenant_id.as_deref(), Some("tenant-b"));
        assert_eq!(credential_a.secret.expose(), "synthetic-secret-a");
        assert_eq!(credential_b.secret.expose(), "synthetic-secret-b");
        assert!(!format!("{credential_a:?}").contains("synthetic-secret-a"));
        assert!(!format!("{credential_b:?}").contains("synthetic-secret-b"));
    }

    #[test]
    fn unscoped_enterprise_context_does_not_inherit_community_provider_key() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TenantCredentialExtension)),
            )
            .unwrap(),
        ));
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        let mut context = tenant_context("tenant-a");
        context.tenant = None;

        let credential = execution_provider_credential(
            Some(ExecutionAuthentication {
                db: &db,
                context: Some(&context),
            }),
            &registry,
            "openai/gpt-5.5",
        )
        .unwrap()
        .unwrap();

        assert!(credential.tenant_id.is_none());
        assert_eq!(credential.secret.expose(), "synthetic-unscoped-secret");
    }

    fn with_env(name: &str, value: &str, body: impl FnOnce()) {
        let previous = std::env::var(name).ok();
        unsafe { std::env::set_var(name, value) };
        body();
        unsafe {
            match previous {
                Some(previous) => std::env::set_var(name, previous),
                None => std::env::remove_var(name),
            }
        }
    }

    #[test]
    fn community_runtime_uses_instance_key_for_tenant_callers() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ));
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        with_env("OPENAI_API_KEY", "sk-community-instance", || {
            let credential = execution_provider_credential(
                Some(ExecutionAuthentication {
                    db: &db,
                    context: Some(&tenant_context("tenant-a")),
                }),
                &registry,
                "openai/gpt-5.5",
            )
            .unwrap()
            .unwrap();
            assert!(credential.tenant_id.is_none());
            assert_eq!(credential.secret.expose(), "sk-community-instance");
            assert_eq!(credential.credential_id, "env:OPENAI_API_KEY");
        });
    }

    #[test]
    fn enterprise_missing_row_falls_back_to_instance_key() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TenantCredentialExtension)),
            )
            .unwrap(),
        ));
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        with_env("OPENAI_API_KEY", "sk-enterprise-fallback", || {
            let credential = execution_provider_credential(
                Some(ExecutionAuthentication {
                    db: &db,
                    context: Some(&tenant_context("tenant-c")),
                }),
                &registry,
                "openai/gpt-5.5",
            )
            .unwrap()
            .unwrap();
            assert!(credential.tenant_id.is_none());
            assert_eq!(credential.secret.expose(), "sk-enterprise-fallback");
        });
    }

    #[test]
    fn native_prompt_cache_requires_profile_support_and_minimum_size() {
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        let requested = llm::PromptCacheIntent {
            enabled: true,
            cacheable_message_count: 0,
        };
        let mut request = ProviderExecutionRequest {
            model: "anthropic/claude-sonnet-4-8".into(),
            system: "short".into(),
            ..Default::default()
        };
        assert_eq!(
            eligible_prompt_cache_intent(&registry, &request, requested).unwrap(),
            llm::PromptCacheIntent::default()
        );

        request.system = "s".repeat(4 * 4_096);
        assert_eq!(
            eligible_prompt_cache_intent(&registry, &request, requested).unwrap(),
            requested
        );

        request.model = "openai/gpt-5.5".into();
        assert_eq!(
            eligible_prompt_cache_intent(&registry, &request, requested).unwrap(),
            llm::PromptCacheIntent::default()
        );
    }

    #[test]
    fn invalid_native_cache_controls_fail_before_provider_contact() {
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        let request = ProviderExecutionRequest {
            model: "anthropic/claude-sonnet-4-8".into(),
            system: "s".repeat(4 * 4_096),
            ..Default::default()
        };
        let error = eligible_prompt_cache_intent(
            &registry,
            &request,
            llm::PromptCacheIntent {
                enabled: true,
                cacheable_message_count: 1,
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("invalid_controls"));
    }
}
