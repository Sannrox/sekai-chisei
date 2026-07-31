use std::sync::Arc;

use futures_util::StreamExt;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::pb::llm::llm_service_server::LlmService;
use super::pb::llm::*;
use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::llm;

pub struct LlmServiceImpl {
    config: Config,
    budget: Arc<BudgetTracker>,
}

impl LlmServiceImpl {
    #[allow(dead_code)]
    pub fn new(config: Config, db: Arc<RuntimeDb>) -> Self {
        Self {
            budget: Arc::new(BudgetTracker::new(db)),
            config,
        }
    }

    #[allow(dead_code)]
    pub fn with_budget(config: Config, budget: Arc<BudgetTracker>) -> Self {
        Self { budget, config }
    }
}

pub async fn execute_chat_request(
    config: &Config,
    budget: Arc<BudgetTracker>,
    r: ChatRequest,
) -> Result<ChatResponse, Status> {
    execute_chat_request_with_cache(config, budget, r, llm::PromptCacheIntent::default(), None)
        .await
}

pub async fn execute_native_chat_request(
    config: &Config,
    budget: Arc<BudgetTracker>,
    db: &RuntimeDb,
    authenticated_context: Option<&crate::enterprise::AuthenticatedContext>,
    r: ChatRequest,
    cacheable_message_count: usize,
) -> Result<ChatResponse, Status> {
    execute_chat_request_with_cache(
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

#[derive(Clone, Copy)]
struct ExecutionAuthentication<'a> {
    db: &'a RuntimeDb,
    context: Option<&'a crate::enterprise::AuthenticatedContext>,
}

async fn execute_chat_request_with_cache(
    config: &Config,
    budget: Arc<BudgetTracker>,
    r: ChatRequest,
    prompt_cache: llm::PromptCacheIntent,
    execution_authentication: Option<ExecutionAuthentication<'_>>,
) -> Result<ChatResponse, Status> {
    let registry = refresh_provider_registry(config).await?;
    let prompt_cache = eligible_prompt_cache_intent(&registry, &r, prompt_cache)?;
    let registry_state_path =
        crate::provider_profile::provider_registry_state_path(&config.db_path);
    let user_id = r.user_id.as_deref().unwrap_or("default");
    let estimated = estimate_chat_request(&r);
    let provider_credential =
        execution_provider_credential(execution_authentication, &registry, &r.model)?;
    budget
        .check_and_reserve(user_id, estimated)
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
            budget.adjust(user_id, estimated, 0);
            return Err(Status::failed_precondition(e));
        }
    };
    let chat_req = llm::ChatRequest {
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
    };
    let resp = match provider.chat(&chat_req).await {
        Ok(r) => r,
        Err(e) => {
            budget.adjust(user_id, estimated, 0);
            return Err(provider_error_status(e));
        }
    };
    let actual_tokens = resp
        .input_tokens
        .saturating_add(resp.output_tokens)
        .saturating_add(resp.cache_read_input_tokens)
        .saturating_add(resp.cache_creation_input_tokens);
    budget.adjust(user_id, estimated, actual_tokens);
    let tool_calls = resp
        .tool_calls
        .iter()
        .map(|tc| ToolCall {
            id: tc.id.clone(),
            name: tc.name.clone(),
            args_json: tc.args.to_string(),
        })
        .collect();
    Ok(ChatResponse {
        content: resp.content,
        tool_calls,
        input_tokens: resp.input_tokens,
        output_tokens: resp.output_tokens,
        stop_reason: resp.stop_reason,
        cache_read_input_tokens: resp.cache_read_input_tokens,
        cache_creation_input_tokens: resp.cache_creation_input_tokens,
    })
}

pub type ChatStreamResponse =
    Pin<Box<dyn futures_util::Stream<Item = Result<ChatStreamChunk, Status>> + Send + 'static>>;

pub async fn execute_chat_request_stream(
    config: &Config,
    budget: Arc<BudgetTracker>,
    r: ChatRequest,
) -> Result<ChatStreamResponse, Status> {
    execute_chat_request_stream_with_cache(
        config,
        budget,
        r,
        llm::PromptCacheIntent::default(),
        None,
    )
    .await
}

pub async fn execute_native_chat_request_stream(
    config: &Config,
    budget: Arc<BudgetTracker>,
    db: &RuntimeDb,
    authenticated_context: Option<&crate::enterprise::AuthenticatedContext>,
    r: ChatRequest,
    cacheable_message_count: usize,
) -> Result<ChatStreamResponse, Status> {
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

async fn execute_chat_request_stream_with_cache(
    config: &Config,
    budget: Arc<BudgetTracker>,
    r: ChatRequest,
    prompt_cache: llm::PromptCacheIntent,
    execution_authentication: Option<ExecutionAuthentication<'_>>,
) -> Result<ChatStreamResponse, Status> {
    let registry = refresh_provider_registry(config).await?;
    let prompt_cache = eligible_prompt_cache_intent(&registry, &r, prompt_cache)?;
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
    let chat_req = pb_chat_to_domain(r, prompt_cache);
    let stream = match provider.chat_stream(&chat_req).await {
        Ok(stream) => stream,
        Err(e) => {
            budget.adjust(&user_id, estimated, 0);
            return Err(provider_error_status(e));
        }
    };
    let budget_for_stream = budget.clone();
    let (tx, rx) = mpsc::channel::<Result<ChatStreamChunk, Status>>(16);
    let user_id_for_stream = user_id.clone();

    tokio::spawn(async move {
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
                    let pb_chunk = domain_chunk_to_pb(chunk);
                    if tx.send(Ok(pb_chunk)).await.is_err() {
                        continue;
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
    });

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
    let extension = authentication
        .db
        .enterprise_extension()
        .ok_or_else(|| Status::unavailable("provider credential unavailable"))?;
    let credential = extension
        .resolve_provider_credential(context, &resolved.provider)
        .map_err(|_| Status::unavailable("provider credential unavailable"))?;
    if credential.provider != resolved.provider
        || credential.tenant_id.as_deref() != expected_tenant_id
        || credential.secret.expose().trim().is_empty()
    {
        return Err(Status::unavailable("provider credential unavailable"));
    }
    Ok(Some(credential))
}

fn provider_error_status(error: String) -> Status {
    match llm::decode_provider_error(error) {
        llm::ProviderError::Precondition(message) => Status::failed_precondition(message),
        llm::ProviderError::Unavailable(message) => Status::unavailable(message),
        llm::ProviderError::Upstream(message) => Status::internal(message),
    }
}

fn pb_chat_to_domain(r: ChatRequest, prompt_cache: llm::PromptCacheIntent) -> llm::ChatRequest {
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
    request: &ChatRequest,
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

fn domain_chunk_to_pb(chunk: llm::ChatStreamChunk) -> ChatStreamChunk {
    ChatStreamChunk {
        content_delta: chunk.content_delta,
        content: chunk.content,
        tool_calls: chunk
            .tool_calls
            .into_iter()
            .map(|tc| ToolCall {
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

pub fn estimate_chat_request(r: &ChatRequest) -> i32 {
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

#[tonic::async_trait]
impl LlmService for LlmServiceImpl {
    type ChatStreamStream = ChatStreamResponse;

    async fn chat(&self, req: Request<ChatRequest>) -> Result<Response<ChatResponse>, Status> {
        let resp =
            execute_chat_request(&self.config, self.budget.clone(), req.into_inner()).await?;
        Ok(Response::new(resp))
    }

    async fn chat_stream(
        &self,
        req: Request<ChatRequest>,
    ) -> Result<Response<Self::ChatStreamStream>, Status> {
        let resp = execute_chat_request_stream(&self.config, self.budget.clone(), req.into_inner())
            .await?;
        Ok(Response::new(resp))
    }

    async fn resolve_provider(
        &self,
        req: Request<ResolveProviderRequest>,
    ) -> Result<Response<ResolveProviderResponse>, Status> {
        let registry = refresh_provider_registry(&self.config).await?;
        let model = req.into_inner().model;
        let provider = registry
            .resolve_model(&model)
            .map_err(Status::failed_precondition)?
            .provider;
        Ok(Response::new(ResolveProviderResponse { provider }))
    }
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

    #[test]
    fn native_prompt_cache_requires_profile_support_and_minimum_size() {
        let registry = crate::provider_profile::ProviderRegistry::built_in();
        let requested = llm::PromptCacheIntent {
            enabled: true,
            cacheable_message_count: 0,
        };
        let mut request = ChatRequest {
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
        let request = ChatRequest {
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
