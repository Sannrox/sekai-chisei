use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::pb::llm::llm_service_server::LlmService;
use super::pb::llm::*;
use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::llm;

pub struct LlmServiceImpl {
    config: Config,
    budget: Arc<BudgetTracker>,
}

impl LlmServiceImpl {
    #[allow(dead_code)]
    pub fn new(config: Config) -> Self {
        Self {
            budget: Arc::new(BudgetTracker::new()),
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
    let user_id = r.user_id.as_deref().unwrap_or("default");
    let estimated = estimate_chat_request(&r);
    budget
        .check_and_reserve(user_id, estimated)
        .map_err(Status::resource_exhausted)?;
    let provider = match llm::resolve(
        &r.model,
        config.anthropic_api_key.as_deref(),
        config.openai_api_key.as_deref(),
        &config.ollama_url,
        config.native_llm_url.as_deref(),
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
    };
    let resp = match provider.chat(&chat_req).await {
        Ok(r) => r,
        Err(e) => {
            budget.adjust(user_id, estimated, 0);
            return Err(Status::internal(e));
        }
    };
    let actual_tokens = resp.input_tokens + resp.output_tokens;
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
    })
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
    async fn chat(&self, req: Request<ChatRequest>) -> Result<Response<ChatResponse>, Status> {
        let resp =
            execute_chat_request(&self.config, self.budget.clone(), req.into_inner()).await?;
        Ok(Response::new(resp))
    }

    async fn resolve_provider(
        &self,
        req: Request<ResolveProviderRequest>,
    ) -> Result<Response<ResolveProviderResponse>, Status> {
        let model = req.into_inner().model;
        Ok(Response::new(ResolveProviderResponse {
            provider: llm::provider_name(&model).into(),
        }))
    }
}
