pub mod anthropic;
pub mod ollama;
pub mod openai;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
    pub tool_call_id: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: i32,
}

#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub stop_reason: String,
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String>;
}

/// Resolve a model name to the appropriate provider.
pub fn resolve(
    model: &str,
    anthropic_key: Option<&str>,
    openai_key: Option<&str>,
    ollama_url: &str,
    native_url: Option<&str>,
) -> Result<Box<dyn Provider>, String> {
    if !is_valid_model_name(model) {
        return Err(format!("invalid model name: {:?}", model));
    }
    if model.starts_with("claude") {
        let key = anthropic_key.ok_or("ANTHROPIC_API_KEY not set")?;
        Ok(Box::new(anthropic::Anthropic::new(key)))
    } else if model.starts_with("gpt-") || model.starts_with("o1") {
        let key = openai_key.ok_or("OPENAI_API_KEY not set")?;
        Ok(Box::new(openai::OpenAI::new(key, None)))
    } else if model.starts_with("ollama/") {
        Ok(Box::new(openai::OpenAI::new("", Some(ollama_url))))
    } else {
        let url =
            native_url.ok_or_else(|| format!("NATIVE_LLM_URL not set for model {:?}", model))?;
        Ok(Box::new(openai::OpenAI::new("", Some(url))))
    }
}

pub fn provider_name(model: &str) -> &str {
    if model.starts_with("claude") {
        "anthropic"
    } else if model.starts_with("gpt-") || model.starts_with("o1") {
        "openai"
    } else if model.starts_with("ollama/") {
        "ollama"
    } else {
        "native"
    }
}

fn is_valid_model_name(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
}
