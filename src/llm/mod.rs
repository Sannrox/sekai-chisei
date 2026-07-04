pub mod anthropic;
pub mod ollama;
pub mod openai;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::pin::Pin;
use std::time::Duration;
use tracing::warn;

use futures_util::{Stream, stream};

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_READ_TIMEOUT_SECS: u64 = 60;
const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpTimeouts {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub request_timeout: Duration,
}

impl HttpTimeouts {
    pub(crate) fn from_env() -> Self {
        Self {
            connect_timeout: duration_env(
                "LLM_HTTP_CONNECT_TIMEOUT_SECS",
                DEFAULT_CONNECT_TIMEOUT_SECS,
            ),
            read_timeout: duration_env("LLM_HTTP_READ_TIMEOUT_SECS", DEFAULT_READ_TIMEOUT_SECS),
            pool_idle_timeout: duration_env(
                "LLM_HTTP_POOL_IDLE_TIMEOUT_SECS",
                DEFAULT_POOL_IDLE_TIMEOUT_SECS,
            ),
            request_timeout: duration_env(
                "LLM_HTTP_REQUEST_TIMEOUT_SECS",
                DEFAULT_REQUEST_TIMEOUT_SECS,
            ),
        }
    }

    pub(crate) fn client(self) -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .read_timeout(self.read_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .build()
            .expect("valid reqwest timeout configuration")
    }
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
            pool_idle_timeout: Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
        }
    }
}

fn duration_env(key: &str, default_secs: u64) -> Duration {
    match env::var(key) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            Ok(_) => {
                warn!(key, default_secs, "zero timeout is invalid; using default");
                Duration::from_secs(default_secs)
            }
            Err(err) => {
                warn!(key, value = %value, default_secs, error = %err, "invalid timeout; using default");
                Duration::from_secs(default_secs)
            }
        },
        Err(_) => Duration::from_secs(default_secs),
    }
}

pub(crate) fn classify_reqwest_error(context: &str, err: reqwest::Error) -> String {
    if err.is_timeout() {
        format!("{context} timed out: {err}")
    } else {
        format!("{context} failed: {err}")
    }
}

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

#[derive(Debug, Clone)]
pub struct ChatStreamChunk {
    pub content_delta: String,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub stop_reason: String,
    pub done: bool,
}

impl ChatStreamChunk {
    pub fn from_response(resp: ChatResponse) -> Self {
        Self {
            content_delta: resp.content.clone(),
            content: resp.content,
            tool_calls: resp.tool_calls,
            input_tokens: resp.input_tokens,
            output_tokens: resp.output_tokens,
            stop_reason: resp.stop_reason,
            done: true,
        }
    }
}

pub type ChatStream = Pin<Box<dyn Stream<Item = Result<ChatStreamChunk, String>> + Send>>;

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String>;

    async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, String> {
        let resp = self.chat(req).await?;
        Ok(Box::pin(stream::once(async move {
            Ok(ChatStreamChunk::from_response(resp))
        })))
    }
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
