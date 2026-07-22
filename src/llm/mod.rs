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
        self.client_builder()
            .build()
            .expect("valid reqwest timeout configuration")
    }

    pub(crate) fn gateway_client(self) -> reqwest::Client {
        self.client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("valid reqwest timeout configuration")
    }

    fn client_builder(self) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .read_timeout(self.read_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
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
    /// Internal execution intent. Public LLM/gateway requests leave this disabled;
    /// governed native execution may opt into provider-owned breakpoint placement.
    pub prompt_cache: PromptCacheIntent,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromptCacheIntent {
    pub enabled: bool,
    /// Messages before this index are stable conversation history. The
    /// remaining messages contain current, governed request context.
    pub cacheable_message_count: usize,
}

#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub stop_reason: String,
    pub cache_read_input_tokens: i32,
    pub cache_creation_input_tokens: i32,
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
    pub cache_read_input_tokens: i32,
    pub cache_creation_input_tokens: i32,
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
            cache_read_input_tokens: resp.cache_read_input_tokens,
            cache_creation_input_tokens: resp.cache_creation_input_tokens,
        }
    }
}

pub type ChatStream = Pin<Box<dyn Stream<Item = Result<ChatStreamChunk, String>> + Send>>;

#[derive(Debug)]
pub enum ProviderError {
    Precondition(String),
    Unavailable(String),
    Upstream(String),
}

const PRECONDITION_ERROR_PREFIX: &str = "chisei-provider-error:precondition:";
const UNAVAILABLE_ERROR_PREFIX: &str = "chisei-provider-error:unavailable:";

pub(crate) fn encode_provider_error(error: ProviderError) -> String {
    match error {
        ProviderError::Precondition(message) => format!("{PRECONDITION_ERROR_PREFIX}{message}"),
        ProviderError::Unavailable(message) => format!("{UNAVAILABLE_ERROR_PREFIX}{message}"),
        ProviderError::Upstream(message) => message,
    }
}

pub(crate) fn decode_provider_error(error: String) -> ProviderError {
    if let Some(message) = error.strip_prefix(PRECONDITION_ERROR_PREFIX) {
        ProviderError::Precondition(message.to_string())
    } else if let Some(message) = error.strip_prefix(UNAVAILABLE_ERROR_PREFIX) {
        ProviderError::Unavailable(message.to_string())
    } else {
        ProviderError::Upstream(error)
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Precondition(message) | Self::Unavailable(message) | Self::Upstream(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<String> for ProviderError {
    fn from(message: String) -> Self {
        Self::Upstream(message)
    }
}

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

struct ResolvedModelProvider {
    inner: Box<dyn Provider>,
    upstream_model: String,
    canonical_model: String,
    registry_state_path: Option<std::path::PathBuf>,
}

#[async_trait::async_trait]
impl Provider for ResolvedModelProvider {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String> {
        self.enforce_current_capabilities(req, false)
            .await
            .map_err(encode_provider_error)?;
        let mut request = req.clone();
        request.model.clone_from(&self.upstream_model);
        self.inner.chat(&request).await
    }

    async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, String> {
        self.enforce_current_capabilities(req, true)
            .await
            .map_err(encode_provider_error)?;
        let mut request = req.clone();
        request.model.clone_from(&self.upstream_model);
        self.inner.chat_stream(&request).await
    }
}

impl ResolvedModelProvider {
    async fn enforce_current_capabilities(
        &self,
        request: &ChatRequest,
        streaming: bool,
    ) -> Result<(), ProviderError> {
        let registry =
            crate::provider_resolution::snapshot_for_execution(self.registry_state_path.as_deref())
                .await
                .map_err(ProviderError::Unavailable)?;
        let resolved = registry
            .resolve_model(&self.canonical_model)
            .map_err(ProviderError::Precondition)?;
        let capabilities = registry
            .effective_profile(&resolved.provider)
            .ok_or_else(|| {
                ProviderError::Precondition(format!(
                    "provider profile {:?} is not registered",
                    resolved.provider
                ))
            })?
            .capabilities;
        enforce_chat_capabilities(request, streaming, &capabilities)
            .map_err(ProviderError::Precondition)
    }
}

fn enforce_chat_capabilities(
    request: &ChatRequest,
    streaming: bool,
    capabilities: &crate::provider_profile::ProviderCapabilities,
) -> Result<(), String> {
    let requirements = crate::provider_profile::CapabilityRequirements {
        streaming,
        tools: !request.tools.is_empty()
            || request
                .messages
                .iter()
                .any(|message| !message.tool_calls.is_empty() || !message.tool_call_id.is_empty()),
        modalities: vec!["text".into()],
        max_output_tokens: (request.max_tokens > 0).then_some(request.max_tokens as u64),
        ..Default::default()
    };
    if streaming && !request.tools.is_empty() {
        return Err(
            "provider adapter cannot preserve tool calls in streaming responses".to_string(),
        );
    }
    let missing = requirements.unsupported_by(capabilities);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "provider cannot preserve required capabilities: {}",
            missing.join(", ")
        ))
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
    let registry = crate::provider_profile::provider_registry_snapshot();
    resolve_with_registry(
        model,
        &registry,
        None,
        anthropic_key,
        openai_key,
        ollama_url,
        native_url,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_with_registry(
    model: &str,
    registry: &crate::provider_profile::ProviderRegistry,
    registry_state_path: Option<&std::path::Path>,
    anthropic_key: Option<&str>,
    openai_key: Option<&str>,
    ollama_url: &str,
    native_url: Option<&str>,
) -> Result<Box<dyn Provider>, String> {
    let resolved = registry.resolve_model(model)?;
    let inner: Box<dyn Provider> = match resolved.provider.as_str() {
        "anthropic" => {
            let key = anthropic_key.ok_or("ANTHROPIC_API_KEY not set")?;
            Box::new(anthropic::Anthropic::new(key))
        }
        "openai" => {
            let key = openai_key.ok_or("OPENAI_API_KEY not set")?;
            Box::new(openai::OpenAI::new(key, None))
        }
        "ollama" => Box::new(openai::OpenAI::new("", Some(ollama_url))),
        "native" => {
            let url = native_url
                .ok_or_else(|| format!("NATIVE_LLM_URL not set for model {:?}", model))?;
            Box::new(openai::OpenAI::new("", Some(url)))
        }
        "xai" | "meta" => {
            let profile = registry
                .effective_profile(&resolved.provider)
                .ok_or_else(|| {
                    format!("provider profile {:?} is unavailable", resolved.provider)
                })?;
            let base_url = std::env::var(&profile.endpoint.base_url_env)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or(profile.endpoint.default_base_url)
                .ok_or_else(|| {
                    format!(
                        "{} not set for provider {:?}",
                        profile.endpoint.base_url_env, resolved.provider
                    )
                })?;
            let key_env = profile
                .endpoint
                .api_key_env
                .ok_or_else(|| format!("provider {:?} has no API key source", resolved.provider))?;
            let key = std::env::var(&key_env)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{key_env} not set"))?;
            let api_root = openai_compatible_api_root(&base_url);
            Box::new(openai::OpenAI::new(&key, Some(api_root)))
        }
        provider => return Err(format!("unsupported provider {provider:?}")),
    };
    Ok(Box::new(ResolvedModelProvider {
        inner,
        upstream_model: resolved.upstream_model,
        canonical_model: resolved.canonical_model,
        registry_state_path: registry_state_path.map(std::path::Path::to_path_buf),
    }))
}

fn openai_compatible_api_root(base_url: &str) -> &str {
    let base_url = base_url.trim_end_matches('/');
    base_url.strip_suffix("/v1").unwrap_or(base_url)
}

pub fn provider_name(model: &str) -> &'static str {
    match crate::provider_resolution::provider_id(model).as_deref() {
        Ok("anthropic") => "anthropic",
        Ok("openai") => "openai",
        Ok("ollama") => "ollama",
        Ok("native") => "native",
        Ok("xai") => "xai",
        Ok("meta") => "meta",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn hosted_openai_compatible_urls_use_an_api_root() {
        assert_eq!(
            openai_compatible_api_root("https://api.x.ai/v1"),
            "https://api.x.ai"
        );
        assert_eq!(
            openai_compatible_api_root("https://example.test/v1/"),
            "https://example.test"
        );
        assert_eq!(
            openai_compatible_api_root("https://example.test/openai"),
            "https://example.test/openai"
        );
    }

    struct CapturingProvider(Arc<Mutex<String>>);

    #[async_trait::async_trait]
    impl Provider for CapturingProvider {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, String> {
            *self.0.lock().unwrap() = request.model.clone();
            Ok(ChatResponse {
                content: String::new(),
                tool_calls: Vec::new(),
                input_tokens: 0,
                output_tokens: 0,
                stop_reason: "stop".into(),
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            })
        }
    }

    #[tokio::test]
    async fn resolved_provider_strips_canonical_namespace_before_upstream() {
        let captured = Arc::new(Mutex::new(String::new()));
        let provider = ResolvedModelProvider {
            inner: Box::new(CapturingProvider(captured.clone())),
            upstream_model: "gpt-5.5".into(),
            canonical_model: "openai/gpt-5.5".into(),
            registry_state_path: None,
        };
        provider
            .chat(&ChatRequest {
                model: "openai/gpt-5.5".into(),
                system: String::new(),
                messages: Vec::new(),
                tools: Vec::new(),
                max_tokens: 1,
                prompt_cache: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(*captured.lock().unwrap(), "gpt-5.5");
    }

    #[tokio::test]
    async fn resolved_provider_blocks_disabled_tools_before_contact() {
        let captured = Arc::new(Mutex::new(String::new()));
        let provider = ResolvedModelProvider {
            inner: Box::new(CapturingProvider(captured.clone())),
            upstream_model: "mistral".into(),
            canonical_model: "native/mistral".into(),
            registry_state_path: None,
        };
        let error = provider
            .chat(&ChatRequest {
                model: "native/mistral".into(),
                system: String::new(),
                messages: Vec::new(),
                tools: vec![ToolDef {
                    name: "read".into(),
                    description: String::new(),
                    input_schema: serde_json::json!({"type":"object"}),
                }],
                max_tokens: 1,
                prompt_cache: Default::default(),
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("tools"));
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolved_provider_blocks_streaming_tools_before_contact() {
        let captured = Arc::new(Mutex::new(String::new()));
        let provider = ResolvedModelProvider {
            inner: Box::new(CapturingProvider(captured.clone())),
            upstream_model: "gpt-5.5".into(),
            canonical_model: "openai/gpt-5.5".into(),
            registry_state_path: None,
        };
        let result = provider
            .chat_stream(&ChatRequest {
                model: "openai/gpt-5.5".into(),
                system: String::new(),
                messages: Vec::new(),
                tools: vec![ToolDef {
                    name: "read".into(),
                    description: String::new(),
                    input_schema: serde_json::json!({"type":"object"}),
                }],
                max_tokens: 1,
                prompt_cache: Default::default(),
            })
            .await;
        let error = match result {
            Ok(_) => panic!("streaming tool call reached the provider"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("tool calls"));
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn streaming_tool_history_does_not_request_new_tool_emission() {
        let request = ChatRequest {
            model: "openai/gpt-5.5".into(),
            system: String::new(),
            messages: vec![Message {
                role: "tool".into(),
                content: "done".into(),
                tool_call_id: "call_1".into(),
                tool_calls: Vec::new(),
            }],
            tools: Vec::new(),
            max_tokens: 1,
            prompt_cache: Default::default(),
        };
        let capabilities = crate::provider_profile::ProviderRegistry::built_in()
            .profile("openai")
            .unwrap()
            .capabilities
            .clone();

        assert!(enforce_chat_capabilities(&request, true, &capabilities).is_ok());
    }

    #[tokio::test]
    async fn resolved_provider_refreshes_registry_before_contact() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-direct-provider-registry-refresh-{}",
            uuid::Uuid::new_v4()
        ));
        let registry_path = directory.join("registry.json");
        crate::provider_profile::refresh_provider_registry(&registry_path).unwrap();
        std::fs::remove_file(&registry_path).unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let provider = ResolvedModelProvider {
            inner: Box::new(CapturingProvider(captured.clone())),
            upstream_model: "gpt-5.5".into(),
            canonical_model: "openai/gpt-5.5".into(),
            registry_state_path: Some(registry_path),
        };

        let error = provider
            .chat(&ChatRequest {
                model: "openai/gpt-5.5".into(),
                system: String::new(),
                messages: Vec::new(),
                tools: Vec::new(),
                max_tokens: 1,
                prompt_cache: Default::default(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            decode_provider_error(error),
            ProviderError::Unavailable(_)
        ));
        assert!(captured.lock().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_name_uses_registry_namespace_rules() {
        assert_eq!(provider_name("openai/gpt-5.5"), "openai");
        assert_eq!(provider_name("anthropic/claude-sonnet-4"), "anthropic");
        assert_eq!(provider_name("native/mistral"), "native");
        assert_eq!(provider_name("Kiro"), "unknown");
        assert_eq!(provider_name("unknown/model"), "unknown");
    }
}
