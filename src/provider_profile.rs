//! Provider-neutral capability contracts used before gateway upstream contact.

use serde::{Deserialize, Serialize};

pub const CAPABILITY_MATRIX_VERSION: &str = "chisei.provider-capabilities/v1";
pub const PROVIDER_REGISTRY_VERSION: &str = "chisei.provider-registry/v2";
pub const RESPONSES_REQUEST_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "max_output_tokens",
    "stream",
    "metadata",
    "previous_response_id",
    "reasoning",
    "text",
    "temperature",
    "top_p",
    "truncation",
    "store",
];

pub fn normalize_responses_request(body: &[u8]) -> Result<Vec<u8>, String> {
    validate_responses_request_fields(body)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Responses request must be a JSON object".to_string())?;
    if object
        .get("store")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err("Responses store must be false".into());
    }
    object.insert("store".into(), serde_json::Value::Bool(false));
    serde_json::to_vec(&value).map_err(|error| error.to_string())
}

pub fn validate_responses_request_fields(body: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Responses request must be a JSON object".to_string())?;
    let mut unsupported = object
        .keys()
        .filter(|field| !RESPONSES_REQUEST_FIELDS.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unsupported.sort();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(format!(
        "unsupported Responses request fields: {}",
        unsupported.join(", ")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub responses: bool,
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub structured_output: bool,
    pub reasoning_controls: bool,
    pub modalities: Vec<String>,
    pub provider_continuation: bool,
    pub reports_usage: bool,
    pub partial_usage: bool,
    pub context_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub built_in_tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEndpointProfile {
    pub base_url_env: String,
    pub default_base_url: Option<String>,
    pub api_key_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageNormalizationProfile {
    pub version: String,
    pub input_tokens: bool,
    pub output_tokens: bool,
    pub reasoning_tokens: bool,
    pub cache_read_tokens: bool,
    pub cache_write_tokens: bool,
    pub partial_responses: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingProfile {
    pub version: String,
    pub source: String,
    pub observed_at: Option<String>,
    #[serde(default)]
    pub dimensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGovernanceProfile {
    pub metadata_status: String,
    pub data_retention: Option<String>,
    pub training_use: Option<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    pub zero_data_retention_eligible: Option<bool>,
    pub contractual_status: Option<String>,
    pub terms_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub provider: String,
    pub profile_version: String,
    pub lifecycle: String,
    pub transport: String,
    pub model_namespace: Option<String>,
    pub accepted_model_patterns: Vec<String>,
    #[serde(default)]
    pub excluded_model_prefixes: Vec<String>,
    pub endpoint: ProviderEndpointProfile,
    pub protocol_surfaces: Vec<String>,
    #[serde(default)]
    pub request_adaptations: Vec<String>,
    #[serde(default)]
    pub response_adaptations: Vec<String>,
    pub capabilities: ProviderCapabilities,
    pub usage_normalization: UsageNormalizationProfile,
    pub error_normalization_version: String,
    pub pricing: PricingProfile,
    pub governance: ProviderGovernanceProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistry {
    pub version: String,
    pub profiles: Vec<ProviderProfile>,
}

impl ProviderRegistry {
    pub fn built_in() -> Self {
        Self {
            version: PROVIDER_REGISTRY_VERSION.into(),
            profiles: vec![
                profile(
                    "openai",
                    "openai-compatible",
                    None,
                    "CHISEI_OPENAI_BASE_URL",
                    Some("https://api.openai.com/v1"),
                    Some("OPENAI_API_KEY"),
                    &["responses", "chat_completions", "models"],
                    &[],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: true,
                        parallel_tools: true,
                        structured_output: true,
                        reasoning_controls: true,
                        modalities: vec!["text".into(), "image".into()],
                        provider_continuation: true,
                        reports_usage: true,
                        partial_usage: true,
                        context_tokens: 400_000,
                        output_tokens: 128_000,
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "ollama",
                    "openai-compatible",
                    Some("ollama/"),
                    "CHISEI_OLLAMA_BASE_URL",
                    Some("http://127.0.0.1:11434/v1"),
                    None,
                    &["responses", "chat_completions", "models"],
                    &["strip_model_namespace"],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: true,
                        parallel_tools: false,
                        structured_output: true,
                        reasoning_controls: false,
                        modalities: vec!["text".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: false,
                        context_tokens: 128_000,
                        output_tokens: 32_000,
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "native",
                    "openai-compatible",
                    None,
                    "NATIVE_LLM_URL",
                    None,
                    None,
                    &["responses", "chat_completions"],
                    &[],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: false,
                        parallel_tools: false,
                        structured_output: false,
                        reasoning_controls: false,
                        modalities: vec!["text".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: false,
                        context_tokens: 128_000,
                        output_tokens: 32_000,
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "anthropic",
                    "anthropic-messages",
                    None,
                    "CHISEI_ANTHROPIC_BASE_URL",
                    Some("https://api.anthropic.com/v1"),
                    Some("ANTHROPIC_API_KEY"),
                    &["messages", "count_tokens"],
                    &[],
                    ProviderCapabilities {
                        responses: false,
                        streaming: true,
                        tools: true,
                        parallel_tools: true,
                        structured_output: true,
                        reasoning_controls: true,
                        modalities: vec!["text".into(), "image".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: true,
                        context_tokens: 200_000,
                        output_tokens: 64_000,
                        built_in_tools: vec![],
                    },
                ),
            ],
        }
    }

    pub fn profile(&self, provider: &str) -> Option<&ProviderProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.provider == provider)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPath {
    pub provider: String,
    pub profile_version: String,
    pub lifecycle: String,
    pub capabilities: ProviderCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    pub version: String,
    pub paths: Vec<CapabilityPath>,
    pub registry_version: String,
    pub profiles: Vec<ProviderProfile>,
}

impl CapabilityMatrix {
    pub fn built_in() -> Self {
        let registry = ProviderRegistry::built_in();
        let paths = registry
            .profiles
            .iter()
            .map(|profile| CapabilityPath {
                provider: profile.provider.clone(),
                profile_version: profile.profile_version.clone(),
                lifecycle: profile.lifecycle.clone(),
                capabilities: profile.capabilities.clone(),
            })
            .collect();
        Self {
            version: CAPABILITY_MATRIX_VERSION.into(),
            paths,
            registry_version: registry.version,
            profiles: registry.profiles,
        }
    }

    pub fn capabilities(&self, provider: &str) -> Option<&ProviderCapabilities> {
        self.paths
            .iter()
            .find(|path| path.provider == provider)
            .map(|path| &path.capabilities)
    }
}

fn profile(
    provider: &str,
    transport: &str,
    model_namespace: Option<&str>,
    base_url_env: &str,
    default_base_url: Option<&str>,
    api_key_env: Option<&str>,
    protocol_surfaces: &[&str],
    request_adaptations: &[&str],
    capabilities: ProviderCapabilities,
) -> ProviderProfile {
    let reports_reasoning = capabilities.reasoning_controls;
    let reports_partial = capabilities.partial_usage;
    let reports_cache_reads = matches!(provider, "openai" | "anthropic");
    let reports_cache_writes = provider == "anthropic";
    let accepted_model_patterns = match provider {
        "openai" => vec!["*".into()],
        "ollama" => vec!["ollama/*".into()],
        "anthropic" => vec!["claude*".into()],
        _ => vec!["fallback:*".into()],
    };
    let excluded_model_prefixes = if provider == "openai" {
        [
            "claude",
            "gemini",
            "vertex",
            "palm",
            "bedrock",
            "anthropic",
            "azure",
            "cohere",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    };
    ProviderProfile {
        provider: provider.into(),
        profile_version: format!("{provider}.builtin/v2"),
        lifecycle: "enabled".into(),
        transport: transport.into(),
        model_namespace: model_namespace.map(str::to_string),
        accepted_model_patterns,
        excluded_model_prefixes,
        endpoint: ProviderEndpointProfile {
            base_url_env: base_url_env.into(),
            default_base_url: default_base_url.map(str::to_string),
            api_key_env: api_key_env.map(str::to_string),
        },
        protocol_surfaces: protocol_surfaces
            .iter()
            .map(|value| (*value).into())
            .collect(),
        request_adaptations: request_adaptations
            .iter()
            .map(|value| (*value).into())
            .collect(),
        response_adaptations: Vec::new(),
        capabilities,
        usage_normalization: UsageNormalizationProfile {
            version: "chisei.usage-normalization/v1".into(),
            input_tokens: true,
            output_tokens: true,
            reasoning_tokens: reports_reasoning,
            cache_read_tokens: reports_cache_reads,
            cache_write_tokens: reports_cache_writes,
            partial_responses: reports_partial,
        },
        error_normalization_version: "chisei.gateway-errors/v1".into(),
        pricing: PricingProfile {
            version: format!("{provider}.unpriced/v1"),
            source: "unconfigured".into(),
            observed_at: None,
            dimensions: Vec::new(),
        },
        governance: ProviderGovernanceProfile {
            metadata_status: "unknown".into(),
            data_retention: None,
            training_use: None,
            regions: Vec::new(),
            zero_data_retention_eligible: None,
            contractual_status: None,
            terms_version: None,
        },
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityRequirements {
    pub responses: bool,
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub structured_output: bool,
    pub reasoning_controls: bool,
    pub modalities: Vec<String>,
    pub provider_continuation: bool,
    pub built_in_tools: Vec<String>,
    pub max_output_tokens: Option<u64>,
}

impl CapabilityRequirements {
    pub fn from_responses_body(body: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
        let tools = value
            .get("tools")
            .and_then(|tools| tools.as_array())
            .cloned()
            .unwrap_or_default();
        let has_tool_outputs = value.get("input").is_some_and(contains_tool_call_output);
        let built_in_tools = tools
            .iter()
            .filter_map(|tool| tool.get("type").and_then(|value| value.as_str()))
            .filter(|kind| !matches!(*kind, "function" | "custom"))
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut modalities = vec!["text".to_string()];
        collect_modalities(&value, &mut modalities);
        modalities.sort();
        modalities.dedup();
        let max_output_tokens = match value.get("max_output_tokens") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .ok_or_else(|| "max_output_tokens must be an unsigned integer".to_string())?,
            ),
        };
        Ok(Self {
            responses: true,
            streaming: value
                .get("stream")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            tools: !tools.is_empty() || has_tool_outputs,
            parallel_tools: !tools.is_empty()
                && value
                    .get("parallel_tool_calls")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
            structured_output: requires_structured_output(&value),
            reasoning_controls: value.get("reasoning").is_some(),
            provider_continuation: value
                .get("previous_response_id")
                .is_some_and(|value| !value.is_null()),
            modalities,
            built_in_tools,
            max_output_tokens,
        })
    }

    pub fn unsupported_by(&self, capabilities: &ProviderCapabilities) -> Vec<String> {
        let mut missing = Vec::new();
        for (required, supported, name) in [
            (self.responses, capabilities.responses, "responses"),
            (self.streaming, capabilities.streaming, "streaming"),
            (self.tools, capabilities.tools, "tools"),
            (
                self.parallel_tools,
                capabilities.parallel_tools,
                "parallel_tools",
            ),
            (
                self.structured_output,
                capabilities.structured_output,
                "structured_output",
            ),
            (
                self.reasoning_controls,
                capabilities.reasoning_controls,
                "reasoning_controls",
            ),
            (
                self.provider_continuation,
                capabilities.provider_continuation,
                "provider_continuation",
            ),
        ] {
            if required && !supported {
                missing.push(name.to_string());
            }
        }
        for modality in &self.modalities {
            if !capabilities.modalities.contains(modality) {
                missing.push(format!("modality:{modality}"));
            }
        }
        for tool in &self.built_in_tools {
            if !capabilities.built_in_tools.contains(tool) {
                missing.push(format!("built_in_tool:{tool}"));
            }
        }
        if let Some(requested) = self.max_output_tokens
            && requested > capabilities.output_tokens
        {
            missing.push(format!(
                "max_output_tokens:{requested}>{}",
                capabilities.output_tokens
            ));
        }
        missing
    }
}

fn requires_structured_output(value: &serde_json::Value) -> bool {
    [value.pointer("/text/format"), value.get("response_format")]
        .into_iter()
        .flatten()
        .any(|format| {
            format
                .get("type")
                .and_then(|value| value.as_str())
                .is_none_or(|kind| kind != "text")
        })
}

fn collect_modalities(value: &serde_json::Value, modalities: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_modalities(value, modalities);
            }
        }
        serde_json::Value::Object(values) => {
            if let Some(kind) = values.get("type").and_then(|value| value.as_str()) {
                match kind {
                    "input_image" | "image_url" => modalities.push("image".into()),
                    "input_audio" | "audio" => modalities.push("audio".into()),
                    _ => {}
                }
            }
            for value in values.values() {
                collect_modalities(value, modalities);
            }
        }
        _ => {}
    }
}

fn contains_tool_call_output(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(contains_tool_call_output),
        serde_json::Value::Object(values) => {
            values
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind.ends_with("_call_output"))
                || values.values().any(contains_tool_call_output)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_required_capabilities_from_responses_requests() {
        let body = br#"{
            "stream": true,
            "parallel_tool_calls": true,
            "previous_response_id": "resp_1",
            "reasoning": {"effort":"high"},
            "text": {"format":{"type":"json_schema"}},
            "tools":[{"type":"function"},{"type":"web_search"}],
            "input":[{"role":"user","content":[{"type":"input_image"}]}]
        }"#;
        let required = CapabilityRequirements::from_responses_body(body).unwrap();
        assert!(required.streaming);
        assert!(required.parallel_tools);
        assert!(required.provider_continuation);
        assert!(required.structured_output);
        assert_eq!(required.modalities, vec!["image", "text"]);
        assert_eq!(required.built_in_tools, vec!["web_search"]);
    }

    #[test]
    fn built_in_profiles_publish_versioned_isolated_endpoints() {
        let registry = ProviderRegistry::built_in();
        assert_eq!(registry.version, PROVIDER_REGISTRY_VERSION);
        let openai = registry.profile("openai").unwrap();
        let ollama = registry.profile("ollama").unwrap();
        let anthropic = registry.profile("anthropic").unwrap();
        assert_eq!(
            openai.endpoint.api_key_env.as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            anthropic.endpoint.api_key_env.as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(ollama.endpoint.api_key_env, None);
        assert_ne!(openai.endpoint.base_url_env, ollama.endpoint.base_url_env);
        assert_ne!(openai.profile_version, anthropic.profile_version);
        assert_eq!(openai.model_namespace, None);
        assert_eq!(ollama.model_namespace.as_deref(), Some("ollama/"));
        assert_eq!(openai.accepted_model_patterns, vec!["*"]);
        assert!(
            openai
                .excluded_model_prefixes
                .contains(&"anthropic".to_string())
        );
        assert!(openai.usage_normalization.cache_read_tokens);
        assert!(openai.protocol_surfaces.contains(&"responses".to_string()));
        assert!(
            anthropic
                .protocol_surfaces
                .contains(&"messages".to_string())
        );
    }

    #[test]
    fn capability_matrix_is_derived_from_the_profile_registry() {
        let matrix = CapabilityMatrix::built_in();
        assert_eq!(matrix.registry_version, PROVIDER_REGISTRY_VERSION);
        assert_eq!(matrix.paths.len(), matrix.profiles.len());
        for profile in &matrix.profiles {
            assert_eq!(
                matrix.capabilities(&profile.provider),
                Some(&profile.capabilities)
            );
        }
    }

    #[test]
    fn rejects_capability_downgrades_before_routing() {
        let matrix = CapabilityMatrix::built_in();
        let required = CapabilityRequirements {
            responses: true,
            streaming: true,
            tools: true,
            parallel_tools: true,
            modalities: vec!["text".into()],
            ..Default::default()
        };
        assert!(
            required
                .unsupported_by(matrix.capabilities("openai").unwrap())
                .is_empty()
        );
        assert_eq!(
            required.unsupported_by(matrix.capabilities("ollama").unwrap()),
            vec!["parallel_tools"]
        );
        assert!(
            required
                .unsupported_by(matrix.capabilities("anthropic").unwrap())
                .contains(&"responses".to_string())
        );
    }

    #[test]
    fn plain_text_format_does_not_require_structured_output() {
        let required =
            CapabilityRequirements::from_responses_body(br#"{"text":{"format":{"type":"text"}}}"#)
                .unwrap();
        assert!(!required.structured_output);
        let required = CapabilityRequirements::from_responses_body(
            br#"{"text":{"format":{"type":"json_schema"}}}"#,
        )
        .unwrap();
        assert!(required.structured_output);
    }

    #[test]
    fn parallel_flag_without_tools_is_not_a_requirement() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"parallel_tool_calls":true,"input":"hello"}"#,
        )
        .unwrap();
        assert!(!required.tools);
        assert!(!required.parallel_tools);
        let matrix = CapabilityMatrix::built_in();
        assert!(
            required
                .unsupported_by(matrix.capabilities("ollama").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn tool_outputs_require_tool_capability_without_new_schemas() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"input":[{"type":"function_call_output","call_id":"call_1","output":"ok"}]}"#,
        )
        .unwrap();
        assert!(required.tools);
        assert_eq!(
            required.unsupported_by(CapabilityMatrix::built_in().capabilities("native").unwrap()),
            vec!["tools"]
        );
    }

    #[test]
    fn output_limits_are_enforced_before_provider_contact() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"max_output_tokens":64000,"input":"hello"}"#,
        )
        .unwrap();
        let matrix = CapabilityMatrix::built_in();
        assert!(
            required
                .unsupported_by(matrix.capabilities("ollama").unwrap())
                .contains(&"max_output_tokens:64000>32000".to_string())
        );
        assert!(
            required
                .unsupported_by(matrix.capabilities("openai").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn non_integer_output_limits_are_rejected() {
        for body in [
            br#"{"max_output_tokens":64000.0}"#.as_slice(),
            br#"{"max_output_tokens":6.4e4}"#.as_slice(),
            br#"{"max_output_tokens":-1}"#.as_slice(),
            br#"{"max_output_tokens":"64000"}"#.as_slice(),
        ] {
            assert_eq!(
                CapabilityRequirements::from_responses_body(body),
                Err("max_output_tokens must be an unsigned integer".to_string())
            );
        }
    }

    #[test]
    fn request_field_allowlist_blocks_retention_and_provider_extensions() {
        assert!(
            validate_responses_request_fields(
                br#"{"model":"gpt-5.5","input":"hi","service_tier":"flex"}"#
            )
            .unwrap_err()
            .contains("service_tier")
        );
        assert!(
            validate_responses_request_fields(
                br#"{"model":"gpt-5.5","input":"hi","stream":true,"reasoning":{"effort":"high"}}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn responses_requests_are_forced_to_disable_provider_storage() {
        let normalized =
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi"}"#).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&normalized).unwrap();
        assert_eq!(value["store"], false);
        assert!(
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi","store":false}"#)
                .is_ok()
        );
        assert!(
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi","store":true}"#)
                .is_err()
        );
    }
}
