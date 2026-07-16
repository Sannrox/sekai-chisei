//! Provider-neutral capability contracts used before gateway upstream contact.

use serde::{Deserialize, Serialize};

pub const CAPABILITY_MATRIX_VERSION: &str = "chisei.provider-capabilities/v1";

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
}

impl CapabilityMatrix {
    pub fn built_in() -> Self {
        Self {
            version: CAPABILITY_MATRIX_VERSION.into(),
            paths: vec![
                path(
                    "openai",
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
                path(
                    "ollama",
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
                path(
                    "native",
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
                path(
                    "anthropic",
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

    pub fn capabilities(&self, provider: &str) -> Option<&ProviderCapabilities> {
        self.paths
            .iter()
            .find(|path| path.provider == provider)
            .map(|path| &path.capabilities)
    }
}

fn path(provider: &str, capabilities: ProviderCapabilities) -> CapabilityPath {
    CapabilityPath {
        provider: provider.into(),
        profile_version: format!("{provider}.builtin/v1"),
        lifecycle: "enabled".into(),
        capabilities,
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
        Ok(Self {
            responses: true,
            streaming: value
                .get("stream")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            tools: !tools.is_empty(),
            parallel_tools: value
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
}
