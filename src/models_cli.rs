use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::ListAvailableModelsRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use serde_json::{Value, json};

pub const USAGE: &str = "sekaictl models list [--provider <id>] [--json] [--namespace <name>] [--target <url-or-socket>]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelsListConfig {
    pub provider: Option<String>,
    pub json: bool,
    pub namespace: String,
    pub target: String,
}

impl ModelsListConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut args = args.into_iter();
        if args.next().as_deref() != Some("list") {
            return Err(USAGE.into());
        }
        let mut config = Self {
            provider: None,
            json: false,
            namespace: std::env::var("CHISEI_NAMESPACE").unwrap_or_else(|_| "default".into()),
            target: std::env::var("CHISEI_GRPC_URL")
                .or_else(|_| std::env::var("SEKAI_SOCKET"))
                .unwrap_or_else(|_| "./data/sekai.sock".into()),
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" => config.json = true,
                "--provider" => config.provider = Some(required_value(&mut args, "--provider")?),
                "--namespace" => config.namespace = required_value(&mut args, "--namespace")?,
                "--target" => config.target = required_value(&mut args, "--target")?,
                _ => return Err(format!("unknown models option {arg:?}\n{USAGE}")),
            }
        }
        if config.namespace.trim().is_empty() {
            return Err("namespace must not be empty".into());
        }
        Ok(config)
    }
}

fn required_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{option} requires a value"))
}

pub async fn run_models_list(
    config: ModelsListConfig,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.target).await?;
    let response = ChiseiServiceClient::new(channel)
        .list_available_models(ListAvailableModelsRequest {
            namespace: config.namespace,
            provider: config.provider.unwrap_or_default(),
        })
        .await?
        .into_inner();
    Ok(render_models(&response, config.json))
}

pub fn render_models(
    response: &crate::grpc::pb::chisei::ListAvailableModelsResponse,
    as_json: bool,
) -> String {
    if as_json {
        let models = response
            .models
            .iter()
            .map(|model| {
                json!({
                    "provider": model.provider,
                    "upstream_model": model.upstream_model,
                    "canonical_model": model.canonical_model,
                    "lifecycle": model.lifecycle,
                    "capabilities": model.capabilities.as_ref().map(capabilities_json),
                    "pricing": model.pricing.as_ref().map(|pricing| json!({
                        "version": pricing.version,
                        "source": pricing.source,
                        "observed_at": pricing.observed_at,
                        "dimensions": pricing.dimensions,
                    })),
                })
            })
            .collect::<Vec<_>>();
        return serde_json::to_string_pretty(&json!({
            "version": response.version,
            "namespace": response.namespace,
            "models": models,
        }))
        .expect("available models response is serializable");
    }
    let mut output = "PROVIDER\tCANONICAL MODEL\tLIFECYCLE\tCAPABILITIES\tPRICING\n".to_string();
    for model in &response.models {
        let capabilities = model
            .capabilities
            .as_ref()
            .map_or_else(|| "-".into(), |value| value.modalities.join(","));
        let pricing = model
            .pricing
            .as_ref()
            .map_or("-", |value| value.version.as_str());
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            model.provider, model.canonical_model, model.lifecycle, capabilities, pricing
        ));
    }
    output
}

fn capabilities_json(value: &crate::grpc::pb::chisei::AvailableModelCapabilities) -> Value {
    json!({
        "responses": value.responses, "streaming": value.streaming, "tools": value.tools,
        "parallel_tools": value.parallel_tools, "structured_output": value.structured_output,
        "reasoning_controls": value.reasoning_controls, "modalities": value.modalities,
        "provider_continuation": value.provider_continuation, "reports_usage": value.reports_usage,
        "partial_usage": value.partial_usage, "context_tokens": value.context_tokens,
        "output_tokens": value.output_tokens, "built_in_tools": value.built_in_tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::chisei::{AvailableModelRecord, ListAvailableModelsResponse};

    #[test]
    fn parses_provider_and_json_options() {
        let config = ModelsListConfig::from_args(
            ["list", "--provider", "openai", "--json"].map(str::to_string),
        )
        .unwrap();
        assert_eq!(config.provider.as_deref(), Some("openai"));
        assert!(config.json);
    }

    #[test]
    fn renders_table_and_structured_json() {
        let response = ListAvailableModelsResponse {
            version: "chisei.available-models/v1".into(),
            namespace: "acme".into(),
            models: vec![AvailableModelRecord {
                provider: "openai".into(),
                upstream_model: "gpt-x".into(),
                canonical_model: "openai/gpt-x".into(),
                lifecycle: "enabled".into(),
                capabilities: None,
                pricing: None,
            }],
        };
        assert!(render_models(&response, false).contains("openai\topenai/gpt-x\tenabled"));
        let json: Value = serde_json::from_str(&render_models(&response, true)).unwrap();
        assert_eq!(json["models"][0]["canonical_model"], "openai/gpt-x");
    }
}
