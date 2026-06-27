use crate::config::Config;
use crate::llm;
use crate::llm::ollama::InstalledModel;

#[derive(Clone)]
pub struct RoutingContext<'a> {
    pub requested: &'a str,
    pub allowed_models: &'a [String],
    pub route_bias: Option<&'a str>,
    pub config: &'a Config,
    pub ollama_models: &'a [InstalledModel],
}

#[derive(Clone)]
struct Candidate {
    model: String,
    cost_rank: i32,
    capability_rank: i32,
}

pub fn route_bias(steps: &[crate::chisei::pipeline::StepDecision]) -> Option<&str> {
    steps
        .iter()
        .find(|step| step.step == "complexity_route" && step.action == "recommend")
        .and_then(|step| match step.value.as_str() {
            "cheap" => Some("cheap"),
            "capable" => Some("capable"),
            _ => None,
        })
}

pub fn resolve_model(ctx: RoutingContext<'_>) -> Result<String, String> {
    if ctx.requested.is_empty() {
        return Err("model resolution received an empty model".into());
    }

    if let Some((provider, alias)) = alias_parts(ctx.requested) {
        let candidates = candidate_pool(&ctx);
        let candidate = choose_candidate(provider, alias, &candidates)?;
        return Ok(candidate.model.clone());
    }

    if let Some(name) = exact_available_ollama_name(ctx.requested, ctx.ollama_models) {
        return Ok(format!("ollama/{name}"));
    }

    if let Some(name) = ctx.requested.strip_prefix("ollama/") {
        if has_available_model(name, ctx.ollama_models) {
            return Ok(ctx.requested.to_string());
        }
        let fallback_alias = ctx.route_bias.unwrap_or("capable");
        let candidates = candidate_pool(&ctx);
        let candidate =
            choose_candidate(Some("ollama"), fallback_alias, &candidates).map_err(|_| {
                missing_model_message(ctx.requested, ctx.ollama_models, ctx.allowed_models)
            })?;
        return Ok(candidate.model.clone());
    }

    validate_or_fallback_provider_model(ctx)
}

fn validate_or_fallback_provider_model(ctx: RoutingContext<'_>) -> Result<String, String> {
    let provider = llm::provider_name(ctx.requested);
    if provider_is_available(provider, ctx.config) {
        return Ok(ctx.requested.to_string());
    }

    let fallback_alias = ctx.route_bias.unwrap_or("capable");
    let candidates = candidate_pool(&ctx);
    let candidate = choose_candidate(None, fallback_alias, &candidates).map_err(|_| {
        format!(
            "provider {provider:?} is not configured for model {:?}",
            ctx.requested
        )
    })?;
    Ok(candidate.model.clone())
}

fn candidate_pool(ctx: &RoutingContext<'_>) -> Vec<Candidate> {
    let exact_allowed: Vec<String> = ctx
        .allowed_models
        .iter()
        .filter(|model| alias_parts(model).is_none())
        .cloned()
        .collect();
    let alias_allowed = ctx
        .allowed_models
        .iter()
        .any(|model| alias_parts(model).is_some());

    let base_models = if exact_allowed.is_empty() && !alias_allowed {
        discover_default_candidates(ctx)
    } else {
        exact_allowed
    };

    let mut candidates = Vec::new();
    for model in base_models {
        if let Some(candidate) = build_candidate(&model, ctx) {
            candidates.push(candidate);
        }
    }

    if alias_allowed {
        for model in discover_default_candidates(ctx) {
            if let Some(candidate) = build_candidate(&model, ctx)
                && !candidates
                    .iter()
                    .any(|existing| existing.model == candidate.model)
            {
                candidates.push(candidate);
            }
        }
    }

    candidates
}

fn discover_default_candidates(ctx: &RoutingContext<'_>) -> Vec<String> {
    let mut models = Vec::new();
    if ctx.config.anthropic_api_key.is_some() {
        models.push("claude-sonnet-4-20250514".to_string());
    }
    if ctx.config.openai_api_key.is_some() {
        models.push("gpt-4.1-mini".to_string());
        models.push("gpt-4.1".to_string());
    }
    if ctx.config.native_llm_url.is_some() {
        models.push("native-default".to_string());
    }
    for model in ctx.ollama_models {
        models.push(format!("ollama/{}", model.name));
    }
    models
}

fn build_candidate(model: &str, ctx: &RoutingContext<'_>) -> Option<Candidate> {
    if let Some(name) = exact_available_ollama_name(model, ctx.ollama_models) {
        let installed = ctx
            .ollama_models
            .iter()
            .find(|installed| installed.name == name)?;
        return Some(Candidate {
            model: format!("ollama/{name}"),
            cost_rank: ollama_cost_rank(installed),
            capability_rank: ollama_capability_rank(installed),
        });
    }

    if let Some(name) = model.strip_prefix("ollama/") {
        let installed = ctx
            .ollama_models
            .iter()
            .find(|installed| installed.name == name)?;
        return Some(Candidate {
            model: model.to_string(),
            cost_rank: ollama_cost_rank(installed),
            capability_rank: ollama_capability_rank(installed),
        });
    }

    let provider = llm::provider_name(model);
    if !provider_is_available(provider, ctx.config) {
        return None;
    }

    Some(Candidate {
        model: model.to_string(),
        cost_rank: named_model_cost_rank(model),
        capability_rank: named_model_capability_rank(model),
    })
}

fn choose_candidate(
    provider: Option<&str>,
    alias: &str,
    candidates: &[Candidate],
) -> Result<Candidate, String> {
    let mut sorted = candidates
        .iter()
        .filter(|candidate| {
            provider.is_none_or(|provider| llm::provider_name(&candidate.model) == provider)
        })
        .cloned()
        .collect::<Vec<_>>();
    sorted.sort_by(|left, right| match alias {
        "cheap" => left
            .cost_rank
            .cmp(&right.cost_rank)
            .then_with(|| right.capability_rank.cmp(&left.capability_rank))
            .then_with(|| left.model.cmp(&right.model)),
        _ => right
            .capability_rank
            .cmp(&left.capability_rank)
            .then_with(|| left.cost_rank.cmp(&right.cost_rank))
            .then_with(|| left.model.cmp(&right.model)),
    });
    sorted
        .into_iter()
        .next()
        .ok_or_else(|| format!("no candidate available for alias {alias:?}"))
}

fn ollama_cost_rank(model: &InstalledModel) -> i32 {
    (model.parameter_size_b.unwrap_or(1000.0) * 100.0) as i32
}

fn ollama_capability_rank(model: &InstalledModel) -> i32 {
    (model.parameter_size_b.unwrap_or(0.0) * 100.0) as i32
        + model.context_length / 1024
        + if model.capabilities.iter().any(|cap| cap == "thinking") {
            20
        } else {
            0
        }
}

fn named_model_cost_rank(model: &str) -> i32 {
    let lower = model.to_ascii_lowercase();
    if lower.contains("nano") {
        1
    } else if lower.contains("mini") || lower.contains("haiku") {
        2
    } else if lower.contains("sonnet") {
        5
    } else if lower.contains("opus") || lower.starts_with("o1") {
        9
    } else {
        6
    }
}

fn named_model_capability_rank(model: &str) -> i32 {
    let lower = model.to_ascii_lowercase();
    if lower.contains("opus") || lower.starts_with("o1") {
        10
    } else if lower.contains("sonnet") || lower == "gpt-4.1" {
        8
    } else if lower.contains("mini") || lower.contains("haiku") {
        4
    } else if model == "native-default" {
        7
    } else {
        6
    }
}

fn provider_is_available(provider: &str, config: &Config) -> bool {
    match provider {
        "anthropic" => config.anthropic_api_key.is_some(),
        "openai" => config.openai_api_key.is_some(),
        "ollama" => true,
        "native" => config.native_llm_url.is_some(),
        _ => false,
    }
}

fn alias_parts(model: &str) -> Option<(Option<&str>, &str)> {
    match model {
        "cheap" | "capable" => Some((None, model)),
        "ollama/cheap" => Some((Some("ollama"), "cheap")),
        "openai/cheap" => Some((Some("openai"), "cheap")),
        "anthropic/cheap" => Some((Some("anthropic"), "cheap")),
        "native/cheap" => Some((Some("native"), "cheap")),
        "ollama/capable" => Some((Some("ollama"), "capable")),
        "openai/capable" => Some((Some("openai"), "capable")),
        "anthropic/capable" => Some((Some("anthropic"), "capable")),
        "native/capable" => Some((Some("native"), "capable")),
        _ => None,
    }
}

fn exact_available_ollama_name<'a>(
    requested: &'a str,
    available: &'a [InstalledModel],
) -> Option<&'a str> {
    available
        .iter()
        .find(|model| model.name == requested)
        .map(|model| model.name.as_str())
}

fn has_available_model(name: &str, available: &[InstalledModel]) -> bool {
    available.iter().any(|model| model.name == name)
}

fn missing_model_message(
    requested: &str,
    available: &[InstalledModel],
    allowed_models: &[String],
) -> String {
    format!(
        "requested Ollama model {requested:?} is not installed; available models: {}; allowed policy models: {}",
        display_models(available),
        display_allowed_models(allowed_models),
    )
}

fn display_models(models: &[InstalledModel]) -> String {
    if models.is_empty() {
        "none".into()
    } else {
        models
            .iter()
            .map(|model| model.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn display_allowed_models(allowed_models: &[String]) -> String {
    if allowed_models.is_empty() {
        "any".into()
    } else {
        allowed_models.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{RoutingContext, resolve_model};
    use crate::config::Config;
    use crate::llm::ollama::InstalledModel;

    fn config() -> Config {
        Config {
            grpc_port: 50051,
            db_path: ":memory:".into(),
            anthropic_api_key: Some("anthropic".into()),
            openai_api_key: Some("openai".into()),
            ollama_url: "http://localhost:11434".into(),
            native_llm_url: Some("http://localhost:1234".into()),
            auth_token: None,
            sample_rate: 0.05,
            sample_risk_threshold: 0.7,
        }
    }

    fn model(name: &str, size: f64) -> InstalledModel {
        InstalledModel {
            name: name.into(),
            parameter_size_b: Some(size),
            context_length: 8192,
            capabilities: vec!["completion".into()],
        }
    }

    #[test]
    fn resolves_plain_alias_across_providers() {
        let config = config();
        let available = vec![model("llama3.2:latest", 3.2), model("qwen:14b", 14.0)];
        let resolved = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &["gpt-4.1-mini".into(), "ollama/qwen:14b".into()],
            route_bias: None,
            config: &config,
            ollama_models: &available,
        })
        .unwrap();
        assert_eq!(resolved, "gpt-4.1-mini");
    }

    #[test]
    fn falls_back_when_ollama_model_is_missing() {
        let config = config();
        let available = vec![model("llama3.2:latest", 3.2), model("qwen:14b", 14.0)];
        let resolved = resolve_model(RoutingContext {
            requested: "ollama/missing",
            allowed_models: &[],
            route_bias: Some("cheap"),
            config: &config,
            ollama_models: &available,
        })
        .unwrap();
        assert_eq!(resolved, "ollama/llama3.2:latest");
    }

    #[test]
    fn preserves_installed_ollama_models() {
        let config = config();
        let available = vec![model("llama3.2:latest", 3.2)];
        let resolved = resolve_model(RoutingContext {
            requested: "ollama/llama3.2:latest",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &available,
        })
        .unwrap();
        assert_eq!(resolved, "ollama/llama3.2:latest");
    }

    #[test]
    fn falls_back_to_configured_provider_when_requested_provider_is_unavailable() {
        let mut config = config();
        config.openai_api_key = None;
        let available = vec![model("llama3.2:latest", 3.2)];
        let resolved = resolve_model(RoutingContext {
            requested: "gpt-4.1-mini",
            allowed_models: &["gpt-4.1-mini".into(), "claude-sonnet-4-20250514".into()],
            route_bias: Some("capable"),
            config: &config,
            ollama_models: &available,
        })
        .unwrap();
        assert_eq!(resolved, "claude-sonnet-4-20250514");
    }
}
