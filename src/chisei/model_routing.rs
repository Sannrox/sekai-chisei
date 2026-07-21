use crate::chisei::model_availability::AvailableModel;
use crate::config::Config;
use crate::llm;
use crate::llm::ollama::InstalledModel;
use std::collections::HashSet;

#[derive(Clone)]
pub struct RoutingContext<'a> {
    pub requested: &'a str,
    pub allowed_models: &'a [String],
    pub route_bias: Option<&'a str>,
    pub config: &'a Config,
    pub ollama_models: &'a [InstalledModel],
    pub available_models: &'a [AvailableModel],
    pub authoritative_providers: &'a [String],
    pub safe_only: bool,
    pub safe_providers: &'a HashSet<String>,
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

/// Whether a task class may automatically use a lower-cost model tier.
/// Unknown, primary, and reasoning work deliberately fail safe to capable.
pub fn is_cheap_eligible_task_class(task_class: &str) -> bool {
    matches!(
        task_class.trim().to_ascii_lowercase().as_str(),
        "background" | "bulk" | "batch" | "small_fast" | "small-fast"
    )
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
        return safe_resolved(format!("ollama/{name}"), &ctx);
    }

    if let Some(name) = ctx.requested.strip_prefix("ollama/") {
        if has_available_model(name, ctx.ollama_models) {
            return safe_resolved(ctx.requested.to_string(), &ctx);
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
    if ctx.safe_only && !provider_is_safe(provider, &ctx) {
        return Err(format!(
            "provider {provider:?} is not safe for sensitive data"
        ));
    }
    let provider_has_live_catalog = ctx
        .authoritative_providers
        .iter()
        .any(|available| available == provider);
    let requested_is_available = ctx.available_models.iter().any(|available| {
        available.provider == provider
            && available.discovery_source != "static_fallback"
            && available.routable
            && (available.canonical_model == ctx.requested
                || available.upstream_model == ctx.requested)
    });
    if provider_is_available(provider, ctx.config)
        && (!provider_has_live_catalog || requested_is_available)
    {
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
    let mut models = ctx
        .available_models
        .iter()
        .filter(|model| model.routable)
        .map(|model| model.canonical_model.clone())
        .collect::<Vec<_>>();
    let authoritative = |provider: &str| {
        ctx.authoritative_providers
            .iter()
            .any(|available| available == provider)
    };
    if !authoritative("anthropic") && provider_is_available("anthropic", ctx.config) {
        models.push("claude-sonnet-4-20250514".to_string());
    }
    if !authoritative("openai") && provider_is_available("openai", ctx.config) {
        models.push("gpt-4.1-mini".to_string());
        models.push("gpt-4.1".to_string());
    }
    if !authoritative("native") && provider_is_available("native", ctx.config) {
        models.push("native-default".to_string());
    }
    if !authoritative("ollama") {
        for model in ctx.ollama_models {
            models.push(format!("ollama/{}", model.name));
        }
    }
    models.sort();
    models.dedup();
    models
}

fn build_candidate(model: &str, ctx: &RoutingContext<'_>) -> Option<Candidate> {
    if !ctx.available_models.is_empty() {
        let inferred_provider = llm::provider_name(model);
        let intended_provider = if inferred_provider == "native"
            && exact_available_ollama_name(model, ctx.ollama_models).is_some()
        {
            "ollama"
        } else {
            inferred_provider
        };
        let available = ctx.available_models.iter().find(|available| {
            available.routable
                && available.provider == intended_provider
                && (available.canonical_model == model || available.upstream_model == model)
        });
        if let Some(available) = available {
            if !provider_is_available(&available.provider, ctx.config) {
                return None;
            }
            if ctx.safe_only && !provider_is_safe(&available.provider, ctx) {
                return None;
            }
            return Some(Candidate {
                model: available.canonical_model.clone(),
                cost_rank: available
                    .cost_rank
                    .unwrap_or_else(|| named_model_cost_rank(&available.upstream_model)),
                capability_rank: available
                    .capability_rank
                    .unwrap_or_else(|| named_model_capability_rank(&available.upstream_model)),
            });
        }
        if ctx
            .authoritative_providers
            .iter()
            .any(|available| available == intended_provider)
        {
            return None;
        }
    }
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
    if ctx.safe_only && !provider_is_safe(provider, ctx) {
        return None;
    }

    Some(Candidate {
        model: model.to_string(),
        cost_rank: named_model_cost_rank(model),
        capability_rank: named_model_capability_rank(model),
    })
}

fn safe_resolved(model: String, ctx: &RoutingContext<'_>) -> Result<String, String> {
    let provider = llm::provider_name(&model);
    if ctx.safe_only && !provider_is_safe(provider, ctx) {
        return Err(format!(
            "provider {provider:?} is not safe for sensitive data"
        ));
    }
    Ok(model)
}

fn provider_is_safe(provider: &str, ctx: &RoutingContext<'_>) -> bool {
    crate::chisei::privacy::provider_safe_to_send(provider, ctx.safe_providers)
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

pub fn named_model_cost_rank(model: &str) -> i32 {
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
    if config
        .gateway_provided_providers
        .iter()
        .any(|p| p == provider)
    {
        return true;
    }
    match provider {
        "anthropic" => config.anthropic_api_key.is_some(),
        "openai" => config.openai_api_key.is_some(),
        "ollama" => true,
        "native" => config.native_llm_url.is_some(),
        "xai" => std::env::var_os("XAI_API_KEY").is_some(),
        "meta" => crate::chisei::model_availability::meta_provider_is_configured(),
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
    use crate::chisei::model_availability::AvailableModel;
    use crate::config::Config;
    use crate::llm::ollama::InstalledModel;
    use crate::provider_profile::ProviderRegistry;

    fn config() -> Config {
        Config {
            grpc_port: 50051,
            sekai_bind: None,
            ops_port: None,
            ops_bind: "127.0.0.1".into(),
            sekai_socket: None,
            db_path: ":memory:".into(),
            anthropic_api_key: Some("anthropic".into()),
            openai_api_key: Some("openai".into()),
            ollama_url: "http://localhost:11434".into(),
            native_llm_url: Some("http://localhost:1234".into()),
            auth_token: None,
            sample_rate: 0.05,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "claude-opus-4-8".into(),
            scoring_batch_size: 16,
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec![],
            gateway_provided_providers: vec![],
            gateway_receipt_principals: vec![],
            leak_review_model: None,
            tls_cert: None,
            tls_key: None,
            allow_plaintext: false,
            insecure: false,
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

    fn discovered(provider: &str, model: &str) -> AvailableModel {
        let profile = ProviderRegistry::built_in()
            .effective_profile(provider)
            .unwrap();
        AvailableModel {
            provider: provider.into(),
            upstream_model: model.into(),
            canonical_model: format!("{provider}/{model}"),
            lifecycle: "enabled".into(),
            routable: true,
            discovery_source: "provider_catalog".into(),
            capabilities: Some(profile.capabilities),
            pricing: Some(profile.pricing),
            cost_rank: None,
            capability_rank: None,
        }
    }

    fn keyless_config() -> Config {
        // ChatGPT-plan style: the control-plane server holds no provider keys.
        let mut config = config();
        config.openai_api_key = None;
        config.anthropic_api_key = None;
        config.native_llm_url = None;
        config
    }

    #[test]
    fn gateway_provided_provider_resolves_without_a_local_key() {
        let mut config = keyless_config();
        config.gateway_provided_providers = vec!["openai".into()];
        let resolved = resolve_model(RoutingContext {
            requested: "gpt-5.5",
            allowed_models: &["gpt-5.5".into()],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "gpt-5.5");
    }

    #[test]
    fn gateway_provided_alias_survives_unrelated_authoritative_catalog() {
        let mut config = keyless_config();
        config.gateway_provided_providers = vec!["openai".into()];
        let resolved = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &["ollama".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "gpt-4.1-mini");
    }

    #[test]
    fn aliases_use_discovered_models_and_static_candidates_only_without_a_snapshot() {
        let config = config();
        let discovered = vec![discovered("openai", "gpt-discovered-mini")];
        let resolved = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &discovered,
            authoritative_providers: &["openai".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "openai/gpt-discovered-mini");

        let fallback = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(fallback, "gpt-4.1-mini");
    }

    #[test]
    fn lifecycle_unroutable_discovered_models_are_excluded() {
        let mut config = config();
        config.anthropic_api_key = None;
        config.native_llm_url = None;
        let mut disabled = discovered("openai", "gpt-disabled-mini");
        disabled.lifecycle = "disabled".into();
        disabled.routable = false;
        let result = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[disabled],
            authoritative_providers: &["openai".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn authoritative_empty_catalog_does_not_fall_back_to_static_models() {
        let mut config = config();
        config.native_llm_url = None;
        let result = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &["openai".into(), "anthropic".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn exact_policy_model_preserves_provider_when_upstream_names_collide() {
        let config = config();
        let discovered = vec![
            discovered("openai", "gpt-4.1"),
            discovered("ollama", "gpt-4.1"),
        ];
        let installed = vec![model("gpt-4.1", 7.0)];
        let resolved = resolve_model(RoutingContext {
            requested: "cheap",
            allowed_models: &["gpt-4.1".into()],
            route_bias: None,
            config: &config,
            ollama_models: &installed,
            available_models: &discovered,
            authoritative_providers: &["openai".into(), "ollama".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "openai/gpt-4.1");
    }

    #[test]
    fn discovered_ollama_candidates_preserve_metadata_ranking() {
        let config = config();
        let mut small = discovered("ollama", "z-small");
        small.cost_rank = Some(100);
        small.capability_rank = Some(100);
        let mut large = discovered("ollama", "a-large");
        large.cost_rank = Some(1000);
        large.capability_rank = Some(1000);
        let models = vec![small, large];
        let resolved = resolve_model(RoutingContext {
            requested: "ollama/capable",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &models,
            authoritative_providers: &["ollama".into()],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "ollama/a-large");
    }

    #[test]
    fn provider_unavailable_without_key_or_gateway_flag() {
        let config = keyless_config();
        let result = resolve_model(RoutingContext {
            requested: "gpt-5.5",
            allowed_models: &["gpt-5.5".into()],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        });
        assert!(result.is_err());
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
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
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
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
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
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
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
            available_models: &[],
            authoritative_providers: &[],
            safe_only: false,
            safe_providers: &std::collections::HashSet::new(),
        })
        .unwrap();
        assert_eq!(resolved, "claude-sonnet-4-20250514");
    }

    #[test]
    fn safe_only_filters_external_candidates() {
        let config = config();
        let available = vec![model("llama3.2:latest", 3.2)];
        let safe = std::collections::HashSet::from(["ollama".to_string()]);
        let resolved = resolve_model(RoutingContext {
            requested: "capable",
            allowed_models: &[
                "claude-sonnet-4-20250514".into(),
                "ollama/llama3.2:latest".into(),
            ],
            route_bias: Some("capable"),
            config: &config,
            ollama_models: &available,
            available_models: &[],
            authoritative_providers: &[],
            safe_only: true,
            safe_providers: &safe,
        })
        .unwrap();
        assert_eq!(resolved, "ollama/llama3.2:latest");
    }

    #[test]
    fn safe_only_rejects_explicit_unsafe_provider() {
        let config = config();
        let safe = std::collections::HashSet::from(["ollama".to_string()]);
        let err = resolve_model(RoutingContext {
            requested: "gpt-4.1-mini",
            allowed_models: &[],
            route_bias: None,
            config: &config,
            ollama_models: &[],
            available_models: &[],
            authoritative_providers: &[],
            safe_only: true,
            safe_providers: &safe,
        })
        .unwrap_err();
        assert!(err.contains("not safe"));
    }
}
