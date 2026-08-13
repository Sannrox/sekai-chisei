//! Shared live-model and runtime helpers for policy resolution and planning.
//!
//! These are private implementation used by already-deep modules. They are not a
//! new ordered lifecycle.

use super::*;

impl ChiseiServiceImpl {
    pub(super) async fn resolve_live_model(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
        requirements: Option<&crate::provider_profile::CapabilityRequirements>,
    ) -> Result<String, String> {
        self.resolve_live_model_with_override(
            model,
            policy,
            route_bias,
            safe_only,
            safe_providers,
            requirements,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn resolve_live_model_with_override(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
        requirements: Option<&crate::provider_profile::CapabilityRequirements>,
        exact_override: bool,
    ) -> Result<String, String> {
        validate_explicit_requested_model(model)?;
        let discovery = crate::chisei::model_availability::ModelDiscoveryConfig {
            openai_base_url: std::env::var("CHISEI_OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
            openai_api_key: self.config.openai_api_key.clone(),
            anthropic_base_url: std::env::var("CHISEI_ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1".into()),
            anthropic_api_key: self.config.anthropic_api_key.clone(),
            ollama_url: self.config.ollama_url.clone(),
            native_configured: self.config.native_llm_url.is_some(),
        };
        let availability =
            crate::chisei::model_availability::refresh_model_availability(&discovery, false).await;
        let available_models = availability
            .models_by_provider
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let discovered_ollama = crate::chisei::model_availability::ollama_models(&availability);
        let empty_allowed = Vec::new();
        let allowed_models = policy
            .map(|policy| policy.allowed_models.as_slice())
            .unwrap_or(empty_allowed.as_slice());
        let base_context = crate::chisei::model_routing::RoutingContext {
            requested: model,
            allowed_models,
            route_bias,
            config: &self.config,
            ollama_models: &discovered_ollama,
            available_models: &available_models,
            authoritative_providers: &availability.authoritative_providers,
            requirements,
            safe_only,
            safe_providers,
        };
        let needs_ollama_first = !model.contains('/')
            && model != "native-default"
            && model != "cheap"
            && model != "capable"
            && crate::llm::provider_name(model) == "native";
        if exact_override {
            return crate::chisei::model_routing::resolve_override(base_context);
        }
        if !needs_ollama_first
            && let Ok(resolved) = crate::chisei::model_routing::resolve_model(base_context.clone())
        {
            return Ok(resolved);
        }

        crate::chisei::model_routing::resolve_model(crate::chisei::model_routing::RoutingContext {
            ..base_context
        })
    }
}

fn is_registry_provider_runtime(runtime: &str) -> bool {
    matches!(runtime.trim(), "openai" | "anthropic" | "ollama" | "native")
}

pub(super) fn route_override_allowed(policy: Option<&Policy>, model: &str) -> bool {
    policy.is_none_or(|policy| {
        policy.allowed_models.is_empty()
            || policy
                .allowed_models
                .iter()
                .any(|allowed| models_have_same_identity(allowed, model))
    })
}

pub(super) fn final_runtime_for_model(
    policy: Option<&Policy>,
    current_runtime: &str,
    model: &str,
) -> Result<String, String> {
    let explicitly_registry_routed = ["openai/", "anthropic/", "ollama/", "native/"]
        .iter()
        .any(|prefix| model.starts_with(prefix));
    if !is_registry_provider_runtime(current_runtime) && !explicitly_registry_routed {
        if model.contains('/') {
            crate::chisei::policy::validate_resolved_route(current_runtime, model)?;
            return Ok(current_runtime.to_string());
        }
        let identity = crate::provider_resolution::resolve_model(model)?;
        if identity.provider == "native" {
            crate::provider_resolution::resolve_model(model)?;
            return Ok("native".to_string());
        }
    }
    let runtime = crate::llm::provider_name(model);
    if runtime == "unknown" {
        return Err(format!(
            "model {model:?} has no registered provider runtime"
        ));
    }
    if policy.is_some_and(|policy| {
        !(policy.allowed_runtimes.is_empty()
            || policy
                .allowed_runtimes
                .iter()
                .any(|allowed| allowed == runtime)
            || runtime == "native"
                && policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == "kiro"))
    }) {
        return Err(format!(
            "model runtime {runtime:?} is not allowed by policy"
        ));
    }
    crate::chisei::policy::validate_resolved_route(runtime, model)?;
    Ok(runtime.to_string())
}
