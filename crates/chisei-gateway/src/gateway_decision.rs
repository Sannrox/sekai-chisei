use super::*;

pub(super) fn validate_harness_request_headers(
    responses_route: bool,
    headers: &HeaderMap,
) -> Result<(), String> {
    if responses_route && headers.contains_key(&IDEMPOTENCY_KEY) {
        return Err("Idempotency-Key is not supported by this gateway profile version".into());
    }
    Ok(())
}
pub(super) fn is_responses_create(method: &Method, normalized_path: &str) -> bool {
    method == Method::POST && matches!(normalized_path, "/responses" | "/responses/")
}
pub(super) async fn rate_limit_rejection(
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
) -> Option<String> {
    let mut subjects = vec![
        (
            "gateway:global".to_string(),
            runtime.global_rate_limit_requests,
        ),
        (
            format!("agent:{}", identity.agent),
            runtime.rate_limit_requests,
        ),
    ];
    if !identity.key_id.is_empty() {
        subjects.push((
            format!("key:{}", identity.key_id),
            runtime.rate_limit_requests,
        ));
    }
    let now = Instant::now();
    let mut limits = runtime.rate_limits.write().await;
    limits.retain(|_, window| now.duration_since(window.started_at) < runtime.rate_limit_window);
    for (subject, limit) in &subjects {
        if !limits.contains_key(subject) && limits.len() >= MAX_RATE_LIMIT_SUBJECTS {
            return Some("gateway:subject_capacity".to_string());
        }
        let window = limits.entry(subject.clone()).or_insert(RateLimitWindow {
            started_at: now,
            requests: 0,
        });
        if now.duration_since(window.started_at) >= runtime.rate_limit_window {
            window.started_at = now;
            window.requests = 0;
        }
        if window.requests >= *limit {
            return Some(subject.clone());
        }
    }
    for (subject, _) in subjects {
        limits
            .get_mut(&subject)
            .expect("rate window exists")
            .requests += 1;
    }
    None
}

#[cfg(test)]
pub(super) async fn select_healthy_policy_fallback(
    runtime: &GatewayRuntime,
    registry: &ProviderRegistry,
    decision: PolicyPreflight,
    surface: Option<CapabilityRequestSurface>,
    client_provider: ProviderKind,
    allow_cross_provider: bool,
    local_free_only: bool,
) -> Result<PolicyPreflight, GatewayRejection> {
    let selected_key = capability_provider_id(decision.resolved_provider);
    let circuits = runtime.upstream_circuits.read().await;
    let selected_unhealthy = circuits
        .get(selected_key)
        .is_some_and(CircuitBreakerState::is_open);
    if !selected_unhealthy {
        return Ok(decision);
    }
    drop(circuits);
    match select_next_failover_candidate(
        runtime,
        registry,
        &decision,
        surface,
        client_provider,
        allow_cross_provider,
        local_free_only,
        &[],
    )
    .await
    {
        Ok(Some(next)) => Ok(next),
        Ok(None) => Err(GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_unavailable",
            format!(
                "provider {selected_key:?} is unhealthy and no policy-authorized capability and governance equivalent fallback is eligible"
            ),
        )
        .with_retry_safety("safe")),
        Err(rejection) => Err(rejection),
    }
}
/// Whether the client protocol can be prepared for the candidate provider.
///
/// Same-family is always adaptable. The only implemented cross-family adapter is
/// Anthropic Messages → OpenAI-compatible chat.
pub(super) fn client_can_dispatch_to_provider(client: ProviderKind, target: ProviderKind) -> bool {
    client == target
        || client.same_family(target)
        || (client == ProviderKind::Anthropic && target.is_openai())
}
/// Pick the next policy-authorized fallback, skipping open circuits and already-tried providers.
///
/// Used both for preflight health fallback and same-request mid-request failover after a live
/// upstream failure. Never crosses governance, capability, family (unless allowed), or local-free
/// boundaries. Also skips candidates the client protocol cannot adapt to, so preparation
/// failures do not terminate failover early.
#[allow(clippy::too_many_arguments)]
pub(super) async fn select_next_failover_candidate(
    runtime: &GatewayRuntime,
    registry: &ProviderRegistry,
    decision: &PolicyPreflight,
    surface: Option<CapabilityRequestSurface>,
    client_provider: ProviderKind,
    allow_cross_provider: bool,
    local_free_only: bool,
    excluded_provider_ids: &[&str],
) -> Result<Option<PolicyPreflight>, GatewayRejection> {
    let selected_key = capability_provider_id(decision.resolved_provider);
    let selected_profile = registry.effective_profile(selected_key).ok_or_else(|| {
        GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_unavailable",
            format!("selected provider {selected_key:?} has no effective profile"),
        )
        .with_retry_safety("safe")
    })?;
    let requirements = surface
        .map(|surface| match surface {
            CapabilityRequestSurface::Responses => {
                CapabilityRequirements::from_responses_body(&decision.body)
            }
            CapabilityRequestSurface::OpenAiChat => {
                CapabilityRequirements::from_openai_chat_body(&decision.body)
            }
            CapabilityRequestSurface::AnthropicMessages => {
                CapabilityRequirements::from_anthropic_messages_body(&decision.body)
            }
        })
        .transpose()
        .map_err(|reason| {
            GatewayRejection::json(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("cannot derive fallback requirements: {reason}"),
            )
        })?;
    let circuits = runtime.upstream_circuits.read().await;
    for candidate in &decision.fallback_models {
        let Ok(resolved) = registry.resolve_model(candidate) else {
            continue;
        };
        let Some(provider) = ProviderKind::from_runtime(&resolved.provider) else {
            continue;
        };
        let provider_id = capability_provider_id(provider);
        if excluded_provider_ids.contains(&provider_id) {
            continue;
        }
        if local_free_only && provider != ProviderKind::OpenAi(OpenAiRuntime::Ollama) {
            continue;
        }
        if !decision.resolved_provider.same_family(provider) && !allow_cross_provider {
            continue;
        }
        if !client_can_dispatch_to_provider(client_provider, provider) {
            continue;
        }
        if let Some(surface) = surface
            && enforce_adapter_capabilities(client_provider, provider, surface, &decision.body)
                .is_err()
        {
            continue;
        }
        if circuits
            .get(provider_id)
            .is_some_and(CircuitBreakerState::is_open)
        {
            continue;
        }
        let Some(profile) = registry.effective_profile(&resolved.provider) else {
            continue;
        };
        if profile.governance != selected_profile.governance
            || requirements
                .as_ref()
                .is_some_and(|required| !required.unsupported_by(&profile.capabilities).is_empty())
        {
            continue;
        }
        let mut next = decision.clone();
        next.body =
            rewrite_request_model(&decision.body, &resolved.canonical_model).map_err(|error| {
                GatewayRejection::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    format!("could not rewrite fallback model: {error}"),
                )
            })?;
        next.resolved_model = Some(resolved.canonical_model);
        next.resolved_provider = provider;
        next.route_bias = Some("health_fallback".into());
        return Ok(Some(next));
    }
    Ok(None)
}
