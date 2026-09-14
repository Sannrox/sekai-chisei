use super::*;

pub(super) async fn send_upstream_with_resilience(
    runtime: &GatewayRuntime,
    provider: ProviderKind,
    request: reqwest::RequestBuilder,
    contact_guard: &ProviderContactGuard,
) -> Result<(reqwest::Response, String), UpstreamSendError> {
    let circuit_key = capability_provider_id(provider).to_string();
    {
        let mut circuits = runtime.upstream_circuits.write().await;
        if let Some(circuit) = circuits.get_mut(&circuit_key) {
            if circuit.observe(&circuit_key) {
                return Err(UpstreamSendError::CircuitOpen {
                    health: circuit.health,
                });
            }
        } else {
            crate::obs::signals::set_provider_circuit_open(&circuit_key, false);
        }
    }

    let mut request = request;
    let mut model_attempted = false;
    for attempt in 0..=runtime.resilience.upstream_connect_retries {
        let contact_snapshot_version =
            contact_guard
                .enforce(runtime)
                .await
                .map_err(
                    |(rejection, snapshot_version)| UpstreamSendError::Governance {
                        rejection,
                        snapshot_version,
                        model_attempted,
                    },
                )?;
        let retry = request.try_clone();
        model_attempted = true;
        match request.send().await {
            Ok(response) => {
                let signal = provider_health_from_response(&response);
                let retry_after = retry_after_duration(response.headers());
                {
                    let mut circuits = runtime.upstream_circuits.write().await;
                    let circuit = circuits.entry(circuit_key.clone()).or_default();
                    circuit.record_http_signal(signal, retry_after, &runtime.resilience);
                    circuit.publish_metrics(&circuit_key);
                }
                return Ok((response, contact_snapshot_version));
            }
            Err(error)
                if error.is_connect()
                    && attempt < runtime.resilience.upstream_connect_retries
                    && retry.is_some() =>
            {
                request = retry.expect("retry availability was checked");
                let multiplier = 1u32.checked_shl(attempt.min(10)).unwrap_or(u32::MAX);
                tokio::time::sleep(runtime.resilience.control_plane_retry_backoff * multiplier)
                    .await;
            }
            Err(error) => {
                {
                    let mut circuits = runtime.upstream_circuits.write().await;
                    let circuit = circuits.entry(circuit_key.clone()).or_default();
                    circuit.record_failure(error.to_string(), &runtime.resilience);
                    circuit.publish_metrics(&circuit_key);
                }
                return Err(UpstreamSendError::Request {
                    error,
                    snapshot_version: contact_snapshot_version,
                });
            }
        }
    }
    unreachable!("upstream retry loop always returns")
}
pub(super) fn provider_health_from_response(response: &reqwest::Response) -> ProviderHealth {
    provider_health_from_status(response.status())
}
pub(super) fn provider_health_from_status(status: reqwest::StatusCode) -> ProviderHealth {
    match status.as_u16() {
        402 => ProviderHealth::QuotaExhausted,
        408 => ProviderHealth::Unavailable,
        429 => ProviderHealth::RateLimited,
        502..=504 => ProviderHealth::Overloaded,
        500..=599 => ProviderHealth::Unavailable,
        _ => ProviderHealth::Healthy,
    }
}
pub(super) fn retry_after_duration(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    retry_after_value_duration(value)
}
pub(super) fn retry_after_value_duration(value: &str) -> Option<Duration> {
    let seconds = value.parse::<u64>().ok().or_else(|| {
        httpdate::parse_http_date(value).ok().map(|date| {
            date.duration_since(std::time::SystemTime::now())
                .unwrap_or_default()
                .as_secs()
        })
    })?;
    Some(Duration::from_secs(
        seconds.min(MAX_PROVIDER_RETRY_AFTER_SECS),
    ))
}
pub(super) fn capability_provider_id(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi) => "openai",
        ProviderKind::OpenAi(OpenAiRuntime::Ollama) => "ollama",
        ProviderKind::OpenAi(OpenAiRuntime::Native) => "native",
        ProviderKind::OpenAi(OpenAiRuntime::Xai) => "xai",
        ProviderKind::OpenAi(OpenAiRuntime::Meta) => "meta",
        ProviderKind::Anthropic => "anthropic",
    }
}
pub(super) fn capability_snapshot_identifier(registry: &ProviderRegistry) -> String {
    format!(
        "{CAPABILITY_MATRIX_VERSION}:registry-state-{}",
        registry.state_version
    )
}
pub(super) fn capability_request_surface(
    method: &Method,
    normalized_path: &str,
) -> Option<CapabilityRequestSurface> {
    if method != Method::POST {
        return None;
    }
    match normalized_path {
        "/responses" | "/responses/" => Some(CapabilityRequestSurface::Responses),
        "/chat/completions" | "/chat/completions/" => Some(CapabilityRequestSurface::OpenAiChat),
        "/messages" | "/messages/" => Some(CapabilityRequestSurface::AnthropicMessages),
        _ => None,
    }
}
pub(super) fn enforce_provider_capabilities(
    provider: ProviderKind,
    resolved_model: Option<&str>,
    surface: CapabilityRequestSurface,
    body: &[u8],
) -> Result<CapabilityRequirements, GatewayRejection> {
    if matches!(surface, CapabilityRequestSurface::Responses) {
        validate_responses_request_fields(body).map_err(|reason| {
            GatewayRejection::json(StatusCode::BAD_REQUEST, "invalid_request_error", reason)
        })?;
    }
    let requirements = match surface {
        CapabilityRequestSurface::Responses => CapabilityRequirements::from_responses_body(body),
        CapabilityRequestSurface::OpenAiChat => CapabilityRequirements::from_openai_chat_body(body),
        CapabilityRequestSurface::AnthropicMessages => {
            CapabilityRequirements::from_anthropic_messages_body(body)
        }
    }
    .map_err(|reason| {
        GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("cannot derive request capabilities: {reason}"),
        )
    })?;
    if requirements.provider_continuation {
        return Err(GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "capability_unsupported",
            "previous_response_id is unavailable until provider continuation ownership can be verified",
        ));
    }
    let provider_id = capability_provider_id(provider);
    let registry = provider_registry_snapshot();
    registry
        .ensure_provider_available(provider_id)
        .map_err(|reason| GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", reason))?;
    if let Some(model) = resolved_model {
        registry.resolve_model(model).map_err(|reason| {
            GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", reason)
        })?;
    }
    let profile = registry.effective_profile(provider_id).ok_or_else(|| {
        GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "capability_unsupported",
            format!("provider {provider_id} has no capability profile"),
        )
    })?;
    let missing = requirements.unsupported_by(&profile.capabilities);
    if missing.is_empty() {
        return Ok(requirements);
    }
    Err(GatewayRejection::json(
        StatusCode::BAD_REQUEST,
        "capability_unsupported",
        format!(
            "provider {provider_id} cannot preserve required capabilities: {}",
            missing.join(", ")
        ),
    ))
}
pub(super) fn enforce_adapter_capabilities(
    client_provider: ProviderKind,
    resolved_provider: ProviderKind,
    surface: CapabilityRequestSurface,
    body: &[u8],
) -> Result<(), GatewayRejection> {
    if client_provider != ProviderKind::Anthropic
        || !resolved_provider.is_openai()
        || !matches!(surface, CapabilityRequestSurface::AnthropicMessages)
    {
        return Ok(());
    }
    let required =
        CapabilityRequirements::from_anthropic_messages_body(body).map_err(|reason| {
            GatewayRejection::json(StatusCode::BAD_REQUEST, "invalid_request_error", reason)
        })?;
    let mut unsupported = Vec::new();
    if required.tools {
        unsupported.push("tools");
    }
    if required.structured_output {
        unsupported.push("structured_output");
    }
    if required.reasoning_controls {
        unsupported.push("reasoning_controls");
    }
    if required
        .modalities
        .iter()
        .any(|modality| modality != "text")
    {
        unsupported.push("non_text_modalities");
    }
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|reason| {
        GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("invalid Anthropic request: {reason}"),
        )
    })?;
    let allowed_fields = [
        "model",
        "messages",
        "system",
        "max_tokens",
        "temperature",
        "stream",
    ];
    if value.as_object().is_some_and(|object| {
        object
            .keys()
            .any(|field| !allowed_fields.contains(&field.as_str()))
    }) {
        unsupported.push("request_fields");
    }
    if !anthropic_adapter_preserves_text_content(&value) {
        unsupported.push("content_blocks");
    }
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "capability_unsupported",
            format!(
                "cross-provider Anthropic to OpenAI adapter cannot preserve: {}",
                unsupported.join(", ")
            ),
        ))
    }
}
pub(super) fn anthropic_adapter_preserves_text_content(value: &serde_json::Value) -> bool {
    pub(super) fn text_content_is_lossless(content: &serde_json::Value) -> bool {
        match content {
            serde_json::Value::String(_) => true,
            serde_json::Value::Array(blocks) => {
                let [block] = blocks.as_slice() else {
                    return false;
                };
                let Some(object) = block.as_object() else {
                    return false;
                };
                object.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    && object.get("text").is_some_and(serde_json::Value::is_string)
                    && object
                        .keys()
                        .all(|key| matches!(key.as_str(), "type" | "text"))
            }
            _ => false,
        }
    }

    if value
        .get("system")
        .is_some_and(|system| !text_content_is_lossless(system))
    {
        return false;
    }
    value
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|messages| {
            !messages.is_empty()
                && messages.iter().all(|message| {
                    let Some(object) = message.as_object() else {
                        return false;
                    };
                    object
                        .keys()
                        .all(|key| matches!(key.as_str(), "role" | "content"))
                        && object
                            .get("role")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|role| matches!(role, "user" | "assistant"))
                        && object.get("content").is_some_and(text_content_is_lossless)
                })
        })
}
/// Normalizes a gateway Anthropic upstream base URL so it ends in `/v1`.
///
/// `upstream_path` strips the leading `/v1` from the client path and
/// `build_upstream_url` re-appends the base, so the effective base must carry
/// the `/v1` segment. A base like `https://api.anthropic.com` (no `/v1`) would
/// otherwise misroute every call to `…/messages`, which Anthropic rejects.
pub(super) fn normalize_anthropic_base_url(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return DEFAULT_ANTHROPIC_BASE_URL.to_string();
    }
    if trimmed.ends_with("/v1") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1")
    }
}
/// Base URL for a provider's backend. This is what makes per-model routing work:
/// a request resolved to an Ollama or native model is sent to that backend
/// instead of the OpenAI upstream.
pub(super) fn base_url_for_provider(
    config: &GatewayConfig,
    provider: ProviderKind,
) -> Option<String> {
    match provider {
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi) => Some(config.openai_base_url.clone()),
        ProviderKind::OpenAi(OpenAiRuntime::Ollama) => Some(config.ollama_base_url.clone()),
        ProviderKind::OpenAi(OpenAiRuntime::Native) => config
            .native_base_url
            .clone()
            .filter(|value| !value.trim().is_empty()),
        ProviderKind::OpenAi(OpenAiRuntime::Xai) => Some(
            std::env::var("CHISEI_XAI_BASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "https://api.x.ai/v1".into()),
        ),
        ProviderKind::OpenAi(OpenAiRuntime::Meta) => std::env::var("CHISEI_META_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        ProviderKind::Anthropic => Some(config.anthropic_base_url.clone()),
    }
}
/// Maps a client request path to (client provider by wire shape, upstream path).
pub(super) fn upstream_path(uri: &Uri) -> Option<(ProviderKind, String)> {
    let path = uri.path();
    let openai = ProviderKind::OpenAi(OpenAiRuntime::OpenAi);
    let mapped = if matches!(path, "/v1/responses" | "/v1/responses/") {
        (openai, path.trim_start_matches("/v1").to_string())
    } else if matches!(path, "/responses" | "/responses/") {
        (openai, path.to_string())
    } else if let Some(rest) = path.strip_prefix("/v1/chat/completions") {
        (openai, format!("/chat/completions{rest}"))
    } else if let Some(rest) = path.strip_prefix("/chat/completions") {
        (openai, format!("/chat/completions{rest}"))
    } else if let Some(rest) = path.strip_prefix("/v1/models") {
        (openai, format!("/models{rest}"))
    } else if let Some(rest) = path.strip_prefix("/models") {
        (openai, format!("/models{rest}"))
    } else if let Some(rest) = path.strip_prefix("/v1/messages/count_tokens") {
        (
            ProviderKind::Anthropic,
            format!("/messages/count_tokens{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/messages/count_tokens") {
        (
            ProviderKind::Anthropic,
            format!("/messages/count_tokens{rest}"),
        )
    } else if let Some(rest) = path.strip_prefix("/v1/messages") {
        (ProviderKind::Anthropic, format!("/messages{rest}"))
    } else {
        let rest = path.strip_prefix("/messages")?;
        (ProviderKind::Anthropic, format!("/messages{rest}"))
    };
    Some(mapped)
}
pub(super) fn build_upstream_url(base_url: &str, upstream_path: &str, uri: &Uri) -> String {
    let mut url = format!("{}{}", base_url.trim_end_matches('/'), upstream_path);
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    url
}
pub(super) fn apply_provider_auth(
    upstream: reqwest::RequestBuilder,
    config: &GatewayConfig,
    provider: ProviderKind,
) -> Result<reqwest::RequestBuilder, Box<Response<Body>>> {
    match provider {
        // Local backends (Ollama, native) need no upstream credential.
        ProviderKind::OpenAi(OpenAiRuntime::Ollama | OpenAiRuntime::Native) => Ok(upstream),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi) => config
            .openai_api_key
            .as_ref()
            .map(|key| upstream.bearer_auth(key))
            .ok_or_else(|| {
                Box::new(json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_config_error",
                    "OPENAI_API_KEY is not configured",
                ))
            }),
        ProviderKind::Anthropic => config
            .anthropic_api_key
            .as_ref()
            .map(|key| upstream.header(X_API_KEY, key))
            .ok_or_else(|| {
                Box::new(json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_config_error",
                    "ANTHROPIC_API_KEY is not configured",
                ))
            }),
        ProviderKind::OpenAi(OpenAiRuntime::Xai | OpenAiRuntime::Meta) => {
            let (variable, provider_name) = match provider {
                ProviderKind::OpenAi(OpenAiRuntime::Xai) => ("XAI_API_KEY", "xAI"),
                ProviderKind::OpenAi(OpenAiRuntime::Meta) => {
                    ("META_MODEL_API_KEY", "Meta Model API")
                }
                _ => unreachable!(),
            };
            std::env::var(variable)
                .ok()
                .filter(|key| !key.trim().is_empty())
                .map(|key| upstream.bearer_auth(key))
                .ok_or_else(|| {
                    Box::new(json_error(
                        StatusCode::BAD_GATEWAY,
                        "gateway_config_error",
                        &format!("{variable} is not configured for {provider_name}"),
                    ))
                })
        }
    }
}
pub(super) fn upstream_auth_mode(
    config: &GatewayConfig,
    requested_mode: UpstreamAuthMode,
    provider: ProviderKind,
) -> UpstreamAuthMode {
    if requested_mode == UpstreamAuthMode::Passthrough
        && matches!(provider, ProviderKind::OpenAi(OpenAiRuntime::OpenAi))
        && config.rewrite_openai_passthrough_auth
        && config.openai_api_key.is_some()
    {
        return UpstreamAuthMode::GatewayKey;
    }
    if matches!(
        provider,
        ProviderKind::OpenAi(OpenAiRuntime::Xai | OpenAiRuntime::Meta)
    ) {
        return UpstreamAuthMode::GatewayKey;
    }
    requested_mode
}
pub(super) fn buffered_gateway_usage_outcome(
    status: StatusCode,
    terminal_required: bool,
    terminal: Option<ResponsesTerminal>,
) -> GatewayUsageOutcome {
    if !status.is_success() {
        GatewayUsageOutcome::TerminalFailure(status, "upstream_http_error".into())
    } else if !terminal_required {
        GatewayUsageOutcome::Success(status)
    } else {
        match terminal {
            Some(ResponsesTerminal::Completed) => GatewayUsageOutcome::Success(status),
            Some(ResponsesTerminal::Incomplete(reason)) => {
                GatewayUsageOutcome::Incomplete(status, reason)
            }
            Some(ResponsesTerminal::Failed) => {
                GatewayUsageOutcome::TerminalFailure(status, "response_failed".into())
            }
            Some(ResponsesTerminal::Cancelled) => {
                GatewayUsageOutcome::TerminalFailure(status, "response_cancelled".into())
            }
            Some(ResponsesTerminal::Interrupted) => {
                GatewayUsageOutcome::TerminalFailure(status, "response_interrupted".into())
            }
            Some(ResponsesTerminal::Invalid) | None => {
                GatewayUsageOutcome::TerminalFailure(status, "missing_terminal_status".into())
            }
        }
    }
}
pub(super) fn streaming_gateway_usage_outcome(
    status: StatusCode,
    terminal_required: bool,
    terminal: Option<ResponsesTerminal>,
    aborted: bool,
    terminal_validated: bool,
    missing_terminal: bool,
    stream_error: Option<String>,
) -> GatewayUsageOutcome {
    if !status.is_success() {
        return GatewayUsageOutcome::TerminalFailure(status, "upstream_http_error".into());
    }
    if !terminal_required {
        return if aborted {
            GatewayUsageOutcome::Interrupted(
                status,
                stream_error.unwrap_or_else(|| "upstream response stream was interrupted".into()),
            )
        } else {
            GatewayUsageOutcome::Success(status)
        };
    }
    if aborted && !terminal_validated {
        return GatewayUsageOutcome::Interrupted(
            status,
            stream_error.unwrap_or_else(|| "upstream response stream was interrupted".into()),
        );
    }
    match terminal {
        Some(ResponsesTerminal::Completed) => GatewayUsageOutcome::Success(status),
        Some(ResponsesTerminal::Incomplete(reason)) => {
            GatewayUsageOutcome::Incomplete(status, reason)
        }
        Some(ResponsesTerminal::Failed) => {
            GatewayUsageOutcome::TerminalFailure(status, "response_failed".into())
        }
        Some(ResponsesTerminal::Cancelled) => {
            GatewayUsageOutcome::TerminalFailure(status, "response_cancelled".into())
        }
        Some(ResponsesTerminal::Interrupted) => GatewayUsageOutcome::Interrupted(
            status,
            "upstream reported chisei.response.interrupted".into(),
        ),
        Some(ResponsesTerminal::Invalid) => GatewayUsageOutcome::Interrupted(
            status,
            "upstream emitted invalid terminal events".into(),
        ),
        None if aborted || missing_terminal => GatewayUsageOutcome::Interrupted(
            status,
            stream_error.unwrap_or_else(|| "upstream stream ended without a terminal event".into()),
        ),
        None => GatewayUsageOutcome::Success(status),
    }
}
