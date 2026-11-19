use super::*;

pub(super) fn rewrite_request_model(
    body: &[u8],
    model: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_slice(body)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "model".to_string(),
            serde_json::Value::String(model.to_string()),
        );
    }
    serde_json::to_vec(&value)
}
pub(super) fn rewrite_resolved_request_model(
    body: &[u8],
    resolved_model: &crate::provider_profile::ResolvedProviderModel,
) -> Result<Vec<u8>, serde_json::Error> {
    rewrite_request_model(body, &resolved_model.upstream_model)
}
/// Chisei names Ollama models `ollama/<name>`, but the Ollama API expects the
/// bare `<name>`. Strip the prefix from the request body's model before
/// forwarding to the Ollama backend. Returns the body unchanged if it can't be
/// parsed or the model isn't prefixed.
pub(super) fn strip_ollama_model_prefix(body: &[u8]) -> Vec<u8> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    match value
        .get("model")
        .and_then(|model| model.as_str())
        .and_then(|model| model.strip_prefix("ollama/"))
    {
        Some(stripped) => rewrite_request_model(body, stripped).unwrap_or_else(|_| body.to_vec()),
        None => body.to_vec(),
    }
}
#[allow(clippy::result_large_err)]
pub(super) async fn prepare_upstream_request(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    uri: &Uri,
    client_provider: ProviderKind,
    resolved_provider: ProviderKind,
    body: Vec<u8>,
    resolved_model: Option<&crate::provider_profile::ResolvedProviderModel>,
) -> Result<PreparedUpstreamRequest, Response<Body>> {
    if client_provider == resolved_provider || client_provider.same_family(resolved_provider) {
        // Same wire family: pass through unchanged, but route to the *resolved*
        // provider's backend so within-family routing (OpenAI vs Ollama vs native)
        // reaches the right upstream. All of these speak the same wire natively.
        let body = if let Some(resolved_model) = resolved_model {
            rewrite_resolved_request_model(&body, resolved_model).map_err(|error| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("could not rewrite resolved model: {error}"),
                )
            })?
        } else if matches!(
            resolved_provider,
            ProviderKind::OpenAi(OpenAiRuntime::Ollama)
        ) {
            strip_ollama_model_prefix(&body)
        } else {
            body
        };
        return Ok(PreparedUpstreamRequest {
            provider: resolved_provider,
            url: upstream_url_for_provider(config, uri, resolved_provider).ok_or_else(|| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_config_error",
                    &format!(
                        "{} endpoint is not configured",
                        resolved_provider.runtime_name()
                    ),
                )
            })?,
            body,
            response_adapter: ResponseAdapter::Passthrough,
            client_response_model: None,
            cross_provider: false,
        });
    }
    if client_provider == ProviderKind::Anthropic
        && resolved_provider.is_openai()
        && is_anthropic_messages_path(uri.path())
    {
        let streaming = request_stream_enabled(&body);
        // Tool-call translation is not modeled, so deny tool-using streams rather
        // than silently dropping the tool schema.
        if streaming && anthropic_request_has_tools(&body) {
            let reason = "cross-provider Anthropic to OpenAI streaming translation with tools is not supported";
            record_gateway_decision(
                config,
                identity,
                "gateway.cross_provider_denied",
                reason,
                "denied",
                HashMap::from([
                    (
                        "client_provider".to_string(),
                        capability_provider_id(client_provider).to_string(),
                    ),
                    (
                        "resolved_provider".to_string(),
                        capability_provider_id(resolved_provider).to_string(),
                    ),
                ]),
            )
            .await;
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_cross_provider_stream",
                reason,
            ));
        }
        let resolved_model = resolved_model.ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "cross-provider translation requires a resolved model",
            )
        })?;
        let mut translated =
            anthropic_messages_to_openai_chat(&body, &resolved_model.upstream_model).map_err(
                |err| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        &format!("failed to translate Anthropic request to OpenAI: {err}"),
                    )
                },
            )?;
        // Ask the OpenAI-compatible upstream to stream (with usage) so we can
        // re-emit Anthropic streaming events and still meter tokens.
        if streaming {
            translated = enable_openai_stream(&translated).unwrap_or(translated);
        }
        // Route to the *resolved* OpenAI-family backend (OpenAI, Ollama, or
        // native), not hardcoded OpenAI. Ollama uses the OpenAI-compatible chat
        // surface with the `ollama/` model prefix stripped and no upstream auth.
        if matches!(
            resolved_provider,
            ProviderKind::OpenAi(OpenAiRuntime::Ollama)
        ) {
            translated = strip_ollama_model_prefix(&translated);
        }
        let response_adapter = if streaming {
            ResponseAdapter::OpenAiChatStreamToAnthropicMessage
        } else {
            ResponseAdapter::OpenAiChatToAnthropicMessage
        };
        record_gateway_decision(
            config,
            identity,
            "gateway.cross_provider_translate",
            "translated Anthropic Messages request to OpenAI Chat Completions",
            "translated",
            HashMap::from([
                (
                    "client_provider".to_string(),
                    capability_provider_id(client_provider).to_string(),
                ),
                (
                    "resolved_provider".to_string(),
                    capability_provider_id(resolved_provider).to_string(),
                ),
                (
                    "resolved_model".to_string(),
                    resolved_model.canonical_model.clone(),
                ),
                ("streaming".to_string(), streaming.to_string()),
                ("project".to_string(), identity.project.clone()),
            ]),
        )
        .await;
        return Ok(PreparedUpstreamRequest {
            provider: resolved_provider,
            url: chat_completions_url_for_provider(config, uri, resolved_provider).ok_or_else(
                || {
                    json_error(
                        StatusCode::BAD_GATEWAY,
                        "gateway_config_error",
                        &format!(
                            "{} endpoint is not configured",
                            resolved_provider.runtime_name()
                        ),
                    )
                },
            )?,
            body: translated,
            response_adapter,
            client_response_model: Some(resolved_model.upstream_model.clone()),
            cross_provider: true,
        });
    }
    let reason = format!(
        "cross-provider translation from {} to {} is not supported",
        capability_provider_id(client_provider),
        capability_provider_id(resolved_provider)
    );
    record_gateway_decision(
        config,
        identity,
        "gateway.cross_provider_denied",
        &reason,
        "denied",
        HashMap::from([
            (
                "client_provider".to_string(),
                capability_provider_id(client_provider).to_string(),
            ),
            (
                "resolved_provider".to_string(),
                capability_provider_id(resolved_provider).to_string(),
            ),
        ]),
    )
    .await;
    Err(json_error(
        StatusCode::FORBIDDEN,
        "unsupported_cross_provider_route",
        &reason,
    ))
}
pub(super) fn upstream_url_for_provider(
    config: &GatewayConfig,
    uri: &Uri,
    provider: ProviderKind,
) -> Option<String> {
    // Keep the client's wire path but send it to the resolved provider's backend,
    // so e.g. a Responses request resolved to an Ollama model hits the Ollama base.
    match upstream_path(uri) {
        Some((_, path)) => Some(build_upstream_url(
            &base_url_for_provider(config, provider)?,
            &path,
            uri,
        )),
        None => openai_chat_completions_url(config, uri),
    }
}
pub(super) fn openai_chat_completions_url(config: &GatewayConfig, uri: &Uri) -> Option<String> {
    chat_completions_url_for_provider(config, uri, ProviderKind::OpenAi(OpenAiRuntime::OpenAi))
}
/// Chat-completions URL for a specific OpenAI-family backend (OpenAI, Ollama, or
/// native), so cross-provider translation routes to the *resolved* provider
/// instead of always OpenAI.
pub(super) fn chat_completions_url_for_provider(
    config: &GatewayConfig,
    uri: &Uri,
    provider: ProviderKind,
) -> Option<String> {
    let mut url = format!(
        "{}/chat/completions",
        base_url_for_provider(config, provider)?.trim_end_matches('/')
    );
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    Some(url)
}
/// Whether an Anthropic Messages request carries a non-empty `tools` array.
pub(super) fn anthropic_request_has_tools(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("tools")
                .and_then(|tools| tools.as_array())
                .map(|tools| !tools.is_empty())
        })
        .unwrap_or(false)
}
/// Sets `stream: true` and requests streamed usage on an OpenAI-compatible chat
/// request body so the upstream emits incremental deltas plus a usage chunk.
pub(super) fn enable_openai_stream(body: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_slice(body)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("stream".to_string(), serde_json::Value::Bool(true));
        object.insert(
            "stream_options".to_string(),
            serde_json::json!({"include_usage": true}),
        );
    }
    serde_json::to_vec(&value)
}
pub(super) fn is_anthropic_messages_path(path: &str) -> bool {
    (path == "/v1/messages" || path == "/messages")
        || (path.starts_with("/v1/messages/") || path.starts_with("/messages/"))
            && !path.contains("count_tokens")
}
pub(super) fn request_stream_enabled(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}
pub(super) fn anthropic_messages_to_openai_chat(
    body: &[u8],
    resolved_model: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let mut messages = Vec::new();
    if let Some(system) = value.get("system") {
        let system_text = anthropic_content_to_text(system);
        if !system_text.trim().is_empty() {
            messages.push(serde_json::json!({"role": "system", "content": system_text}));
        }
    }
    if let Some(items) = value
        .get("messages")
        .and_then(|messages| messages.as_array())
    {
        for item in items {
            let role = item
                .get("role")
                .and_then(|role| role.as_str())
                .unwrap_or("user");
            let content = item
                .get("content")
                .map(anthropic_content_to_text)
                .unwrap_or_default();
            messages.push(serde_json::json!({
                "role": if role == "assistant" { "assistant" } else { "user" },
                "content": content,
            }));
        }
    }
    let mut out = serde_json::json!({
        "model": resolved_model,
        "messages": messages,
    });
    if let Some(max_tokens) = value.get("max_tokens")
        && let Some(object) = out.as_object_mut()
    {
        object.insert("max_tokens".to_string(), max_tokens.clone());
    }
    if let Some(temperature) = value.get("temperature")
        && let Some(object) = out.as_object_mut()
    {
        object.insert("temperature".to_string(), temperature.clone());
    }
    serde_json::to_vec(&out)
}
pub(super) fn anthropic_content_to_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                if item.get("type").and_then(|value| value.as_str()) == Some("text") {
                    item.get("text")
                        .and_then(|text| text.as_str())
                        .map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}
pub(super) fn openai_chat_to_anthropic_message(
    body: &[u8],
    resolved_model: Option<&str>,
) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let choice = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first());
    let text = choice
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .unwrap_or_default();
    let finish_reason = choice
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(|reason| reason.as_str())
        .unwrap_or("stop");
    let stop_reason = match finish_reason {
        "length" => "max_tokens",
        "tool_calls" | "function_call" => "tool_use",
        _ => "end_turn",
    };
    let usage = value.get("usage");
    let input_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens"))
        .and_then(|tokens| tokens.as_i64())
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(|tokens| tokens.as_i64())
        .unwrap_or(0);
    let model = resolved_model
        .map(str::to_string)
        .or_else(|| {
            value
                .get("model")
                .and_then(|model| model.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({
        "id": value.get("id").and_then(|id| id.as_str()).unwrap_or("msg_chisei"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    }))
}
/// Appends one Anthropic SSE event (`event:`/`data:` lines) to `out`.
pub(super) fn push_anthropic_event(out: &mut Vec<u8>, event: &str, data: &serde_json::Value) {
    out.extend_from_slice(format!("event: {event}\ndata: {data}\n\n").as_bytes());
}
/// Whether an Anthropic request carries a `cache_control` breakpoint at a valid
/// position: a tool definition, a `system` content block, or a `messages`
/// content block. Used to keep object-context injection from mutating the
/// cached prefix. Only the top level of each of these blocks is inspected, so a
/// tool `input_schema` property that happens to be named `cache_control` does
/// not false-positive.
pub(super) fn anthropic_has_cache_control(
    object: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let tools_have = object
        .get("tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(block_has_cache_control));
    // A string `system` cannot carry a breakpoint; only array blocks can.
    let system_has = object
        .get("system")
        .and_then(|value| value.as_array())
        .is_some_and(|blocks| blocks.iter().any(block_has_cache_control));
    let messages_have = object
        .get("messages")
        .and_then(|value| value.as_array())
        .is_some_and(|messages| {
            messages.iter().any(|message| {
                message
                    .get("content")
                    .and_then(|content| content.as_array())
                    .is_some_and(|blocks| blocks.iter().any(block_has_cache_control))
            })
        });
    tools_have || system_has || messages_have
}
/// Records only whether the caller explicitly requested a provider cache.
/// The control value and all surrounding prompt content remain unpersisted.
pub(super) fn prompt_cache_requested(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|object| anthropic_has_cache_control(&object))
}
pub(super) fn automatic_cache_attempted(
    profile: Option<&ProviderProfile>,
    prepared_body: &[u8],
) -> bool {
    profile.is_some_and(|profile| {
        let minimum = profile
            .prompt_cache
            .minimum_cacheable_tokens
            .or_else(|| (profile.provider == "openai").then_some(1_024));
        !profile.prompt_cache.explicit_breakpoints
            && profile.usage_normalization.cache_read_tokens
            && minimum
                .is_some_and(|minimum| estimate_cacheable_prompt_tokens(prepared_body) >= minimum)
    })
}
pub(super) fn estimate_cacheable_prompt_tokens(body: &[u8]) -> u64 {
    pub(super) fn string_tokens(value: &serde_json::Value) -> u64 {
        match value {
            serde_json::Value::String(text) => text.split_whitespace().count() as u64,
            serde_json::Value::Array(values) => values.iter().map(string_tokens).sum(),
            serde_json::Value::Object(values) => values.values().map(string_tokens).sum(),
            _ => 0,
        }
    }

    let byte_estimate = body.len().div_ceil(4) as u64;
    let token_dense_estimate = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .map_or(0, |value| string_tokens(&value));
    byte_estimate.max(token_dense_estimate)
}
pub(super) fn block_has_cache_control(block: &serde_json::Value) -> bool {
    block
        .as_object()
        .is_some_and(|map| map.contains_key("cache_control"))
}
/// The error a request carrying the retired `chisei_context` field gets.
pub(super) const CHISEI_CONTEXT_REMOVED: &str = "chisei_context is no longer supported: the gateway \
     does not inject graph data. Select context through native planning (PlanExecution) or read \
     it with the MCP read tools (Search, GetObject, ExpandNeighborhood)";

/// Whether the request body names the retired top-level `chisei_context` field.
pub(super) fn carries_chisei_context(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body)
        .is_ok_and(|object| object.contains_key("chisei_context"))
}
pub(super) fn estimate_tokens_from_bytes(request_bytes: usize) -> i32 {
    request_bytes.div_ceil(4).min(i32::MAX as usize) as i32
}
