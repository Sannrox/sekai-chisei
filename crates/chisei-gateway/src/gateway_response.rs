use super::*;

pub(super) fn extract_response_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = if let Some(usage) = value.get("usage") {
        usage
    } else if value.get("input_tokens").is_some()
        || value.get("prompt_tokens").is_some()
        || value.get("output_tokens").is_some()
        || value.get("completion_tokens").is_some()
        || value.get("total_tokens").is_some()
    {
        &value
    } else {
        return None;
    };
    let input_tokens = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    let provider_total_tokens = non_negative_token_field(usage.get("total_tokens"));
    // Anthropic reports cache tokens as siblings of `input_tokens`; OpenAI nests
    // the cache-read count under `prompt_tokens_details.cached_tokens`. Absent
    // fields stay 0, so non-caching providers and responses are unchanged.
    let cache_read_is_separate = usage.get("cache_read_input_tokens").is_some();
    let cache_read = usage
        .get("cache_read_input_tokens")
        .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
        .and_then(|value| non_negative_token_field(Some(value)));
    let cache_creation = usage
        .get("cache_creation_input_tokens")
        .and_then(|value| non_negative_token_field(Some(value)));
    let cache_creation_5m = usage
        .pointer("/cache_creation/ephemeral_5m_input_tokens")
        .and_then(|value| non_negative_token_field(Some(value)));
    let cache_creation_1h = usage
        .pointer("/cache_creation/ephemeral_1h_input_tokens")
        .and_then(|value| non_negative_token_field(Some(value)));
    let normalized_total = input_tokens
        .saturating_add(output_tokens)
        .saturating_add(cache_creation.unwrap_or(0))
        .saturating_add(if cache_read_is_separate {
            cache_read.unwrap_or(0)
        } else {
            0
        });

    Some(ResponseUsage {
        input_tokens: clamp_i64_to_i32(input_tokens),
        output_tokens: clamp_i64_to_i32(output_tokens),
        total_tokens: clamp_i64_to_i32(normalized_total),
        cache_read_input_tokens: clamp_i64_to_i32(cache_read.unwrap_or(0)),
        cache_creation_input_tokens: clamp_i64_to_i32(cache_creation.unwrap_or(0)),
        cache_creation_5m_input_tokens: clamp_i64_to_i32(cache_creation_5m.unwrap_or(0)),
        cache_creation_1h_input_tokens: clamp_i64_to_i32(cache_creation_1h.unwrap_or(0)),
        cache_read_reported: cache_read.is_some(),
        cache_read_included_in_input: cache_read.is_some() && !cache_read_is_separate,
        cache_creation_reported: cache_creation.is_some(),
        cache_creation_5m_reported: cache_creation_5m.is_some(),
        cache_creation_1h_reported: cache_creation_1h.is_some(),
        provider_total_tokens: provider_total_tokens.map(clamp_i64_to_i32),
    })
}
pub(super) fn non_negative_token_field(value: Option<&serde_json::Value>) -> Option<i64> {
    value
        .and_then(serde_json::Value::as_i64)
        .filter(|value| *value >= 0)
}
pub(super) fn extract_response_observation(body: &[u8]) -> Option<ResponseObservation> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut text = String::new();
    collect_response_text(&value, &mut text);
    let text = truncate_gateway_spec(text.trim());
    if text.is_empty() {
        return None;
    }
    Some(ResponseObservation {
        output_content: text,
        stop_reason: extract_stop_reason(&value),
    })
}
pub(super) fn collect_response_text(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(text) = map.get("output_text").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            if let Some(text) = map.get("text").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            if let Some(text) = map.get("content").and_then(|value| value.as_str()) {
                push_observation_text(out, text);
            }
            for key in ["output", "content", "message", "choices"] {
                if let Some(value) = map.get(key) {
                    collect_response_text(value, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_response_text(item, out);
            }
        }
        _ => {}
    }
}
pub(super) fn push_observation_text(out: &mut String, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}
pub(super) fn extract_stop_reason(value: &serde_json::Value) -> String {
    value
        .get("stop_reason")
        .or_else(|| value.get("finish_reason"))
        .or_else(|| value.pointer("/choices/0/finish_reason"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}
pub(super) fn merge_usage(existing: Option<ResponseUsage>, next: ResponseUsage) -> ResponseUsage {
    let Some(existing) = existing else {
        return next;
    };
    let input_tokens = if next.input_tokens > 0 {
        next.input_tokens
    } else {
        existing.input_tokens
    };
    let output_tokens = if next.output_tokens > 0 {
        next.output_tokens
    } else {
        existing.output_tokens
    };
    let cache_read_input_tokens = if next.cache_read_reported {
        next.cache_read_input_tokens
    } else {
        existing.cache_read_input_tokens
    };
    let cache_creation_input_tokens = if next.cache_creation_reported {
        next.cache_creation_input_tokens
    } else {
        existing.cache_creation_input_tokens
    };
    let cache_creation_5m_input_tokens = if next.cache_creation_5m_reported {
        next.cache_creation_5m_input_tokens
    } else {
        existing.cache_creation_5m_input_tokens
    };
    let cache_creation_1h_input_tokens = if next.cache_creation_1h_reported {
        next.cache_creation_1h_input_tokens
    } else {
        existing.cache_creation_1h_input_tokens
    };
    ResponseUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens
            .saturating_add(output_tokens)
            .saturating_add(
                if next.cache_read_included_in_input
                    || (!next.cache_read_reported && existing.cache_read_included_in_input)
                {
                    0
                } else {
                    cache_read_input_tokens
                },
            )
            .saturating_add(cache_creation_input_tokens),
        cache_read_input_tokens,
        cache_creation_input_tokens,
        cache_creation_5m_input_tokens,
        cache_creation_1h_input_tokens,
        cache_read_reported: next.cache_read_reported || existing.cache_read_reported,
        cache_read_included_in_input: if next.cache_read_reported {
            next.cache_read_included_in_input
        } else {
            existing.cache_read_included_in_input
        },
        cache_creation_reported: next.cache_creation_reported || existing.cache_creation_reported,
        cache_creation_5m_reported: next.cache_creation_5m_reported
            || existing.cache_creation_5m_reported,
        cache_creation_1h_reported: next.cache_creation_1h_reported
            || existing.cache_creation_1h_reported,
        provider_total_tokens: next
            .provider_total_tokens
            .or(existing.provider_total_tokens),
    }
}
/// Extract usage from a fully buffered upstream body, falling back to SSE
/// parsing when the body is an event stream rather than a single JSON
/// document. The ChatGPT Codex backend (chatgpt.com/backend-api/codex) streams
/// SSE without a Content-Type header, so its responses land in the buffered
/// path instead of the streaming tap.
pub(super) fn extract_buffered_body_usage(
    body: &[u8],
) -> (Option<ResponseUsage>, Option<ResponseObservation>) {
    let usage = extract_response_usage(body);
    let observation = extract_response_observation(body);
    if usage.is_some() || observation.is_some() || !body_looks_like_sse(body) {
        return (usage, observation);
    }
    let mut tap = SseUsageTap::new();
    tap.push(body);
    tap.finish()
}
pub(super) fn body_looks_like_sse(body: &[u8]) -> bool {
    String::from_utf8_lossy(body)
        .lines()
        .take(32)
        .any(|line| line.starts_with("data:") || line.starts_with("event:"))
}
pub(super) fn validate_responses_sse_frame(frame: &[u8]) -> Result<bool, String> {
    let text = std::str::from_utf8(frame)
        .map_err(|_| "upstream SSE frame is not valid UTF-8".to_string())?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let data = normalized
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
        .collect::<Vec<_>>();
    if data.is_empty() {
        return Ok(false);
    }
    let data = data.join("\n");
    serde_json::from_str::<serde_json::Value>(&data)
        .map_err(|error| format!("upstream SSE data is invalid JSON: {error}"))?;
    Ok(true)
}
pub(super) async fn send_bounded_stream_bytes(
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, reqwest::Error>>,
    outgoing: Bytes,
) -> bool {
    for offset in (0..outgoing.len()).step_by(STREAM_FORWARD_CHUNK_BYTES) {
        let end = offset
            .saturating_add(STREAM_FORWARD_CHUNK_BYTES)
            .min(outgoing.len());
        if tx.send(Ok(outgoing.slice(offset..end))).await.is_err() {
            return false;
        }
    }
    true
}
pub(super) fn sse_event_terminal(event: &[u8]) -> Option<ResponsesTerminal> {
    let parse = |event: &str| match event {
        "response.completed" => Some(ResponsesTerminal::Completed),
        "response.failed" => Some(ResponsesTerminal::Failed),
        "response.cancelled" => Some(ResponsesTerminal::Cancelled),
        "chisei.response.interrupted" => Some(ResponsesTerminal::Interrupted),
        _ => None,
    };
    let data = extract_sse_data(event)?;
    let text = String::from_utf8_lossy(event);
    let semantic_text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let normalized = semantic_text.replace("\r\n", "\n").replace('\r', "\n");
    let data_value = serde_json::from_str::<serde_json::Value>(&data).ok();
    let event_name = normalized
        .lines()
        .filter_map(|line| {
            if line == "event" {
                Some("")
            } else {
                line.strip_prefix("event:").map(str::trim)
            }
        })
        .next_back();
    let data_event = data_value
        .as_ref()
        .and_then(|value| value.get("type"))
        .and_then(|value| value.as_str());
    let authoritative_event = event_name.or(data_event);
    if let Some(event) = authoritative_event
        && (parse(event).is_some() || event == "response.incomplete")
    {
        let expected_status = match event {
            "response.completed" => "completed",
            "response.incomplete" => "incomplete",
            "response.failed" => "failed",
            "response.cancelled" => "cancelled",
            "chisei.response.interrupted" => "interrupted",
            _ => unreachable!(),
        };
        let response_status = data_value
            .as_ref()
            .and_then(|value| value.get("response"))
            .and_then(|value| value.get("status"))
            .or_else(|| data_value.as_ref().and_then(|value| value.get("status")))
            .and_then(|value| value.as_str());
        if data_event.is_some_and(|data_event| data_event != event)
            || response_status.is_some_and(|status| status != expected_status)
            || (data_event.is_none() && response_status.is_none())
        {
            return Some(ResponsesTerminal::Invalid);
        }
    }
    if authoritative_event == Some("response.incomplete") {
        let reason = data_value
            .as_ref()
            .and_then(|value| value.get("response"))
            .and_then(|value| value.get("incomplete_details"))
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str())
            .unwrap_or("response_incomplete")
            .to_string();
        return Some(ResponsesTerminal::Incomplete(reason));
    }
    if let Some(event) = event_name {
        return parse(event);
    }
    data_event.and_then(parse)
}
/// Decide from the first body bytes whether the stream is SSE. Returns None
/// while the prefix is still too short to tell. SSE streams start with a
/// field line (`data:`, `event:`, `id:`, `retry:`) or a `:` comment line.
pub(super) fn body_prefix_is_sse(bytes: &[u8]) -> Option<bool> {
    const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";
    if bytes.len() < UTF8_BOM.len() && UTF8_BOM.starts_with(bytes) {
        return None;
    }
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let prefix = &bytes[start..];
    if let Some(line_end) = prefix.iter().position(|byte| matches!(byte, b'\n' | b'\r'))
        && matches!(&prefix[..line_end], b"data" | b"event" | b"id" | b"retry")
    {
        return Some(true);
    }
    const SSE_FIELD_PREFIXES: [&[u8]; 5] = [b"data:", b"event:", b"id:", b"retry:", b":"];
    let mut undecided = false;
    for field in SSE_FIELD_PREFIXES {
        if prefix.starts_with(field) {
            return Some(true);
        }
        if field.starts_with(prefix) {
            undecided = true;
        }
    }
    if undecided { None } else { Some(false) }
}
pub(super) fn find_sse_event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    crate::harness::find_frame_boundary(bytes)
        .map(|(frame_end, separator_end)| (frame_end, separator_end - frame_end))
}
pub(super) fn extract_sse_event_usage(event: &[u8]) -> Option<ResponseUsage> {
    let data = extract_sse_data(event)?;
    extract_response_usage(data.as_bytes())
        .or_else(|| extract_nested_response_usage(data.as_bytes()))
        .or_else(|| extract_nested_message_usage(data.as_bytes()))
}
pub(super) fn extract_sse_event_observation(event: &[u8]) -> Option<ResponseObservation> {
    let data = extract_sse_data(event)?;
    let value: serde_json::Value = serde_json::from_str(&data).ok()?;
    let mut text = String::new();
    if let Some(delta) = value
        .pointer("/delta/text")
        .and_then(|value| value.as_str())
    {
        push_observation_text(&mut text, delta);
    }
    if let Some(delta) = value.get("delta").and_then(|value| value.as_str()) {
        push_observation_text(&mut text, delta);
    }
    if let Some(text_value) = value
        .pointer("/content_block/text")
        .and_then(|value| value.as_str())
    {
        push_observation_text(&mut text, text_value);
    }
    collect_response_text(&value, &mut text);
    let text = truncate_gateway_spec(text.trim());
    if text.is_empty() {
        return None;
    }
    Some(ResponseObservation {
        output_content: text,
        stop_reason: extract_stop_reason(&value),
    })
}
pub(super) fn extract_sse_data(event: &[u8]) -> Option<String> {
    let event = event.strip_prefix(b"\xef\xbb\xbf").unwrap_or(event);
    let text = String::from_utf8_lossy(event);
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut data = String::new();
    for line in normalized.lines() {
        if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim_start());
        }
    }
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return None;
    }
    Some(data)
}
pub(super) fn extract_nested_response_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let response = value.get("response")?;
    extract_response_usage(&serde_json::to_vec(response).ok()?)
}
pub(super) fn extract_nested_message_usage(body: &[u8]) -> Option<ResponseUsage> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let message = value.get("message")?;
    extract_response_usage(&serde_json::to_vec(message).ok()?)
}
pub(super) fn extract_request_model(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("model")
                .and_then(|model| model.as_str())
                .map(str::to_string)
        })
}
pub(super) fn extract_gateway_pipeline_spec(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return truncate_gateway_spec(&String::from_utf8_lossy(body));
    };
    let mut parts = Vec::new();
    collect_gateway_spec_text(&value, &mut parts);
    let spec = parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if spec.is_empty() {
        truncate_gateway_spec(&value.to_string())
    } else {
        truncate_gateway_spec(&spec)
    }
}
pub(super) fn collect_gateway_spec_text(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            if !text.trim().is_empty() {
                parts.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_gateway_spec_text(item, parts);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["input", "instructions", "system", "content", "messages"] {
                if let Some(value) = map.get(key) {
                    collect_gateway_spec_text(value, parts);
                }
            }
            if map.get("type").and_then(|value| value.as_str()) == Some("text")
                && let Some(text) = map.get("text").and_then(|value| value.as_str())
                && !text.trim().is_empty()
            {
                parts.push(text.to_string());
            }
        }
        _ => {}
    }
}
pub(super) fn truncate_gateway_spec(value: &str) -> String {
    const MAX_GATEWAY_SPEC_CHARS: usize = 4000;
    value.chars().take(MAX_GATEWAY_SPEC_CHARS).collect()
}
/// Maximum characters of governed object context the gateway will inject into a
/// request, read from `CHISEI_GATEWAY_MAX_OBJECT_CONTEXT_CHARS` (default 4000).
/// Bounds precision-injection so it never balloons the prompt (which would
/// defeat the cost goal) or drown the model in low-signal context.
pub(super) fn max_object_context_chars() -> usize {
    const DEFAULT_MAX_OBJECT_CONTEXT_CHARS: usize = 4000;
    std::env::var("CHISEI_GATEWAY_MAX_OBJECT_CONTEXT_CHARS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_OBJECT_CONTEXT_CHARS)
}
/// Keep whole object contexts in order until the character budget is reached;
/// drop the rest. Returns the kept objects and the number dropped, so injection
/// stays bounded and the drop is auditable. Whole lines are preserved where
/// possible; a single first object whose line is larger than the budget is
/// truncated so the total never exceeds `max_chars`.
pub(super) fn cap_injectable_objects(
    objects: Vec<InjectableObject>,
    max_chars: usize,
) -> (Vec<InjectableObject>, usize) {
    let mut kept: Vec<InjectableObject> = Vec::new();
    let mut used = 0usize;
    let mut dropped = 0usize;
    for mut object in objects {
        if kept.is_empty() {
            // Always inject at least one object's context, hard-truncating it
            // to the budget in the rare case it exceeds the cap on its own.
            if object.line.chars().count() > max_chars {
                object.line = object.line.chars().take(max_chars).collect();
            }
            used = object.line.chars().count();
            kept.push(object);
            continue;
        }
        // Account for the "\n" separator between kept lines.
        let projected = used + 1 + object.line.chars().count();
        if projected <= max_chars {
            used = projected;
            kept.push(object);
        } else {
            dropped += 1;
        }
    }
    (kept, dropped)
}
pub(super) fn clamp_i64_to_i32(value: i64) -> i32 {
    value.clamp(0, i32::MAX as i64) as i32
}
pub(super) async fn response_from_upstream(
    upstream: reqwest::Response,
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    context: UsageContext,
    response_adapter: ResponseAdapter,
    client_response_model: Option<String>,
) -> Response<Body> {
    let status = upstream.status();
    if context.responses_profile && !status.is_success() {
        let retry_after = upstream
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .cloned();
        let mut upstream_stream = upstream.bytes_stream();
        let mut buffered = Vec::new();
        let mut body_error = None;
        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(chunk)
                    if buffered.len().saturating_add(chunk.len()) <= DEFAULT_MAX_REQUEST_BYTES =>
                {
                    buffered.extend_from_slice(&chunk);
                }
                Ok(_) => {
                    body_error = Some("upstream error response exceeds the gateway limit".into());
                    break;
                }
                Err(error) => {
                    body_error = Some(safe_upstream_error_reason(
                        context.provider,
                        "error response",
                        &error,
                    ));
                    break;
                }
            }
        }
        let bytes = match body_error {
            None => Bytes::from(buffered),
            Some(reason) => {
                let rejection = GatewayRejection {
                    status: StatusCode::BAD_GATEWAY,
                    error_type: "upstream_invalid_response".into(),
                    reason,
                    retry_safety: Some("ambiguous"),
                };
                record_usage_and_append(
                    config,
                    runtime,
                    identity,
                    None,
                    None,
                    &context,
                    GatewayUsageOutcome::AccountingOnly(rejection.status),
                )
                .await;
                record_refusal_with_usage_and_append(
                    config, runtime, identity, &context, &rejection, None, true,
                )
                .await;
                return json_error_with_retry_safety(
                    rejection.status,
                    &rejection.error_type,
                    &rejection.reason,
                    "ambiguous",
                );
            }
        };
        let (usage, observation) = extract_buffered_body_usage(&bytes);
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/message")
                    .or_else(|| value.get("message"))
                    .and_then(|message| message.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| format!("upstream provider returned HTTP {status}"));
        record_usage_and_append(
            config,
            runtime,
            identity,
            usage,
            observation,
            &context,
            GatewayUsageOutcome::TerminalFailure(status, "upstream_http_error".into()),
        )
        .await;
        let (code, safety) = match status.as_u16() {
            400 | 404 | 405 | 409 | 413 | 422 => ("invalid_request", "safe"),
            401 | 403 => ("authentication_error", "safe"),
            402 => ("upstream_unavailable", "safe"),
            429 => ("rate_limited", "safe"),
            408 => ("upstream_timeout", "ambiguous"),
            400..=499 => ("invalid_request", "safe"),
            300..=399 => ("upstream_invalid_response", "ambiguous"),
            500..=599 => ("upstream_unavailable", "ambiguous"),
            _ => ("upstream_unavailable", "safe"),
        };
        let mut response = json_error_with_retry_safety(status, code, &message, safety);
        if let Some(value) = retry_after
            && value
                .to_str()
                .ok()
                .and_then(retry_after_value_duration)
                .is_some()
        {
            response
                .headers_mut()
                .insert(reqwest::header::RETRY_AFTER, value);
        }
        return response;
    }
    if status.is_redirection() {
        record_usage_and_append(
            config,
            runtime,
            identity,
            None,
            None,
            &context,
            GatewayUsageOutcome::TerminalFailure(status, "upstream_redirect".into()),
        )
        .await;
        return json_error_with_retry_safety(
            StatusCode::BAD_GATEWAY,
            "upstream_invalid_response",
            "upstream redirects are not followed by the governed gateway",
            "ambiguous",
        );
    }
    let mut builder = Response::builder().status(status);
    let response_headers = upstream.headers().clone();
    for (name, value) in upstream.headers().iter() {
        if should_forward_response_header(name) {
            builder = builder.header(name, value);
        }
    }

    let content_type = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    let declares_sse = content_type.is_some_and(|value| value.starts_with("text/event-stream"));
    // The ChatGPT Codex backend (chatgpt.com/backend-api/codex) streams SSE
    // without a Content-Type header. Passthrough responses with no declared
    // content type stream through so clients keep incremental delivery; the
    // usage tap recovers usage from whole-JSON bodies at flush.
    // A declared SSE content type streams. A missing content type only streams
    // for Passthrough (the ChatGPT Codex backend omits it); cross-provider
    // translation requires a declared SSE stream, so a non-SSE JSON body without
    // a content type falls through to the buffered translator below instead of
    // being swallowed into an empty translated message.
    let is_stream = declares_sse
        || (content_type.is_none() && response_adapter == ResponseAdapter::Passthrough);
    if is_stream {
        // The buffered cross-provider adapter cannot translate a live stream.
        if response_adapter == ResponseAdapter::OpenAiChatToAnthropicMessage {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "unsupported_cross_provider_stream",
                "cross-provider streaming response translation is not supported",
            );
        }
        let translate = response_adapter == ResponseAdapter::OpenAiChatStreamToAnthropicMessage;
        let config = config.clone();
        let runtime = runtime.clone();
        let identity = identity.clone();
        let context = context.clone();
        let client_model = client_response_model
            .or_else(|| context.resolved_model.clone())
            .unwrap_or_default();
        let mut upstream_stream = upstream.bytes_stream();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, reqwest::Error>>(
            STREAM_FORWARD_CHANNEL_CAPACITY,
        );
        tokio::spawn(async move {
            let mut usage_tap = if declares_sse {
                SseUsageTap::sse()
            } else {
                SseUsageTap::new()
            };
            let enforce_responses_terminal =
                context.responses_terminal_required && status.is_success();
            let mut responses_validator =
                enforce_responses_terminal.then(ResponsesStreamValidator::default);
            let mut translator =
                translate.then(|| AnthropicMessageStreamTranslator::new(client_model));
            let mut aborted = false;
            let mut stream_error = None;
            let mut client_gone = false;
            let mut terminal_forwarded = false;
            let mut interruption_forwarded = false;
            let mut terminal_validation_deadline = None;
            loop {
                let next = if let Some(deadline) = terminal_validation_deadline {
                    tokio::time::timeout_at(deadline, upstream_stream.next())
                        .await
                        .unwrap_or_default()
                } else {
                    upstream_stream.next().await
                };
                let Some(chunk) = next else {
                    break;
                };
                match chunk {
                    Ok(bytes) => {
                        // Always tap the upstream (OpenAI) bytes for usage, even
                        // after the client disconnects: OpenAI reports token
                        // counts only in the trailing chunk, so we must keep
                        // draining to meter interrupted streams accurately.
                        let validated_responses_bytes = match responses_validator.as_mut() {
                            Some(validator) => match validator.push(&bytes) {
                                Ok(validated) => Some(Bytes::from(validated)),
                                Err(error) => {
                                    usage_tap.push(&bytes);
                                    stream_error = Some(error.reason.clone());
                                    if !client_gone
                                        && !error.validated.is_empty()
                                        && tx.send(Ok(Bytes::from(error.validated))).await.is_err()
                                    {
                                        client_gone = true;
                                    }
                                    if !terminal_forwarded && !client_gone {
                                        let interruption = interrupted_responses_event(
                                            &error.reason,
                                            usage_tap.usage.as_ref(),
                                        );
                                        interruption_forwarded =
                                            tx.send(Ok(interruption)).await.is_ok();
                                    }
                                    aborted = true;
                                    break;
                                }
                            },
                            None => None,
                        };
                        usage_tap.push(&bytes);
                        if let Some(reason) = usage_tap.overflow_reason() {
                            stream_error = Some(reason.to_string());
                            if usage_tap.mode != SseTapMode::Raw
                                && !terminal_forwarded
                                && !client_gone
                            {
                                let interruption = interrupted_stream_event(
                                    enforce_responses_terminal,
                                    translate || context.provider == ProviderKind::Anthropic,
                                    reason,
                                    usage_tap.usage.as_ref(),
                                );
                                interruption_forwarded = tx.send(Ok(interruption)).await.is_ok();
                            }
                            aborted = true;
                            break;
                        }
                        if terminal_validation_deadline.is_none()
                            && responses_validator
                                .as_ref()
                                .is_some_and(|validator| validator.terminal_seen)
                        {
                            terminal_validation_deadline =
                                Some(tokio::time::Instant::now() + Duration::from_millis(250));
                        }
                        if enforce_responses_terminal
                            && usage_tap.terminal == Some(ResponsesTerminal::Invalid)
                        {
                            let reason =
                                "upstream emitted data after a terminal response event".to_string();
                            stream_error = Some(reason.clone());
                            if !terminal_forwarded && !client_gone {
                                let interruption =
                                    interrupted_responses_event(&reason, usage_tap.usage.as_ref());
                                interruption_forwarded = tx.send(Ok(interruption)).await.is_ok();
                            }
                            aborted = true;
                            break;
                        }
                        if client_gone {
                            continue;
                        }
                        if let Some(translator) = translator.as_mut() {
                            for window in bytes.chunks(SSE_VALIDATION_WINDOW_BYTES) {
                                let outgoing = match translator.push_window(window) {
                                    Ok(translated) => Bytes::from(translated),
                                    Err(reason) => {
                                        stream_error = Some(reason.clone());
                                        if !terminal_forwarded && !client_gone {
                                            let interruption = interrupted_stream_event(
                                                false,
                                                true,
                                                &reason,
                                                usage_tap.usage.as_ref(),
                                            );
                                            interruption_forwarded =
                                                tx.send(Ok(interruption)).await.is_ok();
                                        }
                                        aborted = true;
                                        break;
                                    }
                                };
                                if !outgoing.is_empty()
                                    && !send_bounded_stream_bytes(&tx, outgoing).await
                                {
                                    client_gone = true;
                                    break;
                                }
                            }
                            if aborted {
                                break;
                            }
                            continue;
                        }
                        let outgoing = validated_responses_bytes.unwrap_or(bytes);
                        if outgoing.is_empty() {
                            continue;
                        }
                        if !send_bounded_stream_bytes(&tx, outgoing).await {
                            client_gone = true;
                        }
                    }
                    Err(err) => {
                        stream_error =
                            Some(safe_upstream_error_reason(context.provider, "stream", &err));
                        if enforce_responses_terminal
                            && let Some(validator) = &responses_validator
                            && let Ok(terminal_bytes) = validator.finish()
                            && !terminal_bytes.is_empty()
                            && !client_gone
                        {
                            terminal_forwarded =
                                tx.send(Ok(Bytes::from(terminal_bytes))).await.is_ok();
                        }
                        if !enforce_responses_terminal && !client_gone {
                            let _ = tx.send(Err(err)).await;
                        }
                        aborted = true;
                        break;
                    }
                }
            }
            if !aborted && let Some(validator) = &responses_validator {
                match validator.finish() {
                    Ok(terminal_bytes) => {
                        if !terminal_bytes.is_empty() && !client_gone {
                            terminal_forwarded =
                                tx.send(Ok(Bytes::from(terminal_bytes))).await.is_ok();
                        }
                    }
                    Err(reason) => {
                        stream_error = Some(reason.clone());
                        usage_tap.terminal = Some(ResponsesTerminal::Invalid);
                        if !terminal_forwarded && !client_gone {
                            let interruption =
                                interrupted_responses_event(&reason, usage_tap.usage.as_ref());
                            interruption_forwarded = tx.send(Ok(interruption)).await.is_ok();
                        }
                        aborted = true;
                    }
                }
            }
            // Only emit the Anthropic closing events on a clean end of stream to
            // a still-connected client; after an upstream error or client
            // disconnect the client stream is already terminated.
            if let Some(translator) = translator
                && !aborted
                && !client_gone
            {
                let tail = translator.finish();
                if !tail.is_empty() {
                    let _ = tx.send(Ok(Bytes::from(tail))).await;
                }
            }
            let terminal_validated = terminal_forwarded;
            let (usage, observation, terminal, tap_mode) = usage_tap.finish_with_terminal();
            let missing_responses_terminal = enforce_responses_terminal
                && !terminal_forwarded
                && (aborted || terminal.is_none());
            if missing_responses_terminal
                && tap_mode != SseTapMode::Raw
                && !client_gone
                && !interruption_forwarded
            {
                let terminal_event = interrupted_responses_event(
                    stream_error
                        .as_deref()
                        .unwrap_or("upstream stream ended without a terminal event"),
                    usage.as_ref(),
                );
                let _ = tx.send(Ok(terminal_event)).await;
            }
            let outcome = streaming_gateway_usage_outcome(
                status,
                enforce_responses_terminal,
                terminal,
                aborted,
                terminal_validated,
                missing_responses_terminal,
                stream_error,
            );
            record_usage_and_append(
                &config,
                &runtime,
                &identity,
                usage,
                observation,
                &context,
                outcome,
            )
            .await;
        });
        let stream = ReceiverStream::new(rx);
        return builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|err| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "gateway_response_error",
                    &format!("failed to build upstream response: {err}"),
                )
            });
    }

    match read_bounded_upstream_response(upstream).await {
        Ok(bytes) => {
            let (usage, observation) = extract_buffered_body_usage(&bytes);
            let buffered_terminal = context
                .responses_profile
                .then(|| buffered_responses_terminal(&bytes))
                .flatten();
            let body = match response_adapter {
                ResponseAdapter::Passthrough => bytes.to_vec(),
                // Both cross-provider adapters map a buffered OpenAI chat body to
                // a single Anthropic message. The streaming adapter only lands
                // here when the upstream ignored our stream request and returned
                // a whole JSON body.
                ResponseAdapter::OpenAiChatToAnthropicMessage
                | ResponseAdapter::OpenAiChatStreamToAnthropicMessage => {
                    let response_model = context
                        .resolved_model
                        .as_deref()
                        .and_then(|model| crate::provider_resolution::resolve_model(model).ok());
                    match openai_chat_to_anthropic_message(
                        &bytes,
                        response_model
                            .as_ref()
                            .map(|resolved| resolved.upstream_model.as_str()),
                    ) {
                        Ok(body) => body,
                        Err(err) => {
                            let rejection = GatewayRejection {
                                status: StatusCode::BAD_GATEWAY,
                                error_type: "gateway_response_error".into(),
                                reason: format!(
                                    "failed to translate OpenAI response to Anthropic: {err}"
                                ),
                                retry_safety: None,
                            };
                            record_usage_and_append(
                                config,
                                runtime,
                                identity,
                                usage,
                                observation.clone(),
                                &context,
                                GatewayUsageOutcome::AccountingOnly(rejection.status),
                            )
                            .await;
                            record_refusal_with_usage_and_append(
                                config, runtime, identity, &context, &rejection, usage, true,
                            )
                            .await;
                            return json_error(
                                rejection.status,
                                &rejection.error_type,
                                &rejection.reason,
                            );
                        }
                    }
                }
            };
            let response = match builder.body(Body::from(body)) {
                Ok(response) => response,
                Err(err) => {
                    let rejection = GatewayRejection {
                        status: StatusCode::BAD_GATEWAY,
                        error_type: "gateway_response_error".into(),
                        reason: format!("failed to build upstream response: {err}"),
                        retry_safety: None,
                    };
                    record_usage_and_append(
                        config,
                        runtime,
                        identity,
                        usage,
                        observation.clone(),
                        &context,
                        GatewayUsageOutcome::AccountingOnly(rejection.status),
                    )
                    .await;
                    record_refusal_with_usage_and_append(
                        config, runtime, identity, &context, &rejection, usage, true,
                    )
                    .await;
                    return json_error(rejection.status, &rejection.error_type, &rejection.reason);
                }
            };
            let invalid_terminal = context.responses_terminal_required
                && status.is_success()
                && matches!(buffered_terminal, Some(ResponsesTerminal::Invalid) | None);
            let outcome = buffered_gateway_usage_outcome(
                status,
                context.responses_terminal_required,
                buffered_terminal,
            );
            record_usage_and_append(
                config,
                runtime,
                identity,
                usage,
                observation,
                &context,
                outcome,
            )
            .await;
            if invalid_terminal {
                return json_error_with_retry_safety(
                    StatusCode::BAD_GATEWAY,
                    "upstream_invalid_response",
                    "upstream Responses body is missing a valid terminal status",
                    "ambiguous",
                );
            }
            response
        }
        Err(err) => {
            let reason = match &err {
                BoundedResponseError::Transfer(error) => {
                    safe_upstream_error_reason(context.provider, "response", error)
                }
                BoundedResponseError::TooLarge => format!(
                    "{} upstream response exceeded the {DEFAULT_MAX_RESPONSE_BYTES} byte response limit",
                    context.provider.runtime_name()
                ),
            };
            let rejection = GatewayRejection {
                status: StatusCode::BAD_GATEWAY,
                error_type: "upstream_error".into(),
                reason,
                retry_safety: Some("ambiguous"),
            };
            record_usage_and_append(
                config,
                runtime,
                identity,
                None,
                None,
                &context,
                GatewayUsageOutcome::AccountingOnly(rejection.status),
            )
            .await;
            record_refusal_with_usage_and_append(
                config, runtime, identity, &context, &rejection, None, true,
            )
            .await;
            json_error(rejection.status, &rejection.error_type, &rejection.reason)
        }
    }
}
pub(super) async fn read_bounded_upstream_response(
    upstream: reqwest::Response,
) -> Result<Bytes, BoundedResponseError> {
    if upstream
        .content_length()
        .is_some_and(|length| length > DEFAULT_MAX_RESPONSE_BYTES as u64)
    {
        return Err(BoundedResponseError::TooLarge);
    }
    let mut body = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BoundedResponseError::Transfer)?;
        if buffered_response_exceeds_limit(body.len(), chunk.len()) {
            return Err(BoundedResponseError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}
pub(super) fn buffered_response_exceeds_limit(buffered: usize, next_chunk: usize) -> bool {
    buffered.saturating_add(next_chunk) > DEFAULT_MAX_RESPONSE_BYTES
}
#[cfg(test)]
pub(super) fn buffered_responses_incomplete_reason(body: &[u8]) -> Option<String> {
    match buffered_responses_terminal(body) {
        Some(ResponsesTerminal::Incomplete(reason)) => Some(reason),
        _ => None,
    }
}
pub(super) fn buffered_responses_terminal(body: &[u8]) -> Option<ResponsesTerminal> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value.get("status").and_then(|value| value.as_str())? {
        "completed" => Some(ResponsesTerminal::Completed),
        "incomplete" => Some(ResponsesTerminal::Incomplete(
            value
                .get("incomplete_details")
                .and_then(|value| value.get("reason"))
                .and_then(|value| value.as_str())
                .unwrap_or("response_incomplete")
                .to_string(),
        )),
        "failed" => Some(ResponsesTerminal::Failed),
        "cancelled" => Some(ResponsesTerminal::Cancelled),
        _ => None,
    }
}
pub(super) fn interrupted_responses_event(reason: &str, usage: Option<&ResponseUsage>) -> Bytes {
    let mut response = serde_json::json!({"status": "interrupted"});
    if let Some(usage) = usage {
        response["usage"] = serde_json::json!({
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "total_tokens": usage.total_tokens,
        });
    }
    let payload = serde_json::json!({
        "type": "chisei.response.interrupted",
        "response": response,
        "error": {
            "type": "upstream_stream_error",
            "code": "upstream_unavailable",
            "message": reason,
            "retry_safety": "ambiguous",
        }
    });
    Bytes::from(format!(
        "event: chisei.response.interrupted\ndata: {payload}\n\n"
    ))
}
pub(super) fn interrupted_stream_event(
    responses_profile: bool,
    anthropic_wire: bool,
    reason: &str,
    usage: Option<&ResponseUsage>,
) -> Bytes {
    if responses_profile {
        return interrupted_responses_event(reason, usage);
    }
    let error = serde_json::json!({
        "type": if anthropic_wire { "api_error" } else { "upstream_stream_error" },
        "code": "upstream_unavailable",
        "message": reason,
        "retry_safety": "ambiguous",
    });
    if anthropic_wire {
        let payload = serde_json::json!({"type": "error", "error": error});
        Bytes::from(format!("event: error\ndata: {payload}\n\n"))
    } else {
        Bytes::from(format!("data: {}\n\n", serde_json::json!({"error": error})))
    }
}
pub(super) fn safe_upstream_error_reason(
    provider: ProviderKind,
    stage: &str,
    error: &reqwest::Error,
) -> String {
    let failure = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() {
        "body transfer failed"
    } else if error.is_decode() {
        "response decoding failed"
    } else {
        "failed"
    };
    format!("{} upstream {stage} {failure}", provider.runtime_name())
}
pub(super) fn should_forward_request_header(
    name: &HeaderName,
    auth_mode: UpstreamAuthMode,
) -> bool {
    if is_hop_by_hop(name)
        || name == HOST
        || name == CONTENT_LENGTH
        || name == ACCEPT_ENCODING
        || name == TRACEPARENT
        || name == TRACESTATE
        || is_chisei_header(name)
    {
        // Strip Accept-Encoding so upstreams return identity-encoded bodies the
        // gateway's usage parser (extract_response_usage / SseUsageTap) can read.
        // The reqwest client is built without decompression features, so a
        // compressed upstream body would otherwise parse as zero usage tokens.
        return false;
    }
    if auth_mode == UpstreamAuthMode::GatewayKey && (name == AUTHORIZATION || name == X_API_KEY) {
        return false;
    }
    true
}
pub(super) fn should_strip_isolated_client_credential(
    name: &HeaderName,
    isolated_route: bool,
) -> bool {
    isolated_route && (name == AUTHORIZATION || name == X_API_KEY || name == COOKIE)
}
pub(super) fn is_chisei_header(name: &HeaderName) -> bool {
    name.as_str().starts_with("x-chisei-")
}
pub(super) fn should_forward_response_header(name: &HeaderName) -> bool {
    !is_hop_by_hop(name)
        && name != CONTENT_LENGTH
        && !is_chisei_header(name)
        && name != TRACEPARENT
        && name != TRACESTATE
}
pub(super) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
pub(super) fn json_error(status: StatusCode, error_type: &str, message: &str) -> Response<Body> {
    if let Some(retry_safety) = retry_safety_for_error(error_type) {
        return json_error_with_retry_safety(status, error_type, message, retry_safety);
    }
    let code = stable_gateway_error_code(error_type);
    let body = serde_json::json!({
        "error": {
            "type": error_type,
            "code": code,
            "message": message
        }
    });
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}
pub(super) fn retry_safety_for_error(error_type: &str) -> Option<&'static str> {
    match error_type {
        "rate_limited" | "rate_limit_exceeded" | "upstream_rate_limited" => Some("safe"),
        "governance_unavailable"
        | "governance_audit_unavailable"
        | "provider_registry_unavailable"
        | "audit_unavailable"
        | "recovery_spool_unavailable" => Some("safe"),
        "upstream_timeout"
        | "upstream_unavailable"
        | "upstream_error"
        | "upstream_stream_error" => Some("ambiguous"),
        _ => None,
    }
}
pub(super) fn json_error_with_retry_safety(
    status: StatusCode,
    error_type: &str,
    message: &str,
    retry_safety: &'static str,
) -> Response<Body> {
    let code = stable_gateway_error_code(error_type);
    let body = serde_json::json!({
        "error": {
            "type": error_type,
            "code": code,
            "message": message,
            "retry_safety": retry_safety,
        }
    });
    (
        status,
        [
            (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                X_CHISEI_RETRY_SAFETY,
                HeaderValue::from_static(retry_safety),
            ),
        ],
        body.to_string(),
    )
        .into_response()
}
pub(super) fn stable_gateway_error_code(error_type: &str) -> &'static str {
    match error_type {
        "authentication_error" | "invalid_api_key" | "unauthorized" => "authentication_error",
        "policy_denied" | "governance_denied" | "context_denied" => "policy_denied",
        "budget_exceeded" => "budget_exceeded",
        "capability_unsupported"
        | "unsupported_cross_provider_stream"
        | "unsupported_cross_provider_route" => "capability_unsupported",
        "request_conflict"
        | "request_id_conflict"
        | "usage_recovery_required"
        | "governance_precondition" => "request_conflict",
        "rate_limited" | "rate_limit_exceeded" => "rate_limited",
        "upstream_rate_limited" => "rate_limited",
        "upstream_quota_exhausted" => "upstream_unavailable",
        "upstream_timeout" => "upstream_timeout",
        "upstream_unavailable"
        | "provider_registry_unavailable"
        | "upstream_error"
        | "upstream_stream_error"
        | "governance_unavailable"
        | "governance_audit_unavailable"
        | "audit_unavailable"
        | "recovery_spool_unavailable" => "upstream_unavailable",
        "upstream_invalid_response" | "gateway_response_error" => "upstream_invalid_response",
        "invalid_request"
        | "invalid_request_error"
        | "invalid_correlation"
        | "not_found"
        | "context_not_found"
        | "governance_not_found" => "invalid_request",
        "internal_error" | "gateway_config_error" => "internal_error",
        _ => "internal_error",
    }
}
pub(super) fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}
