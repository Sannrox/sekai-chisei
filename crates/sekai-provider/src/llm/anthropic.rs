use super::{
    ChatRequest, ChatResponse, ChatStream, ChatStreamChunk, HttpTimeouts,
    MAX_PROVIDER_RESPONSE_BYTES, Provider, SamplingOptions, ToolCall, classify_reqwest_error,
    ensure_declared_response_size, read_bounded_response,
};
use crate::content::{ContentChatRequest, ContentKind, ResolvedPayload};
use base64::Engine as _;
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct Anthropic {
    api_key: String,
    base_url: String,
    client: Client,
    timeouts: HttpTimeouts,
}

impl Anthropic {
    pub fn new(api_key: &str) -> Self {
        Self::with_base_url_and_timeouts(
            api_key,
            "https://api.anthropic.com",
            HttpTimeouts::from_env(),
        )
    }

    pub(crate) fn with_base_url_and_timeouts(
        api_key: &str,
        base_url: &str,
        timeouts: HttpTimeouts,
    ) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: base_url.to_string(),
            client: timeouts.client(),
            timeouts,
        }
    }
}

#[async_trait::async_trait]
impl Provider for Anthropic {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String> {
        self.chat_with_sampling(req, SamplingOptions::default())
            .await
    }

    async fn chat_with_sampling(
        &self,
        req: &ChatRequest,
        sampling: SamplingOptions,
    ) -> Result<ChatResponse, String> {
        let body = messages_body_with_sampling(req, false, sampling);

        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(url)
            .timeout(self.timeouts.request_timeout)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error("anthropic chat request", err))?;

        let status = resp.status();
        ensure_declared_response_size(resp.content_length(), "anthropic chat response")?;
        let body = read_bounded_response(resp, "anthropic chat response").await?;
        let text = String::from_utf8_lossy(&body);
        if !status.is_success() {
            return Err(format!("anthropic {}: {}", status, text));
        }

        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let content = anthropic_text_content(&v);
        let tool_calls = v["content"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|b| b["type"] == "tool_use")
                    .map(|b| ToolCall {
                        id: b["id"].as_str().unwrap_or("").into(),
                        name: b["name"].as_str().unwrap_or("").into(),
                        args: b["input"].clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            tool_calls,
            input_tokens: v["usage"]["input_tokens"].as_i64().unwrap_or(0) as i32,
            output_tokens: v["usage"]["output_tokens"].as_i64().unwrap_or(0) as i32,
            stop_reason: v["stop_reason"].as_str().unwrap_or("").to_string(),
            cache_read_input_tokens: usage_tokens(&v["usage"], "cache_read_input_tokens"),
            cache_creation_input_tokens: usage_tokens(&v["usage"], "cache_creation_input_tokens"),
        })
    }

    async fn content_chat(&self, req: &ContentChatRequest) -> Result<ChatResponse, String> {
        let body = content_messages_body(req)?;
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(url)
            .timeout(self.timeouts.request_timeout)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error("anthropic content request", err))?;
        let status = resp.status();
        ensure_declared_response_size(resp.content_length(), "anthropic content response")?;
        let body = read_bounded_response(resp, "anthropic content response").await?;
        let text = String::from_utf8_lossy(&body);
        if !status.is_success() {
            return Err(format!("anthropic {}: {}", status, text));
        }
        parse_anthropic_content_response(&text)
    }

    async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, String> {
        let body = messages_body(req, true);
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error("anthropic stream request", err))?;

        let status = resp.status();
        ensure_declared_response_size(resp.content_length(), "anthropic stream response")?;
        if !status.is_success() {
            let body = read_bounded_response(resp, "anthropic stream response").await?;
            let text = String::from_utf8_lossy(&body);
            return Err(format!("anthropic {}: {}", status, text));
        }

        let stream = resp.bytes_stream();
        Ok(Box::pin(async_stream::stream! {
            let mut buffer = String::new();
            let mut content = String::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut cache_read_input_tokens = 0;
            let mut cache_creation_input_tokens = 0;
            let mut stop_reason = String::new();
            let mut tool_calls = BTreeMap::new();
            let mut emitted_done = false;
            let mut received_bytes = 0usize;

            futures_util::pin_mut!(stream);
            while let Some(next) = stream.next().await {
                let bytes = match next {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        yield Err(classify_reqwest_error("anthropic stream read", err));
                        return;
                    }
                };
                received_bytes = received_bytes.saturating_add(bytes.len());
                if received_bytes > MAX_PROVIDER_RESPONSE_BYTES {
                    yield Err(format!(
                        "anthropic stream response exceeded the {} byte response limit",
                        MAX_PROVIDER_RESPONSE_BYTES
                    ));
                    return;
                }
                buffer.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(index) = buffer.find("\n\n") {
                    let event = buffer[..index].to_string();
                    // Drain in place so many small SSE frames do not copy the
                    // unread tail into a fresh String on every event boundary.
                    buffer.drain(..index + 2);
                    let parsed = parse_anthropic_sse_event(
                        &event,
                        &mut content,
                        &mut input_tokens,
                        &mut output_tokens,
                        &mut cache_read_input_tokens,
                        &mut cache_creation_input_tokens,
                        &mut stop_reason,
                        &mut tool_calls,
                        &mut emitted_done,
                    );
                    let chunks = match parsed {
                        Ok(chunks) => chunks,
                        Err(error) => {
                            yield Err(error);
                            return;
                        }
                    };
                    for chunk in chunks {
                        yield Ok(chunk);
                    }
                }
            }
            if !buffer.trim().is_empty() {
                // A non-empty unread tail after the byte stream ends is only
                // acceptable when it is itself a complete terminal frame
                // (for example `message_stop` without a trailing delimiter).
                // Otherwise refuse to synthesize a successful completion.
                let parsed = parse_anthropic_sse_event(
                    &buffer,
                    &mut content,
                    &mut input_tokens,
                    &mut output_tokens,
                    &mut cache_read_input_tokens,
                    &mut cache_creation_input_tokens,
                    &mut stop_reason,
                    &mut tool_calls,
                    &mut emitted_done,
                );
                let chunks = match parsed {
                    Ok(chunks) if emitted_done => chunks,
                    Ok(_) => {
                        yield Err(
                            "anthropic stream ended with an incomplete SSE frame".into(),
                        );
                        return;
                    }
                    Err(error) => {
                        yield Err(error);
                        return;
                    }
                };
                for chunk in chunks {
                    yield Ok(chunk);
                }
            }
            if !emitted_done {
                let tool_calls = match completed_anthropic_tool_calls(&tool_calls) {
                    Ok(tool_calls) => tool_calls,
                    Err(error) => {
                        yield Err(error);
                        return;
                    }
                };
                yield Ok(ChatStreamChunk {
                    content_delta: String::new(),
                    content,
                    tool_calls,
                    input_tokens,
                    output_tokens,
                    stop_reason,
                    done: true,
                    cache_read_input_tokens,
                    cache_creation_input_tokens,
                });
            }
        }))
    }
}

fn messages_body(req: &ChatRequest, stream: bool) -> Value {
    messages_body_with_sampling(req, stream, SamplingOptions::default())
}

fn messages_body_with_sampling(
    req: &ChatRequest,
    stream: bool,
    sampling: SamplingOptions,
) -> Value {
    let mut messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m| {
            if m.role == "tool" {
                json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": m.content,
                    }]
                })
            } else if !m.tool_calls.is_empty() {
                let mut content = Vec::new();
                if !m.content.is_empty() {
                    content.push(json!({"type": "text", "text": m.content}));
                }
                for tc in &m.tool_calls {
                    content.push(json!({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": if req.prompt_cache.enabled {
                            canonical_json(&tc.args)
                        } else {
                            tc.args.clone()
                        },
                    }));
                }
                json!({
                    "role": m.role,
                    "content": content,
                })
            } else {
                json!({"role": m.role, "content": m.content})
            }
        })
        .collect();
    if req.prompt_cache.enabled
        && req.prompt_cache.cacheable_message_count > 0
        && let Some(message) =
            messages.get_mut(req.prompt_cache.cacheable_message_count.saturating_sub(1))
    {
        add_cache_control_to_message(message);
    }
    let mut body = json!({
        "model": req.model,
        "max_tokens": if req.max_tokens > 0 { req.max_tokens } else { 4096 },
        "messages": messages,
    });
    if let Some(value) = sampling.temperature_millis {
        body["temperature"] = json!(f64::from(value) / 1_000.0);
    }
    if let Some(value) = sampling.top_p_millionths {
        body["top_p"] = json!(f64::from(value) / 1_000_000.0);
    }
    if !req.system.is_empty() {
        body["system"] = if req.prompt_cache.enabled {
            json!([{"type": "text", "text": req.system, "cache_control": {"type": "ephemeral"}}])
        } else {
            json!(req.system)
        };
    }
    if !req.tools.is_empty() {
        let mut tools = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": if req.prompt_cache.enabled {
                        canonical_json(&t.input_schema)
                    } else {
                        t.input_schema.clone()
                    },
                })
            })
            .collect::<Vec<_>>();
        if req.prompt_cache.enabled
            && let Some(last) = tools.last_mut()
        {
            last["cache_control"] = json!({"type": "ephemeral"});
        }
        body["tools"] = json!(tools);
    }
    if stream {
        body["stream"] = json!(true);
    }
    body
}

fn content_messages_body(req: &ContentChatRequest) -> Result<Value, String> {
    let messages = req
        .messages
        .iter()
        .map(|message| {
            if message.role == "tool" {
                if message.parts.len() != 1 || message.parts[0].descriptor.kind != ContentKind::Text
                {
                    return Err(
                        "Anthropic tool results support exactly one text content part".into(),
                    );
                }
                let ResolvedPayload::Text(text) = &message.parts[0].payload else {
                    return Err("Anthropic tool result text payload required".into());
                };
                return Ok(json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": message.tool_call_id,
                        "content": text,
                    }]
                }));
            }
            let mut content = message
                .parts
                .iter()
                .map(|part| match (&part.descriptor.kind, &part.payload) {
                    (ContentKind::Text, ResolvedPayload::Text(text)) => {
                        Ok(json!({"type": "text", "text": text}))
                    }
                    (ContentKind::Image, ResolvedPayload::Bytes(bytes)) => Ok(json!({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": part.descriptor.media_type,
                            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                        }
                    })),
                    (ContentKind::Audio | ContentKind::Document, _) => {
                        Err("Anthropic content adapter does not support audio or document input")
                    }
                    _ => Err("resolved content payload does not match its declared kind"),
                })
                .collect::<Result<Vec<_>, _>>()?;
            for call in &message.tool_calls {
                content.push(json!({
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.args,
                }));
            }
            if content.is_empty() {
                return Err("Anthropic content message cannot be empty".into());
            }
            Ok(json!({"role": message.role, "content": content}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut body = json!({
        "model": req.model,
        "max_tokens": if req.max_tokens > 0 { req.max_tokens } else { 4096 },
        "messages": messages,
    });
    if !req.system.is_empty() {
        body["system"] = json!(req.system);
    }
    if !req.tools.is_empty() {
        body["tools"] = json!(
            req.tools
                .iter()
                .map(|tool| json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }))
                .collect::<Vec<_>>()
        );
    }
    Ok(body)
}

fn parse_anthropic_content_response(text: &str) -> Result<ChatResponse, String> {
    let value: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let content = anthropic_text_content(&value);
    let tool_calls = value["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block["type"] == "tool_use")
                .map(|block| ToolCall {
                    id: block["id"].as_str().unwrap_or("").into(),
                    name: block["name"].as_str().unwrap_or("").into(),
                    args: block["input"].clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ChatResponse {
        content,
        tool_calls,
        input_tokens: value["usage"]["input_tokens"].as_i64().unwrap_or(0) as i32,
        output_tokens: value["usage"]["output_tokens"].as_i64().unwrap_or(0) as i32,
        stop_reason: value["stop_reason"].as_str().unwrap_or("").to_string(),
        cache_read_input_tokens: usage_tokens(&value["usage"], "cache_read_input_tokens"),
        cache_creation_input_tokens: usage_tokens(&value["usage"], "cache_creation_input_tokens"),
    })
}

fn anthropic_text_content(value: &Value) -> String {
    value["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|block| block["type"] == "text")
        .filter_map(|block| block["text"].as_str())
        .collect()
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_json(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

fn add_cache_control_to_message(message: &mut Value) {
    let Some(content) = message.get_mut("content") else {
        return;
    };
    if let Some(text) = content.as_str().map(str::to_string) {
        *content = json!([{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]);
    } else if let Some(block) = content.as_array_mut().and_then(|blocks| blocks.last_mut()) {
        block["cache_control"] = json!({"type": "ephemeral"});
    }
}

fn usage_tokens(usage: &Value, field: &str) -> i32 {
    usage[field]
        .as_i64()
        .and_then(|value| i32::try_from(value.max(0)).ok())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
struct AnthropicToolCallAssembly {
    id: String,
    name: String,
    arguments: String,
}

#[allow(clippy::too_many_arguments)]
fn parse_anthropic_sse_event(
    event: &str,
    content: &mut String,
    input_tokens: &mut i32,
    output_tokens: &mut i32,
    cache_read_input_tokens: &mut i32,
    cache_creation_input_tokens: &mut i32,
    stop_reason: &mut String,
    tool_calls: &mut BTreeMap<u64, AnthropicToolCallAssembly>,
    emitted_done: &mut bool,
) -> Result<Vec<ChatStreamChunk>, String> {
    let mut chunks = Vec::new();
    for data in event_data_values(event) {
        if data.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&data)
            .map_err(|error| format!("anthropic stream received malformed SSE JSON: {error}"))?;
        match value["type"].as_str().unwrap_or("") {
            "message_start" => {
                *input_tokens = value["message"]["usage"]["input_tokens"]
                    .as_i64()
                    .unwrap_or(0) as i32;
                *cache_read_input_tokens =
                    usage_tokens(&value["message"]["usage"], "cache_read_input_tokens");
                *cache_creation_input_tokens =
                    usage_tokens(&value["message"]["usage"], "cache_creation_input_tokens");
            }
            "content_block_start" if value["content_block"]["type"] == "tool_use" => {
                let index = value["index"]
                    .as_u64()
                    .ok_or_else(|| "anthropic tool-use block omitted index".to_string())?;
                let assembly = tool_calls.entry(index).or_default();
                merge_anthropic_tool_call_field(
                    &mut assembly.id,
                    &value["content_block"]["id"],
                    "id",
                )?;
                merge_anthropic_tool_call_field(
                    &mut assembly.name,
                    &value["content_block"]["name"],
                    "name",
                )?;
                let input = &value["content_block"]["input"];
                if !input.is_null() && input.as_object().is_none_or(|object| !object.is_empty()) {
                    assembly.arguments.push_str(&input.to_string());
                }
            }
            "content_block_delta" => {
                if value["delta"]["type"] == "input_json_delta" {
                    let index = value["index"]
                        .as_u64()
                        .ok_or_else(|| "anthropic tool-use delta omitted index".to_string())?;
                    let assembly = tool_calls.get_mut(&index).ok_or_else(|| {
                        "anthropic tool-use delta preceded its start block".to_string()
                    })?;
                    let partial = value["delta"]["partial_json"].as_str().ok_or_else(|| {
                        "anthropic tool-use delta omitted partial_json".to_string()
                    })?;
                    assembly.arguments.push_str(partial);
                }
                if let Some(delta) = value["delta"]["text"]
                    .as_str()
                    .filter(|delta| !delta.is_empty())
                {
                    content.push_str(delta);
                    chunks.push(ChatStreamChunk {
                        content_delta: delta.to_string(),
                        content: content.clone(),
                        tool_calls: Vec::new(),
                        input_tokens: *input_tokens,
                        output_tokens: *output_tokens,
                        stop_reason: stop_reason.clone(),
                        done: false,
                        cache_read_input_tokens: *cache_read_input_tokens,
                        cache_creation_input_tokens: *cache_creation_input_tokens,
                    });
                }
            }
            "message_delta" => {
                if let Some(reason) = value["delta"]["stop_reason"].as_str() {
                    *stop_reason = reason.to_string();
                }
                *output_tokens = value["usage"]["output_tokens"].as_i64().unwrap_or(0) as i32;
            }
            "message_stop" if !*emitted_done => {
                *emitted_done = true;
                let completed_tool_calls = completed_anthropic_tool_calls(tool_calls)?;
                chunks.push(ChatStreamChunk {
                    content_delta: String::new(),
                    content: content.clone(),
                    tool_calls: completed_tool_calls,
                    input_tokens: *input_tokens,
                    output_tokens: *output_tokens,
                    stop_reason: stop_reason.clone(),
                    done: true,
                    cache_read_input_tokens: *cache_read_input_tokens,
                    cache_creation_input_tokens: *cache_creation_input_tokens,
                });
            }
            _ => {}
        }
    }
    Ok(chunks)
}

fn merge_anthropic_tool_call_field(
    current: &mut String,
    value: &Value,
    field: &str,
) -> Result<(), String> {
    let value = value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("anthropic tool-use block omitted {field}"))?;
    if !current.is_empty() && current != value {
        return Err(format!("anthropic tool-use {field} changed during stream"));
    }
    current.clear();
    current.push_str(value);
    Ok(())
}

fn completed_anthropic_tool_calls(
    tool_calls: &BTreeMap<u64, AnthropicToolCallAssembly>,
) -> Result<Vec<ToolCall>, String> {
    tool_calls
        .values()
        .map(|call| {
            if call.id.is_empty() || call.name.is_empty() {
                return Err("anthropic stream ended with incomplete tool-use identity".into());
            }
            let args = serde_json::from_str(if call.arguments.is_empty() {
                "{}"
            } else {
                &call.arguments
            })
            .map_err(|_| "anthropic stream ended with invalid tool-use arguments".to_string())?;
            Ok(ToolCall {
                id: call.id.clone(),
                name: call.name.clone(),
                args,
            })
        })
        .collect()
}

fn event_data_values(event: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in event.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(value) = line.strip_prefix("data:") {
            values.push(value.trim_start().to_string());
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{
        Anthropic, content_messages_body, messages_body, messages_body_with_sampling,
        parse_anthropic_content_response, parse_anthropic_sse_event,
    };
    use crate::content::{
        ContentChatRequest, ContentDescriptor, ContentKind, ContentMessage, ContentProvenance,
        DisclosureState, ResolvedContentPart, ResolvedPayload,
    };
    use crate::llm::{
        ChatRequest, HttpTimeouts, Message, PromptCacheIntent, Provider, SamplingOptions, ToolDef,
    };
    use axum::Router;
    use axum::routing::post;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn test_timeouts() -> HttpTimeouts {
        HttpTimeouts {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            pool_idle_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_millis(50),
        }
    }

    fn test_chat_request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-8".to_string(),
            system: String::new(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: 16,
            prompt_cache: Default::default(),
        }
    }

    fn content_part(
        kind: ContentKind,
        media_type: &str,
        payload: ResolvedPayload,
    ) -> ResolvedContentPart {
        ResolvedContentPart {
            descriptor: ContentDescriptor {
                part_id: format!("{}-1", kind.modality()),
                kind,
                media_type: media_type.into(),
                byte_length: payload.as_bytes().len() as u64,
                sha256_digest: format!("sha256:{}", "0".repeat(64)),
                reference: format!("fixture:{}", kind.modality()),
                provenance: ContentProvenance {
                    source: "fixture".into(),
                    source_id: "provider-map".into(),
                    source_version: "v1".into(),
                    observed_at_ms: 1,
                },
                disclosure_state: DisclosureState::Accepted,
                disclosure_reason: String::new(),
            },
            payload,
        }
    }

    fn content_request(parts: Vec<ResolvedContentPart>) -> ContentChatRequest {
        ContentChatRequest {
            model: "claude-sonnet-fixture".into(),
            system: String::new(),
            messages: vec![ContentMessage {
                role: "user".into(),
                parts,
                tool_call_id: String::new(),
                tool_calls: Vec::new(),
            }],
            tools: Vec::new(),
            max_tokens: 16,
        }
    }

    #[test]
    fn content_body_maps_text_and_image_as_typed_blocks() {
        let body = content_messages_body(&content_request(vec![
            content_part(
                ContentKind::Text,
                "text/plain",
                ResolvedPayload::Text("describe".into()),
            ),
            content_part(
                ContentKind::Image,
                "image/png",
                ResolvedPayload::Bytes(b"png".to_vec()),
            ),
        ]))
        .unwrap();
        assert_eq!(body["messages"][0]["content"][0]["type"], "text");
        assert_eq!(body["messages"][0]["content"][1]["type"], "image");
        assert_eq!(
            body["messages"][0]["content"][1]["source"]["media_type"],
            "image/png"
        );
    }

    #[test]
    fn content_body_denies_documents_instead_of_coercing_them() {
        let error = content_messages_body(&content_request(vec![content_part(
            ContentKind::Document,
            "application/pdf",
            ResolvedPayload::Bytes(b"pdf".to_vec()),
        )]))
        .unwrap_err();
        assert!(error.contains("does not support audio or document"));
    }

    #[test]
    fn content_body_rejects_empty_messages_but_keeps_assistant_tool_calls() {
        let mut request = content_request(Vec::new());
        assert!(content_messages_body(&request).is_err());
        request.messages[0].role = "assistant".into();
        request.messages[0].tool_calls = vec![crate::llm::ToolCall {
            id: "call-1".into(),
            name: "lookup".into(),
            args: json!({}),
        }];
        let body = content_messages_body(&request).unwrap();
        assert_eq!(
            body["messages"][0]["content"][0]["type"],
            serde_json::Value::String("tool_use".into())
        );
    }

    #[test]
    fn content_response_preserves_all_ordered_text_blocks() {
        let response = parse_anthropic_content_response(
            r#"{
                "content": [
                    {"type": "text", "text": "before "},
                    {"type": "tool_use", "id": "call-1", "name": "lookup", "input": {}},
                    {"type": "text", "text": "after"}
                ],
                "usage": {"input_tokens": 1, "output_tokens": 2},
                "stop_reason": "tool_use"
            }"#,
        )
        .unwrap();
        assert_eq!(response.content, "before after");
        assert_eq!(response.tool_calls.len(), 1);
    }

    #[test]
    fn messages_body_forwards_supported_sampling_controls() {
        let request = test_chat_request();
        let body = messages_body_with_sampling(
            &request,
            false,
            SamplingOptions {
                temperature_millis: Some(400),
                top_p_millionths: Some(750_000),
                seed: None,
            },
        );

        assert_eq!(body["temperature"], 0.4);
        assert_eq!(body["top_p"], 0.75);
        assert!(body.get("seed").is_none());
    }

    async fn delayed_messages_response() -> axum::Json<serde_json::Value> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        axum::Json(serde_json::json!({
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "stop_reason": "end_turn"
        }))
    }

    async fn spawn_delayed_anthropic() -> String {
        let app = Router::new().route("/v1/messages", post(delayed_messages_response));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn parses_messages_stream_delta_usage_and_stop() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut cache_read_input_tokens = 0;
        let mut cache_creation_input_tokens = 0;
        let mut stop_reason = String::new();
        let mut tool_calls = BTreeMap::new();
        let mut emitted_done = false;

        parse_anthropic_sse_event(
            "event: message_start\n\
             data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut cache_read_input_tokens,
            &mut cache_creation_input_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(input_tokens, 11);

        let chunks = parse_anthropic_sse_event(
            "event: content_block_delta\n\
             data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut cache_read_input_tokens,
            &mut cache_creation_input_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content_delta, "hi");
        assert_eq!(chunks[0].content, "hi");
        assert!(!chunks[0].done);

        parse_anthropic_sse_event(
            "event: message_delta\n\
             data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut cache_read_input_tokens,
            &mut cache_creation_input_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(output_tokens, 3);
        assert_eq!(stop_reason, "end_turn");

        let chunks = parse_anthropic_sse_event(
            "event: message_stop\n\
             data: {\"type\":\"message_stop\"}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut cache_read_input_tokens,
            &mut cache_creation_input_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].done);
        assert_eq!(chunks[0].content, "hi");
        assert_eq!(chunks[0].input_tokens, 11);
        assert_eq!(chunks[0].output_tokens, 3);
        assert_eq!(chunks[0].stop_reason, "end_turn");
    }

    #[test]
    fn rejects_malformed_sse_json_instead_of_silent_skip() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut cache_read_input_tokens = 0;
        let mut cache_creation_input_tokens = 0;
        let mut stop_reason = String::new();
        let mut tool_calls = BTreeMap::new();
        let mut emitted_done = false;

        let error = parse_anthropic_sse_event(
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut cache_read_input_tokens,
            &mut cache_creation_input_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap_err();
        assert!(
            error.contains("malformed SSE JSON"),
            "expected malformed SSE JSON error, got {error}"
        );
        assert!(!emitted_done);
    }

    #[test]
    fn preserves_fragmented_interleaved_tool_uses() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut cache_read_input_tokens = 0;
        let mut cache_creation_input_tokens = 0;
        let mut stop_reason = String::new();
        let mut tool_calls = BTreeMap::new();
        let mut emitted_done = false;

        for event in [
            r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_b","name":"write","input":{}}}"#,
            r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_a","name":"read","input":{}}}"#,
            r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#,
            r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#,
            r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"b.txt\"}"}}"#,
            r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"a.txt\"}"}}"#,
            r#"data: {"type":"message_stop"}"#,
        ] {
            let chunks = parse_anthropic_sse_event(
                event,
                &mut content,
                &mut input_tokens,
                &mut output_tokens,
                &mut cache_read_input_tokens,
                &mut cache_creation_input_tokens,
                &mut stop_reason,
                &mut tool_calls,
                &mut emitted_done,
            )
            .unwrap();
            if event.contains("message_stop") {
                let terminal = chunks.into_iter().next().unwrap();
                assert!(terminal.done);
                assert_eq!(terminal.tool_calls.len(), 2);
                assert_eq!(terminal.tool_calls[0].id, "call_a");
                assert_eq!(terminal.tool_calls[0].name, "read");
                assert_eq!(terminal.tool_calls[0].args, json!({"path":"a.txt"}));
                assert_eq!(terminal.tool_calls[1].id, "call_b");
                assert_eq!(terminal.tool_calls[1].name, "write");
                assert_eq!(terminal.tool_calls[1].args, json!({"path":"b.txt"}));
            }
        }
    }

    #[test]
    fn native_cache_fixture_places_breakpoints_before_dynamic_context() {
        let request = ChatRequest {
            model: "claude-sonnet-4-8".into(),
            system: "Stable system".into(),
            messages: vec![
                Message {
                    role: "user".into(),
                    content: "Stable document".into(),
                    tool_call_id: String::new(),
                    tool_calls: vec![],
                },
                Message {
                    role: "assistant".into(),
                    content: "Stable answer".into(),
                    tool_call_id: String::new(),
                    tool_calls: vec![],
                },
                Message {
                    role: "user".into(),
                    content: "request-id=dynamic".into(),
                    tool_call_id: String::new(),
                    tool_calls: vec![],
                },
            ],
            tools: vec![ToolDef {
                name: "lookup".into(),
                description: "Stable tool".into(),
                input_schema: serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}}),
            }],
            max_tokens: 64,
            prompt_cache: PromptCacheIntent {
                enabled: true,
                cacheable_message_count: 2,
            },
        };

        let body = messages_body(&request, false);
        assert_eq!(body["tools"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(
            body["messages"][1]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert!(body["messages"][2]["content"].is_string());
        assert_eq!(
            serde_json::to_string(&body["tools"][0]["input_schema"]).unwrap(),
            r#"{"a":{"b":3,"y":2},"z":1}"#
        );

        let mut changed = request.clone();
        changed.messages[2].content = "request-id=other".into();
        let changed_body = messages_body(&changed, false);
        assert_eq!(body["tools"], changed_body["tools"]);
        assert_eq!(body["system"], changed_body["system"]);
        assert_eq!(body["messages"][0], changed_body["messages"][0]);
        assert_eq!(body["messages"][1], changed_body["messages"][1]);
        assert_ne!(body["messages"][2], changed_body["messages"][2]);
    }

    #[test]
    fn uncached_and_tool_result_requests_keep_expected_wire_shape() {
        let uncached = ChatRequest {
            model: "claude-sonnet-4-8".into(),
            system: "system".into(),
            messages: vec![Message {
                role: "tool".into(),
                content: "result".into(),
                tool_call_id: "call-1".into(),
                tool_calls: vec![],
            }],
            tools: vec![],
            max_tokens: 16,
            prompt_cache: PromptCacheIntent::default(),
        };
        let body = messages_body(&uncached, true);
        assert_eq!(body["system"], "system");
        assert_eq!(body["messages"][0]["content"][0]["type"], "tool_result");
        assert!(!body.to_string().contains("cache_control"));
        assert_eq!(body["stream"], true);

        let mut cached = uncached;
        cached.prompt_cache = PromptCacheIntent {
            enabled: true,
            cacheable_message_count: 1,
        };
        let cached_body = messages_body(&cached, false);
        assert_eq!(
            cached_body["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
    }

    #[tokio::test]
    async fn unary_chat_times_out_against_slow_upstream() {
        let base_url = spawn_delayed_anthropic().await;
        let provider =
            Anthropic::with_base_url_and_timeouts("test-key", &base_url, test_timeouts());
        let err = tokio::time::timeout(Duration::from_secs(2), provider.chat(&test_chat_request()))
            .await
            .unwrap()
            .unwrap_err();

        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
