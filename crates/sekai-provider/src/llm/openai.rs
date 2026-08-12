use super::{
    ChatRequest, ChatResponse, ChatStream, ChatStreamChunk, HttpTimeouts,
    MAX_PROVIDER_RESPONSE_BYTES, Provider, SamplingOptions, ToolCall, classify_reqwest_error,
    ensure_declared_response_size, read_bounded_response,
};
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct OpenAI {
    api_key: String,
    base_url: String,
    client: Client,
    timeouts: HttpTimeouts,
}

impl OpenAI {
    pub fn new(api_key: &str, base_url: Option<&str>) -> Self {
        Self::with_timeouts(api_key, base_url, HttpTimeouts::from_env())
    }

    pub(crate) fn with_timeouts(
        api_key: &str,
        base_url: Option<&str>,
        timeouts: HttpTimeouts,
    ) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: base_url.unwrap_or("https://api.openai.com").to_string(),
            client: timeouts.client(),
            timeouts,
        }
    }
}

#[async_trait::async_trait]
impl Provider for OpenAI {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String> {
        self.chat_with_sampling(req, SamplingOptions::default())
            .await
    }

    async fn chat_with_sampling(
        &self,
        req: &ChatRequest,
        sampling: SamplingOptions,
    ) -> Result<ChatResponse, String> {
        let body = chat_completions_body_with_sampling(req, false, sampling);

        let url = format!("{}/v1/chat/completions", self.base_url);
        let mut rb = self
            .client
            .post(&url)
            .header("content-type", "application/json");
        if !self.api_key.is_empty() {
            rb = rb.header("authorization", format!("Bearer {}", self.api_key));
        }

        let resp = rb
            .timeout(self.timeouts.request_timeout)
            .json(&body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error("openai chat request", err))?;
        let status = resp.status();
        ensure_declared_response_size(resp.content_length(), "openai chat response")?;
        let body = read_bounded_response(resp, "openai chat response").await?;
        let text = String::from_utf8_lossy(&body);
        if !status.is_success() {
            return Err(format!("openai {}: {}", status, text));
        }

        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let choice = &v["choices"][0]["message"];
        let content = choice["content"].as_str().unwrap_or("").to_string();
        let tool_calls = choice["tool_calls"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|tc| ToolCall {
                        id: tc["id"].as_str().unwrap_or("").into(),
                        name: tc["function"]["name"].as_str().unwrap_or("").into(),
                        args: serde_json::from_str(
                            tc["function"]["arguments"].as_str().unwrap_or("{}"),
                        )
                        .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            tool_calls,
            input_tokens: v["usage"]["prompt_tokens"].as_i64().unwrap_or(0) as i32,
            output_tokens: v["usage"]["completion_tokens"].as_i64().unwrap_or(0) as i32,
            stop_reason: choice
                .get("finish_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("stop")
                .to_string(),
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
        })
    }

    async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, String> {
        let body = chat_completions_body(req, true);
        let url = format!("{}/v1/chat/completions", self.base_url);
        let mut rb = self
            .client
            .post(&url)
            .header("content-type", "application/json");
        if !self.api_key.is_empty() {
            rb = rb.header("authorization", format!("Bearer {}", self.api_key));
        }
        let resp = rb
            .json(&body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error("openai stream request", err))?;
        let status = resp.status();
        ensure_declared_response_size(resp.content_length(), "openai stream response")?;
        if !status.is_success() {
            let body = read_bounded_response(resp, "openai stream response").await?;
            let text = String::from_utf8_lossy(&body);
            return Err(format!("openai {}: {}", status, text));
        }

        let stream = resp.bytes_stream();
        Ok(Box::pin(async_stream::stream! {
            let mut buffer = String::new();
            let mut content = String::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut stop_reason = String::new();
            let mut tool_calls = BTreeMap::new();
            let mut emitted_done = false;
            let mut received_bytes = 0usize;

            futures_util::pin_mut!(stream);
            while let Some(next) = stream.next().await {
                let bytes = match next {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        yield Err(classify_reqwest_error("openai stream read", err));
                        return;
                    }
                };
                received_bytes = received_bytes.saturating_add(bytes.len());
                if received_bytes > MAX_PROVIDER_RESPONSE_BYTES {
                    yield Err(format!(
                        "openai stream response exceeded the {} byte response limit",
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
                    let parsed = parse_openai_sse_event(
                        &event,
                        &mut content,
                        &mut input_tokens,
                        &mut output_tokens,
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
                let parsed = parse_openai_sse_event(
                    &buffer,
                    &mut content,
                    &mut input_tokens,
                    &mut output_tokens,
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
            if !emitted_done {
                let tool_calls = match completed_openai_tool_calls(&tool_calls) {
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
                    cache_read_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                });
            }
        }))
    }
}

fn chat_completions_body(req: &ChatRequest, stream: bool) -> Value {
    chat_completions_body_with_sampling(req, stream, SamplingOptions::default())
}

fn chat_completions_body_with_sampling(
    req: &ChatRequest,
    stream: bool,
    sampling: SamplingOptions,
) -> Value {
    let mut messages: Vec<Value> = Vec::new();
    if !req.system.is_empty() {
        messages.push(json!({"role": "system", "content": req.system}));
    }
    for m in &req.messages {
        let mut msg = json!({"role": m.role});
        if m.role == "tool" {
            msg["content"] = json!(m.content);
            msg["tool_call_id"] = json!(m.tool_call_id);
        } else {
            msg["content"] = json!(m.content);
            if !m.tool_calls.is_empty() {
                msg["tool_calls"] = json!(
                    m.tool_calls
                        .iter()
                        .map(|tc| json!({
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": tc.args.to_string(),
                            }
                        }))
                        .collect::<Vec<_>>()
                );
            }
        }
        messages.push(msg);
    }

    let mut body = json!({
        "model": outbound_model_name(&req.model),
        "messages": messages
    });
    if req.max_tokens > 0 {
        body["max_tokens"] = json!(req.max_tokens);
    }
    if let Some(value) = sampling.temperature_millis {
        body["temperature"] = json!(f64::from(value) / 1_000.0);
    }
    if let Some(value) = sampling.top_p_millionths {
        body["top_p"] = json!(f64::from(value) / 1_000_000.0);
    }
    if let Some(value) = sampling.seed {
        body["seed"] = json!(value);
    }
    if !req.tools.is_empty() {
        body["tools"] = json!(
            req.tools
                .iter()
                .map(|t| json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    }
                }))
                .collect::<Vec<_>>()
        );
    }
    if stream {
        body["stream"] = json!(true);
        body["stream_options"] = json!({"include_usage": true});
    }
    body
}

#[derive(Debug, Default)]
struct OpenAiToolCallAssembly {
    id: String,
    name: String,
    arguments: String,
}

fn parse_openai_sse_event(
    event: &str,
    content: &mut String,
    input_tokens: &mut i32,
    output_tokens: &mut i32,
    stop_reason: &mut String,
    tool_calls: &mut BTreeMap<u64, OpenAiToolCallAssembly>,
    emitted_done: &mut bool,
) -> Result<Vec<ChatStreamChunk>, String> {
    let mut chunks = Vec::new();
    for data in event_data_values(event) {
        if data == "[DONE]" {
            if !*emitted_done {
                *emitted_done = true;
                let completed_tool_calls = completed_openai_tool_calls(tool_calls)?;
                chunks.push(ChatStreamChunk {
                    content_delta: String::new(),
                    content: content.clone(),
                    tool_calls: completed_tool_calls,
                    input_tokens: *input_tokens,
                    output_tokens: *output_tokens,
                    stop_reason: stop_reason.clone(),
                    done: true,
                    cache_read_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                });
            }
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        if let Some(usage) = value.get("usage").filter(|usage| !usage.is_null()) {
            *input_tokens = usage["prompt_tokens"].as_i64().unwrap_or(0) as i32;
            *output_tokens = usage["completion_tokens"].as_i64().unwrap_or(0) as i32;
        }
        if let Some(choice) = value["choices"].as_array().and_then(|arr| arr.first()) {
            if let Some(reason) = choice["finish_reason"].as_str() {
                *stop_reason = reason.to_string();
            }
            if let Some(deltas) = choice["delta"]["tool_calls"].as_array() {
                for delta in deltas {
                    let index = delta["index"]
                        .as_u64()
                        .ok_or_else(|| "openai tool-call delta omitted index".to_string())?;
                    let assembly = tool_calls.entry(index).or_default();
                    merge_openai_tool_call_field(&mut assembly.id, &delta["id"], "id")?;
                    merge_openai_tool_call_field(
                        &mut assembly.name,
                        &delta["function"]["name"],
                        "name",
                    )?;
                    if let Some(arguments) = delta["function"]["arguments"].as_str() {
                        assembly.arguments.push_str(arguments);
                    }
                }
            }
            if let Some(delta) = choice["delta"]["content"]
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
                    cache_read_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                });
            }
        }
    }
    Ok(chunks)
}

fn merge_openai_tool_call_field(
    current: &mut String,
    value: &Value,
    field: &str,
) -> Result<(), String> {
    let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !current.is_empty() && current != value {
        return Err(format!("openai tool-call {field} changed during stream"));
    }
    current.clear();
    current.push_str(value);
    Ok(())
}

fn completed_openai_tool_calls(
    tool_calls: &BTreeMap<u64, OpenAiToolCallAssembly>,
) -> Result<Vec<ToolCall>, String> {
    tool_calls
        .values()
        .map(|call| {
            if call.id.is_empty() || call.name.is_empty() {
                return Err("openai stream ended with incomplete tool-call identity".into());
            }
            let args = serde_json::from_str(if call.arguments.is_empty() {
                "{}"
            } else {
                &call.arguments
            })
            .map_err(|_| "openai stream ended with invalid tool-call arguments".to_string())?;
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

fn outbound_model_name(model: &str) -> &str {
    model.strip_prefix("ollama/").unwrap_or(model)
}

#[cfg(test)]
mod tests {
    use super::{
        OpenAI, chat_completions_body_with_sampling, outbound_model_name, parse_openai_sse_event,
    };
    use crate::llm::{ChatRequest, HttpTimeouts, Provider, SamplingOptions};
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

    fn test_chat_request(model: &str) -> ChatRequest {
        ChatRequest {
            model: model.to_string(),
            system: String::new(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: 16,
            prompt_cache: Default::default(),
        }
    }

    #[test]
    fn chat_body_forwards_frozen_sampling_controls() {
        let request = test_chat_request("openai/gpt-fixture");
        let body = chat_completions_body_with_sampling(
            &request,
            false,
            SamplingOptions {
                temperature_millis: Some(250),
                top_p_millionths: Some(875_000),
                seed: Some(42),
            },
        );

        assert_eq!(body["model"], "openai/gpt-fixture");
        assert_eq!(body["temperature"], 0.25);
        assert_eq!(body["top_p"], 0.875);
        assert_eq!(body["seed"], 42);
    }

    async fn delayed_chat_response() -> axum::Json<serde_json::Value> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        axum::Json(serde_json::json!({
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        }))
    }

    async fn spawn_delayed_openai() -> String {
        let app = Router::new().route("/v1/chat/completions", post(delayed_chat_response));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn strips_ollama_prefix_for_openai_compatible_backends() {
        assert_eq!(
            outbound_model_name("ollama/llama3.2:latest"),
            "llama3.2:latest"
        );
        assert_eq!(outbound_model_name("gpt-4.1-mini"), "gpt-4.1-mini");
    }

    #[test]
    fn parses_chat_completion_stream_delta_and_usage() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut stop_reason = String::new();
        let mut tool_calls = BTreeMap::new();
        let mut emitted_done = false;

        let chunks = parse_openai_sse_event(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content_delta, "hel");
        assert_eq!(chunks[0].content, "hel");
        assert!(!chunks[0].done);

        let chunks = parse_openai_sse_event(
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":5}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(chunks[0].content_delta, "lo");
        assert_eq!(chunks[0].content, "hello");
        assert_eq!(input_tokens, 7);
        assert_eq!(output_tokens, 5);
        assert_eq!(stop_reason, "stop");

        let chunks = parse_openai_sse_event(
            "data: [DONE]\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut tool_calls,
            &mut emitted_done,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].done);
        assert_eq!(chunks[0].content, "hello");
        assert_eq!(chunks[0].input_tokens, 7);
        assert_eq!(chunks[0].output_tokens, 5);
    }

    #[test]
    fn preserves_fragmented_interleaved_tool_calls() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut stop_reason = String::new();
        let mut tool_calls = BTreeMap::new();
        let mut emitted_done = false;

        for event in [
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"write","arguments":"{\"path\":"}},{"index":0,"id":"call_a","function":{"name":"read","arguments":"{\"path\":"}}]},"finish_reason":null}]}"#,
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.txt\"}"}},{"index":1,"function":{"arguments":"\"b.txt\"}"}}]},"finish_reason":"tool_calls"}]}"#,
            "data: [DONE]",
        ] {
            let chunks = parse_openai_sse_event(
                event,
                &mut content,
                &mut input_tokens,
                &mut output_tokens,
                &mut stop_reason,
                &mut tool_calls,
                &mut emitted_done,
            )
            .unwrap();
            if event == "data: [DONE]" {
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

    #[tokio::test]
    async fn unary_chat_times_out_against_slow_upstream() {
        let base_url = spawn_delayed_openai().await;
        let provider = OpenAI::with_timeouts("", Some(&base_url), test_timeouts());
        let err = tokio::time::timeout(
            Duration::from_secs(2),
            provider.chat(&test_chat_request("gpt-5.5")),
        )
        .await
        .unwrap()
        .unwrap_err();

        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
