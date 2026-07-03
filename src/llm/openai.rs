use super::{ChatRequest, ChatResponse, ChatStream, ChatStreamChunk, Provider, ToolCall};
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};

pub struct OpenAI {
    api_key: String,
    base_url: String,
    client: Client,
}

impl OpenAI {
    pub fn new(api_key: &str, base_url: Option<&str>) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: base_url.unwrap_or("https://api.openai.com").to_string(),
            client: Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for OpenAI {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String> {
        let body = chat_completions_body(req, false);

        let url = format!("{}/v1/chat/completions", self.base_url);
        let mut rb = self
            .client
            .post(&url)
            .header("content-type", "application/json");
        if !self.api_key.is_empty() {
            rb = rb.header("authorization", format!("Bearer {}", self.api_key));
        }

        let resp = rb.json(&body).send().await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| e.to_string())?;
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
        let resp = rb.json(&body).send().await.map_err(|e| e.to_string())?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.map_err(|e| e.to_string())?;
            return Err(format!("openai {}: {}", status, text));
        }

        let stream = resp.bytes_stream();
        Ok(Box::pin(async_stream::stream! {
            let mut buffer = String::new();
            let mut content = String::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut stop_reason = String::new();
            let mut emitted_done = false;

            futures_util::pin_mut!(stream);
            while let Some(next) = stream.next().await {
                let bytes = match next {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        yield Err(err.to_string());
                        return;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(index) = buffer.find("\n\n") {
                    let event = buffer[..index].to_string();
                    buffer = buffer[index + 2..].to_string();
                    for chunk in parse_openai_sse_event(
                        &event,
                        &mut content,
                        &mut input_tokens,
                        &mut output_tokens,
                        &mut stop_reason,
                        &mut emitted_done,
                    ) {
                        yield Ok(chunk);
                    }
                }
            }
            if !buffer.trim().is_empty() {
                for chunk in parse_openai_sse_event(
                    &buffer,
                    &mut content,
                    &mut input_tokens,
                    &mut output_tokens,
                    &mut stop_reason,
                    &mut emitted_done,
                ) {
                    yield Ok(chunk);
                }
            }
            if !emitted_done {
                yield Ok(ChatStreamChunk {
                    content_delta: String::new(),
                    content,
                    tool_calls: Vec::new(),
                    input_tokens,
                    output_tokens,
                    stop_reason,
                    done: true,
                });
            }
        }))
    }
}

fn chat_completions_body(req: &ChatRequest, stream: bool) -> Value {
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

fn parse_openai_sse_event(
    event: &str,
    content: &mut String,
    input_tokens: &mut i32,
    output_tokens: &mut i32,
    stop_reason: &mut String,
    emitted_done: &mut bool,
) -> Vec<ChatStreamChunk> {
    let mut chunks = Vec::new();
    for data in event_data_values(event) {
        if data == "[DONE]" {
            if !*emitted_done {
                *emitted_done = true;
                chunks.push(ChatStreamChunk {
                    content_delta: String::new(),
                    content: content.clone(),
                    tool_calls: Vec::new(),
                    input_tokens: *input_tokens,
                    output_tokens: *output_tokens,
                    stop_reason: stop_reason.clone(),
                    done: true,
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
                });
            }
        }
    }
    chunks
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
    use super::{outbound_model_name, parse_openai_sse_event};

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
        let mut emitted_done = false;

        let chunks = parse_openai_sse_event(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut emitted_done,
        );
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
            &mut emitted_done,
        );
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
            &mut emitted_done,
        );
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].done);
        assert_eq!(chunks[0].content, "hello");
        assert_eq!(chunks[0].input_tokens, 7);
        assert_eq!(chunks[0].output_tokens, 5);
    }
}
