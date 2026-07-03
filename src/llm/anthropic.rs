use super::{ChatRequest, ChatResponse, ChatStream, ChatStreamChunk, Provider, ToolCall};
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};

pub struct Anthropic {
    api_key: String,
    client: Client,
}

impl Anthropic {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for Anthropic {
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, String> {
        let body = messages_body(req, false);

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("anthropic {}: {}", status, text));
        }

        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let content = v["content"]
            .as_array()
            .and_then(|arr| arr.iter().find(|b| b["type"] == "text"))
            .and_then(|b| b["text"].as_str())
            .unwrap_or("")
            .to_string();
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
        })
    }

    async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, String> {
        let body = messages_body(req, true);
        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.map_err(|e| e.to_string())?;
            return Err(format!("anthropic {}: {}", status, text));
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
                    for chunk in parse_anthropic_sse_event(
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
                for chunk in parse_anthropic_sse_event(
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

fn messages_body(req: &ChatRequest, stream: bool) -> Value {
    let messages: Vec<Value> = req
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
                        "input": tc.args,
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
                .map(|t| json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                }))
                .collect::<Vec<_>>()
        );
    }
    if stream {
        body["stream"] = json!(true);
    }
    body
}

fn parse_anthropic_sse_event(
    event: &str,
    content: &mut String,
    input_tokens: &mut i32,
    output_tokens: &mut i32,
    stop_reason: &mut String,
    emitted_done: &mut bool,
) -> Vec<ChatStreamChunk> {
    let mut chunks = Vec::new();
    for data in event_data_values(event) {
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        match value["type"].as_str().unwrap_or("") {
            "message_start" => {
                *input_tokens = value["message"]["usage"]["input_tokens"]
                    .as_i64()
                    .unwrap_or(0) as i32;
            }
            "content_block_delta" => {
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
            _ => {}
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

#[cfg(test)]
mod tests {
    use super::parse_anthropic_sse_event;

    #[test]
    fn parses_messages_stream_delta_usage_and_stop() {
        let mut content = String::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut stop_reason = String::new();
        let mut emitted_done = false;

        parse_anthropic_sse_event(
            "event: message_start\n\
             data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut emitted_done,
        );
        assert_eq!(input_tokens, 11);

        let chunks = parse_anthropic_sse_event(
            "event: content_block_delta\n\
             data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut emitted_done,
        );
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
            &mut stop_reason,
            &mut emitted_done,
        );
        assert_eq!(output_tokens, 3);
        assert_eq!(stop_reason, "end_turn");

        let chunks = parse_anthropic_sse_event(
            "event: message_stop\n\
             data: {\"type\":\"message_stop\"}\n\n",
            &mut content,
            &mut input_tokens,
            &mut output_tokens,
            &mut stop_reason,
            &mut emitted_done,
        );
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].done);
        assert_eq!(chunks[0].content, "hi");
        assert_eq!(chunks[0].input_tokens, 11);
        assert_eq!(chunks[0].output_tokens, 3);
        assert_eq!(chunks[0].stop_reason, "end_turn");
    }
}
