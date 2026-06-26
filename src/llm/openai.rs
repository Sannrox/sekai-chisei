use super::{ChatRequest, ChatResponse, Provider, ToolCall};
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
}

fn outbound_model_name(model: &str) -> &str {
    model.strip_prefix("ollama/").unwrap_or(model)
}

#[cfg(test)]
mod tests {
    use super::outbound_model_name;

    #[test]
    fn strips_ollama_prefix_for_openai_compatible_backends() {
        assert_eq!(
            outbound_model_name("ollama/llama3.2:latest"),
            "llama3.2:latest"
        );
        assert_eq!(outbound_model_name("gpt-4.1-mini"), "gpt-4.1-mini");
    }
}
