use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledModel {
    pub name: String,
    pub parameter_size_b: Option<f64>,
    pub context_length: i32,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TagsResponse {
    models: Vec<TagModel>,
}

#[derive(Debug, Deserialize)]
struct TagModel {
    name: String,
    #[serde(default)]
    details: TagModelDetails,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TagModelDetails {
    #[serde(default)]
    parameter_size: String,
    #[serde(default)]
    context_length: i32,
}

pub async fn list_models(base_url: &str) -> Result<Vec<InstalledModel>, String> {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| format!("failed to build ollama client: {e}"))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("failed to query ollama tags: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama {}: {}", status, text));
    }
    let parsed: TagsResponse = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(parsed
        .models
        .into_iter()
        .map(|model| InstalledModel {
            name: model.name,
            parameter_size_b: parse_parameter_size_b(&model.details.parameter_size),
            context_length: model.details.context_length,
            capabilities: model.capabilities,
        })
        .collect())
}

fn parse_parameter_size_b(raw: &str) -> Option<f64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let number = lower.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let value: f64 = number.parse().ok()?;
    if lower.ends_with('b') {
        Some(value)
    } else if lower.ends_with('m') {
        Some(value / 1000.0)
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_parameter_size_b;

    #[test]
    fn parses_parameter_size_units() {
        assert_eq!(parse_parameter_size_b("14.8B"), Some(14.8));
        assert_eq!(parse_parameter_size_b("800M"), Some(0.8));
        assert_eq!(parse_parameter_size_b(""), None);
    }
}
