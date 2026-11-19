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

/// Largest tags listing read; a few thousand models fit well below it.
const MAX_TAGS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Bytes of an error body echoed into the error.
const ERROR_BODY_BYTES: usize = 512;

/// Installed local models. Like every provider call it never follows a
/// redirect, and it reads at most [`MAX_TAGS_RESPONSE_BYTES`].
pub async fn list_models(base_url: &str) -> Result<Vec<InstalledModel>, String> {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("failed to build ollama client: {e}"))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("failed to query ollama tags: {e}"))?;
    let status = resp.status();
    let body = super::read_response_within(resp, "ollama tags", MAX_TAGS_RESPONSE_BYTES).await?;
    if !status.is_success() {
        let summary = String::from_utf8_lossy(&body[..body.len().min(ERROR_BODY_BYTES)]);
        return Err(format!("ollama {status}: {}", summary.trim()));
    }
    let parsed: TagsResponse = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
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
    use super::*;
    use axum::{
        Router,
        http::{StatusCode, header},
        response::IntoResponse,
        routing::get,
    };

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    const TAGS: &str = r#"{"models":[{"name":"small:1b","details":{"parameter_size":"1B"}}]}"#;

    #[tokio::test]
    async fn lists_installed_models() {
        let base = serve(Router::new().route("/api/tags", get(|| async { TAGS }))).await;
        let models = list_models(&base).await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].name, "small:1b");
        assert_eq!(models[0].parameter_size_b, Some(1.0));
    }

    #[tokio::test]
    async fn a_redirect_is_an_error_and_is_not_followed() {
        let app = Router::new()
            .route(
                "/api/tags",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]) }),
            )
            .route("/elsewhere", get(|| async { TAGS }));
        let base = serve(app).await;
        let error = list_models(&base).await.unwrap_err();
        assert!(error.contains("302"), "{error}");
    }

    #[tokio::test]
    async fn an_oversized_listing_fails_bounded() {
        let app = Router::new().route(
            "/api/tags",
            get(|| async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "x".repeat(MAX_TAGS_RESPONSE_BYTES + 1),
                )
                    .into_response()
            }),
        );
        let base = serve(app).await;
        let error = list_models(&base).await.unwrap_err();
        assert!(error.contains("byte response limit"), "{error}");
        assert!(error.len() < 200, "{}", error.len());
    }

    #[test]
    fn parses_parameter_size_units() {
        assert_eq!(parse_parameter_size_b("14.8B"), Some(14.8));
        assert_eq!(parse_parameter_size_b("800M"), Some(0.8));
        assert_eq!(parse_parameter_size_b(""), None);
    }
}
