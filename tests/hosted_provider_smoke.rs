use serde_json::json;

async fn smoke(
    provider: &str,
    model: &str,
    base_url_env: &str,
    default_base_url: Option<&str>,
    key_env: &str,
) {
    let base_url = std::env::var(base_url_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| default_base_url.map(str::to_string))
        .unwrap_or_else(|| panic!("{base_url_env} must be set for the {provider} smoke test"));
    let key = std::env::var(key_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("{key_env} must be set for the {provider} smoke test"));
    let response = reqwest::Client::new()
        .post(format!("{}/responses", base_url.trim_end_matches('/')))
        .bearer_auth(key)
        .json(&json!({
            "model": model,
            "input": "Reply with exactly: ok",
            "max_output_tokens": 16,
            "store": false
        }))
        .send()
        .await
        .unwrap_or_else(|error| panic!("{provider} smoke request failed: {error}"));
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(status.is_success(), "{provider} returned {status}: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(value.get("id").is_some(), "{provider} omitted response id");
    assert!(value.get("usage").is_some(), "{provider} omitted usage");
}

#[tokio::test]
#[ignore = "requires XAI_API_KEY and makes a billed xAI API request"]
async fn xai_grok_4_5_responses_smoke() {
    smoke(
        "xAI",
        "grok-4.5",
        "CHISEI_XAI_BASE_URL",
        Some("https://api.x.ai/v1"),
        "XAI_API_KEY",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires CHISEI_META_BASE_URL and META_MODEL_API_KEY and makes a billed preview API request"]
async fn meta_muse_spark_1_1_responses_smoke() {
    smoke(
        "Meta Model API",
        "muse-spark-1.1",
        "CHISEI_META_BASE_URL",
        None,
        "META_MODEL_API_KEY",
    )
    .await;
}
