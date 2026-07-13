#[path = "../adapters/http_health_poll.rs"]
mod http_health_poll;
#[path = "../adapters/sdk.rs"]
mod sdk;

use reqwest::header::ETAG;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint = required_env("HEALTH_ENDPOINT")?;
    let source_record_id = required_env("HEALTH_SOURCE_RECORD_ID")?;
    let ttl_ms = std::env::var("HEALTH_EVIDENCE_TTL_MS")
        .unwrap_or_else(|_| "300000".into())
        .parse::<i64>()?;
    let response = reqwest::Client::new()
        .get(&endpoint)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?;
    let response_version = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let payload = http_health_poll::parse(&response.bytes().await?)?;
    let draft = http_health_poll::translate(
        payload,
        &source_record_id,
        response_version.as_deref(),
        ttl_ms,
    )?;
    let config = sdk::AdapterConfig::from_env()?;
    let envelope = draft.into_envelope(&config, chrono::Utc::now().timestamp_millis())?;
    let result = sdk::submit(&config, envelope).await?;
    let submission = result
        .submission
        .ok_or("Sekai returned no evidence submission")?;
    println!(
        "submission={} state={} projected={} deduplicated={}",
        submission.id, submission.lifecycle_state, result.projected, result.deduplicated
    );
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}
