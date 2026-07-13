#[path = "../adapters/github_check_webhook.rs"]
mod github_check_webhook;
#[path = "../adapters/sdk.rs"]
mod sdk;

use std::io::Read;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let config = sdk::AdapterConfig::from_env()?;
    let draft = github_check_webhook::translate(github_check_webhook::parse(&input)?)?;
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
