#[path = "../adapters/sdk.rs"]
mod sdk;
#[path = "../adapters/social_post_snapshot.rs"]
mod social_post_snapshot;

use std::io::Read;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let config = sdk::AdapterConfig::from_env()?;
    let draft = social_post_snapshot::translate(social_post_snapshot::parse(&input)?)?;
    let (envelope, outbox) =
        sdk::prepare_delivery(&config, draft, chrono::Utc::now().timestamp_millis())?;
    let result = sdk::submit(&config, envelope).await?;
    outbox.acknowledge()?;
    let submission = result
        .submission
        .ok_or("Sekai returned no evidence submission")?;
    println!(
        "submission={} state={} projected={} deduplicated={}",
        submission.id, submission.lifecycle_state, result.projected, result.deduplicated
    );
    Ok(())
}
