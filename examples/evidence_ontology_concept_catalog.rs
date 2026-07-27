#[path = "../adapters/ontology_concept_catalog.rs"]
mod ontology_concept_catalog;
#[path = "../adapters/sdk.rs"]
mod sdk;

use std::io::Read;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let config = sdk::AdapterConfig::from_env()?;
    let draft = ontology_concept_catalog::translate(ontology_concept_catalog::parse(&input)?)?;
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
    println!(
        "next: ProposeOntologyDefinitions with submission id (dry_run=true first), then ReviewOntologyDefinitionProposal"
    );
    Ok(())
}
