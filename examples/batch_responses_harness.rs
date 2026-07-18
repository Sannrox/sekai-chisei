#[allow(dead_code)]
#[path = "../adapters/batch_responses_harness.rs"]
mod batch_responses_harness;
#[allow(dead_code)]
#[path = "../adapters/sdk.rs"]
mod sdk;

use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = Vec::new();
    std::io::stdin()
        .take((batch_responses_harness::MAX_STREAM_BYTES + 1) as u64)
        .read_to_end(&mut stream)?;
    if stream.len() > batch_responses_harness::MAX_STREAM_BYTES {
        return Err(std::io::Error::other("batch harness stream exceeds the size limit").into());
    }
    let result = batch_responses_harness::run_fixture(&stream).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
