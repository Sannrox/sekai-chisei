//! Synthetic MCP host over the v1 object / Action / receipt allowlist.
//!
//! Speaks newline-delimited JSON-RPC 2.0 against an isolated
//! SQLite plane. No network bind and no copied protocol definitions.
//!
//! ```bash
//! cargo run --locked --example mcp_adapter
//! cargo test --locked --test mcp_adapter
//! ```

use sekai_chisei::mcp_adapter::run_synthetic_host;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let report = run_synthetic_host().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
