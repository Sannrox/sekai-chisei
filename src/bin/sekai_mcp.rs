use sekai_chisei::mcp_adapter::{AdapterConfig, run_stdio};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(());
    }
    let config = AdapterConfig::from_env().map_err(std::io::Error::other)?;
    run_stdio(config).await.map_err(std::io::Error::other)?;
    Ok(())
}

fn print_usage() {
    println!(
        "sekai-mcp — MCP stdio projection host for GetObject, SubmitActionInstance, and GetOperationReceipt\n\n\
         Environment:\n\
           SEKAI_MCP_PRINCIPAL   authenticated principal (required)\n\
           SEKAI_MCP_NAMESPACE   canonical namespace (required)\n\
           SEKAI_MCP_TARGET      gRPC target (default http://127.0.0.1:50051 or SEKAI_SOCKET)\n\
           SEKAI_CREDENTIAL      bearer token kept in the host environment\n\n\
         The adapter does not bind a network port. Discovery annotations never grant authority."
    );
}
