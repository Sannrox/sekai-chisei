use sekai_chisei::mcp_adapter::{AdapterConfig, run_stdio};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn std::error::Error + Send + Sync>> {
    // The adapter is configured through the environment only; any argument
    // other than help is a mistake, not something to ignore.
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => {}
        [help] if help == "--help" || help == "-h" => {
            println!("{USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
        _ => {
            eprintln!(
                "sekai-mcp: unexpected arguments {args:?}; configure through the environment\n\n{USAGE}"
            );
            return Ok(ExitCode::from(2));
        }
    }
    let config = AdapterConfig::from_env().map_err(std::io::Error::other)?;
    run_stdio(config).await.map_err(std::io::Error::other)?;
    Ok(ExitCode::SUCCESS)
}

const USAGE: &str = "sekai-mcp — MCP stdio projection host for GetObject, SubmitActionInstance, and GetOperationReceipt\n\n\
         Environment:\n\
           SEKAI_MCP_PRINCIPAL   authenticated principal (required)\n\
           SEKAI_MCP_NAMESPACE   canonical namespace (required)\n\
           SEKAI_MCP_TARGET      gRPC target (default http://127.0.0.1:50051 or SEKAI_SOCKET)\n\
           SEKAI_CREDENTIAL      bearer token kept in the host environment\n\n\
         The adapter does not bind a network port. Discovery annotations never grant authority.";
