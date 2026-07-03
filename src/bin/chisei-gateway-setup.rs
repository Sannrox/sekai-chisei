use sekai_chisei::gateway_setup::{
    GatewaySetupConfig, key_usage, run_gateway_key_command, run_setup, usage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("key") {
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            println!("{}", key_usage());
            return Ok(());
        }
        return run_gateway_key_command(args.into_iter().skip(1)).await;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let config = GatewaySetupConfig::from_env_and_args(args)
        .map_err(|err| format!("invalid chisei-gateway setup config: {err}"))?;
    run_setup(config).await
}
