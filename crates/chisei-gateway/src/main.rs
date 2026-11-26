use chisei_gateway::gateway::{GatewayConfig, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut telemetry = chisei_gateway::obs::logging::init("chisei-gateway");
    let result = run().await;
    telemetry.shutdown();
    result
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("refresh") {
        args.remove(0);
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            println!("{}", refresh_usage());
            return Ok(());
        }
        return run_refresh(args).await;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("Usage: chisei-gateway [refresh ...]");
        println!("       chisei-gateway refresh --help");
        return Ok(());
    }
    if let Some(arg) = args.first() {
        return Err(format!("unknown chisei-gateway command {arg:?}").into());
    }

    let config = GatewayConfig::from_env().map_err(|err| std::io::Error::other(err.to_string()))?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        git_version = chisei_gateway::obs::build_info::GIT_VERSION,
        git_commit = chisei_gateway::obs::build_info::GIT_COMMIT,
        openai_upstream = %config.openai_base_url,
        anthropic_upstream = %config.anthropic_base_url,
        "chisei-gateway starting"
    );
    serve(config)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()).into())
}

fn refresh_usage() -> &'static str {
    "Usage: chisei-gateway refresh [--url http://127.0.0.1:8788]\n\
     \n\
     Clears the running gateway key cache through /_chisei/admin/refresh.\n\
     Uses CHISEI_GATEWAY_URL when --url is omitted.\n\
     Uses CHISEI_GATEWAY_ADMIN_TOKEN as a bearer token when set."
}

/// POST /_chisei/admin/refresh. Connect and request timeouts come from
/// `HttpTimeouts` so a listener that accepts and never answers cannot hang.
async fn run_refresh(args: Vec<String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut url =
        std::env::var("CHISEI_GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8788".to_string());
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--url" => {
                url = iter
                    .next()
                    .ok_or_else(|| "missing value for --url".to_string())?;
            }
            _ => return Err(format!("unknown chisei-gateway refresh arg {arg:?}").into()),
        }
    }
    let endpoint = format!(
        "{}/_chisei/admin/refresh",
        url.trim_end_matches('/').trim_end_matches("/v1")
    );
    let timeouts = chisei_gateway::llm::HttpTimeouts::from_env();
    let client = reqwest::Client::builder()
        .connect_timeout(timeouts.connect_timeout)
        .timeout(timeouts.request_timeout)
        .build()?;
    let mut request = client.post(endpoint);
    if let Ok(token) = std::env::var("CHISEI_GATEWAY_ADMIN_TOKEN")
        && !token.trim().is_empty()
    {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(format!("gateway refresh failed with {status}: {body}").into());
    }
    println!("{body}");
    Ok(())
}
