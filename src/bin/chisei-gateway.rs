use sekai_chisei::gateway::{GatewayConfig, serve};
use sekai_chisei::gateway_report::{GatewayReportConfig, report_usage, run_report};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("report") {
        args.remove(0);
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            println!("{}", report_usage());
            return Ok(());
        }
        let config = GatewayReportConfig::from_env_and_args(args)
            .map_err(|err| format!("invalid chisei-gateway report config: {err}"))?;
        return run_report(config).await;
    }
    if args.first().map(String::as_str) == Some("refresh") {
        args.remove(0);
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            println!("{}", refresh_usage());
            return Ok(());
        }
        return run_refresh(args).await;
    }
    let no_preflight = args.iter().any(|arg| arg == "--no-preflight");
    args.retain(|arg| arg != "--no-preflight");

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("Usage: chisei-gateway [--no-preflight] [report ...|refresh ...]");
        println!("       chisei-gateway report --help");
        println!("       chisei-gateway refresh --help");
        println!(
            "       --no-preflight skips CheckBudget, ResolvePolicy, and context-egress preflight"
        );
        return Ok(());
    }
    if let Some(arg) = args.first() {
        return Err(format!("unknown chisei-gateway command {arg:?}").into());
    }

    if no_preflight {
        unsafe {
            std::env::set_var("CHISEI_GATEWAY_NO_PREFLIGHT", "1");
        }
    }
    let config = GatewayConfig::from_env().map_err(|err| std::io::Error::other(err.to_string()))?;
    println!("chisei-gateway v0.1.0");
    println!("  openai upstream: {}", config.openai_base_url);
    println!("  anthropic upstream: {}", config.anthropic_base_url);
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
    let mut request = reqwest::Client::new().post(endpoint);
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
