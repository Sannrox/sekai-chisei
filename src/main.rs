use sekai_chisei::config::Config;
use sekai_chisei::db::sekai::SekaiDb;
use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sekai_chisei::obs::logging::init();
    let config = Config::from_env();
    if let Some(mode) = std::env::args().nth(1)
        && mode == "gateway-report"
    {
        return run_gateway_report(&config);
    }
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "sekai-chisei starting");

    let insecure = std::env::var("SEKAI_INSECURE").unwrap_or_default() == "1";
    if config.auth_token.is_some() {
        tracing::warn!(
            "SEKAI_AUTH_TOKEN is deprecated and maps to fixed principal `root`; use sekaictl credential create instead"
        );
    }

    let db = Arc::new(SekaiDb::new(&config.db_path).expect("failed to open database"));
    db.migrate_datasets();
    db.migrate_functions();
    db.migrate_grants();
    db.migrate_audit();
    db.migrate_schema_types()
        .expect("failed to migrate schema types");
    let _ = db.migrate_chisei();
    db.migrate_principal_credentials()
        .map_err(std::io::Error::other)?;
    let token_auth_mode =
        (config.auth_token.is_some() || !db.list_active_credentials()?.is_empty()) && !insecure;

    if token_auth_mode {
        tracing::info!(
            bind = "0.0.0.0",
            port = config.grpc_port,
            "gRPC TCP listener enabled"
        );
    } else if insecure {
        tracing::info!(
            bind = "127.0.0.1",
            port = config.grpc_port,
            "gRPC TCP listener enabled"
        );
    } else {
        tracing::info!("gRPC TCP listener disabled");
    }

    if let Some(socket_path) = &config.sekai_socket {
        tracing::info!(socket_path, "gRPC UDS listener enabled");
    }
    tracing::info!(db_path = %config.db_path, "database configured");
    tracing::info!(
        anthropic = config.anthropic_api_key.is_some(),
        openai = config.openai_api_key.is_some(),
        ollama_url = %config.ollama_url,
        "LLM providers configured"
    );

    let server = sekai_chisei::grpc::run(config.grpc_port, db);
    let shutdown = async {
        signal::ctrl_c().await.ok();
        tracing::info!("shutting down");
    };

    tokio::select! {
        result = server => {
            result?;
        }
        _ = shutdown => {}
    }
    Ok(())
}

fn run_gateway_report(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    if !args.iter().any(|arg| arg == "--egress") {
        return Err("gateway-report currently requires --egress".into());
    }

    let format = arg_value(&args, "--format").unwrap_or("csv");
    let after = arg_value(&args, "--after")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let limit = arg_value(&args, "--limit")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(500);

    let db = SekaiDb::new(&config.db_path).expect("failed to open database");
    db.migrate_audit();
    let rows = sekai_chisei::gateway_report::egress_rows(&db, after, limit)?;

    match format {
        "html" => println!(
            "{}",
            sekai_chisei::gateway_report::render_egress_html(&rows)
        ),
        "csv" => print!("{}", sekai_chisei::gateway_report::render_egress_csv(&rows)),
        other => return Err(format!("unsupported report format {other:?}").into()),
    }
    Ok(())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}
