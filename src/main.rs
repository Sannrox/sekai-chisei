use sekai_chisei::config::Config;
use sekai_chisei::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
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

    let provider_registry_state_path =
        sekai_chisei::provider_profile::provider_registry_state_path(&config.db_path);
    sekai_chisei::provider_profile::validate_provider_registry_storage(
        &provider_registry_state_path,
    )
    .map_err(std::io::Error::other)?;
    sekai_chisei::provider_profile::refresh_provider_registry(&provider_registry_state_path)
        .map_err(std::io::Error::other)?;

    if config.auth_token.is_some() {
        tracing::warn!(
            "SEKAI_AUTH_TOKEN is deprecated and maps to fixed principal `root`; use sekaictl credential create instead"
        );
    }

    let backend_config =
        RuntimeBackendConfig::from_env(&config.db_path).map_err(std::io::Error::other)?;
    let backend =
        Arc::new(RuntimeBackend::initialize(backend_config).map_err(std::io::Error::other)?);
    let db = backend.database();
    let active_credentials = db.list_active_credentials()?;
    let external_credentials_active = active_credentials.iter().any(|credential| {
        !matches!(
            credential.principal.as_str(),
            "chisei-gateway" | "local-onboarding"
        )
    });
    let grpc_tcp_mode = config.grpc_tcp_mode(external_credentials_active);

    if config.insecure && grpc_tcp_mode.auth_configured {
        tracing::warn!("SEKAI_INSECURE=1 disables token-auth mode for local development");
    }
    if grpc_tcp_mode.bind_inferred_from_active_credentials {
        tracing::warn!(
            "binding 0.0.0.0 because active credentials exist; set SEKAI_BIND to make this explicit"
        );
    }

    if grpc_tcp_mode.token_auth_mode {
        tracing::info!(
            bind = %grpc_tcp_mode.bind_addr,
            port = config.grpc_port,
            "gRPC TCP listener enabled"
        );
    } else if config.insecure {
        tracing::info!(
            bind = %grpc_tcp_mode.bind_addr,
            port = config.grpc_port,
            "gRPC TCP listener enabled"
        );
    } else {
        tracing::info!("gRPC TCP listener disabled");
    }

    if let Some(socket_path) = &config.sekai_socket {
        tracing::info!(socket_path, "gRPC UDS listener enabled");
    }
    tracing::info!(
        db_path = %config.db_path,
        backend = ?backend.capabilities().backend,
        backend_contract = %backend.capabilities().contract_version,
        db_lock_poisoned_total = db.db_lock_poisoned_total(),
        "database configured"
    );
    tracing::info!(
        anthropic = config.anthropic_api_key.is_some(),
        openai = config.openai_api_key.is_some(),
        ollama_url = %config.ollama_url,
        "LLM providers configured"
    );

    let server = sekai_chisei::grpc::run(config, backend, active_credentials, grpc_tcp_mode);
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

    let backend_config =
        RuntimeBackendConfig::from_env(&config.db_path).map_err(std::io::Error::other)?;
    let backend = RuntimeBackend::initialize(backend_config).map_err(std::io::Error::other)?;
    let db = backend.database();
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
