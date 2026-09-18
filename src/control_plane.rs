//! Shared startup for combined, Sekai-only, and Chisei-only processes.

use std::sync::Arc;

use tokio::signal;

use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::plane::{ProcessPlane, plane_registry_anchor, plane_store_identity};

pub fn run(plane: ProcessPlane) -> Result<(), Box<dyn std::error::Error>> {
    let mut telemetry = crate::obs::logging::init();
    let config = Config::from_env();
    tracing::info!(
        version = crate::build_info::PKG_VERSION,
        git_version = crate::build_info::GIT_VERSION,
        git_commit = crate::build_info::GIT_COMMIT,
        plane = plane.as_str(),
        "control plane starting"
    );

    let provider_registry_state_path = crate::provider_profile::provider_registry_state_path(
        &plane_registry_anchor(plane, &config.db_path),
    );
    crate::provider_profile::validate_provider_registry_storage(&provider_registry_state_path)
        .map_err(std::io::Error::other)?;
    crate::provider_profile::refresh_provider_registry(&provider_registry_state_path)
        .map_err(std::io::Error::other)?;

    let stores = Arc::new(
        plane
            .open_layout(&config.db_path)
            .map_err(std::io::Error::other)?,
    );
    let credential_db = match plane {
        ProcessPlane::Chisei => stores.chisei_runtime(),
        ProcessPlane::Combined | ProcessPlane::Sekai => stores.sekai_runtime(),
    };
    let active_credentials = credential_db.list_active_credentials()?;
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
        tracing::info!(
            socket_path,
            "gRPC UDS listener enabled (socket mode 0600; protect the socket directory; unauthenticated identity is forced to local)"
        );
    }
    let identity = plane_store_identity(plane, &stores);
    tracing::info!(
        db_path = %config.db_path,
        plane = plane.as_str(),
        store_mode = stores.mode_name(),
        store = %identity,
        sekai_store = %stores.sekai_identity(),
        chisei_store = %stores.chisei_identity(),
        db_lock_poisoned_total = credential_db.db_lock_poisoned_total(),
        "durable stores configured"
    );
    tracing::info!(
        anthropic = config.anthropic_api_key.is_some(),
        openai = config.openai_api_key.is_some(),
        ollama_url = %config.ollama_url,
        "LLM providers configured"
    );

    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let server = crate::grpc::run_for_plane(
        config,
        Arc::clone(&stores),
        active_credentials,
        grpc_tcp_mode,
        plane,
    )?;
    let result = {
        let _runtime_guard = async_runtime.enter();
        async_runtime.block_on(run_server(server))
    };
    telemetry.shutdown();
    drop(async_runtime);
    drop(stores);
    result
}

async fn run_server(
    server: impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn run_gateway_report(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
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

    let stores = CombinedStoreLayout::from_env(&config.db_path).map_err(std::io::Error::other)?;
    let db = stores.sekai_runtime();
    let rows = crate::gateway_report::egress_rows(&db, after, limit)?;

    match format {
        "html" => println!("{}", crate::gateway_report::render_egress_html(&rows)),
        "csv" => print!("{}", crate::gateway_report::render_egress_csv(&rows)),
        other => return Err(format!("unsupported report format {other:?}").into()),
    }
    Ok(())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}
