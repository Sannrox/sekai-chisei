use crate::config::Config;
use crate::grpc::{ServicePlane, run, run_chisei_plane};
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use std::sync::Arc;
use tokio::signal;

pub fn boot(plane: ServicePlane) -> Result<(), Box<dyn std::error::Error>> {
    let mut telemetry = crate::obs::logging::init();
    let config = Config::from_env();
    tracing::info!(
        version = crate::build_info::PKG_VERSION,
        plane = ?plane,
        "control plane starting"
    );

    let result = match plane {
        ServicePlane::Chisei => boot_chisei(config)?,
        ServicePlane::Sekai | ServicePlane::Combined => boot_with_database(config, plane)?,
    };
    telemetry.shutdown();
    result
}

fn boot_chisei(
    config: Config,
) -> Result<Result<(), Box<dyn std::error::Error>>, Box<dyn std::error::Error>> {
    if crate::grpc::chisei_sekai_endpoint().is_none() {
        return Err("CHISEI_SEKAI_ENDPOINT is required for the Chisei plane".into());
    }
    let grpc_tcp_mode = config.grpc_tcp_mode(false);
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let server = run_chisei_plane(config, grpc_tcp_mode)?;
    let result = {
        let _runtime_guard = async_runtime.enter();
        async_runtime.block_on(run_until_ctrl_c(server))
    };
    drop(async_runtime);
    Ok(result)
}

fn boot_with_database(
    config: Config,
    plane: ServicePlane,
) -> Result<Result<(), Box<dyn std::error::Error>>, Box<dyn std::error::Error>> {
    let provider_registry_state_path =
        crate::provider_profile::provider_registry_state_path(&config.db_path);
    crate::provider_profile::validate_provider_registry_storage(&provider_registry_state_path)
        .map_err(std::io::Error::other)?;
    crate::provider_profile::refresh_provider_registry(&provider_registry_state_path)
        .map_err(std::io::Error::other)?;

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
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let server = run(
        config,
        Arc::clone(&backend),
        active_credentials,
        grpc_tcp_mode,
        plane,
    )?;
    let result = {
        let _runtime_guard = async_runtime.enter();
        async_runtime.block_on(run_until_ctrl_c(server))
    };
    drop(async_runtime);
    drop(backend);
    Ok(result)
}

async fn run_until_ctrl_c(
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
