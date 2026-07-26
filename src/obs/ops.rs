use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{self, ConsoleState, DEFAULT_SESSION_TTL_SECS, SessionStore};
use crate::sekai::credentials::PrincipalCredentialStore;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Clone)]
struct OpsState {
    db: Arc<RuntimeDb>,
    provider_registry_state_path: PathBuf,
}

/// Build the ops HTTP router: unauthenticated health/metrics plus the
/// authenticated operator console under `/console`.
pub fn router(
    db: Arc<RuntimeDb>,
    provider_registry_state_path: PathBuf,
    credential_store: Arc<PrincipalCredentialStore>,
    legacy_root_token: Option<String>,
) -> Router {
    let ops = Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(OpsState {
            db: db.clone(),
            provider_registry_state_path,
        });

    let console = console::router(ConsoleState {
        db: db.clone(),
        auth: crate::grpc::TokenAuthInterceptor::new(credential_store, db, legacy_root_token),
        sessions: Arc::new(SessionStore::new()),
        session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
    });

    ops.merge(console)
}

pub async fn bind_and_spawn(
    bind: &str,
    port: u16,
    db: Arc<RuntimeDb>,
    provider_registry_state_path: PathBuf,
    credential_store: Arc<PrincipalCredentialStore>,
    legacy_root_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::obs::metrics::handle();
    crate::obs::metrics::spawn_upkeep_task();

    let listener = TcpListener::bind((bind, port)).await?;
    let actual_addr = listener.local_addr()?;
    let app = router(
        db,
        provider_registry_state_path,
        credential_store,
        legacy_root_token,
    );

    info!(
        addr = %actual_addr,
        "ops listener serving health, metrics, and authenticated console"
    );
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            error!(error = %err, "ops listener exited");
        }
    });

    Ok(())
}

async fn metrics() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        crate::obs::metrics::handle().render(),
    )
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<OpsState>) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || {
        state.db.ping().map_err(std::io::Error::other)?;
        crate::provider_profile::refresh_provider_registry(&state.provider_registry_state_path)
            .map_err(std::io::Error::other)
    })
    .await
    {
        Ok(Ok(())) => (StatusCode::OK, "ok").into_response(),
        Ok(Err(err)) => {
            warn!(error = %err, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, {
            warn!(error = %err, "readiness task failed");
            "not ready"
        })
            .into_response(),
    }
}
