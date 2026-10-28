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
    chisei_db: Option<Arc<RuntimeDb>>,
    provider_registry_state_path: PathBuf,
    /// Sekai store whose transform work queue `/metrics` reads; `None`
    /// on a process that does not serve Sekai.
    transform_queue: Option<Arc<RuntimeDb>>,
}

/// Build the ops HTTP router: unauthenticated health/metrics plus the
/// authenticated operator console under `/console`. With `transform_queue`,
/// each scrape also reads the transform work queue gauges from it.
pub fn router(
    db: Arc<RuntimeDb>,
    chisei_db: Option<Arc<RuntimeDb>>,
    transform_queue: Option<Arc<RuntimeDb>>,
    provider_registry_state_path: PathBuf,
    credential_store: Arc<PrincipalCredentialStore>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
) -> Router {
    let ops = Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(OpsState {
            db: db.clone(),
            chisei_db,
            provider_registry_state_path,
            transform_queue,
        });

    let console = console::router(ConsoleState {
        db: db.clone(),
        auth: crate::grpc::TokenAuthInterceptor::from_runtime(
            credential_store,
            crate::db::store::SekaiStore::from_shared_runtime(db),
            assertion_authority,
        ),
        sessions: Arc::new(SessionStore::new()),
        session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
    });

    ops.merge(console)
}

#[allow(clippy::too_many_arguments)]
pub async fn bind_and_spawn(
    bind: &str,
    port: u16,
    db: Arc<RuntimeDb>,
    chisei_db: Option<Arc<RuntimeDb>>,
    transform_queue: Option<Arc<RuntimeDb>>,
    provider_registry_state_path: PathBuf,
    credential_store: Arc<PrincipalCredentialStore>,
    assertion_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::obs::metrics::handle();
    crate::obs::metrics::spawn_upkeep_task();

    let listener = TcpListener::bind((bind, port)).await?;
    let actual_addr = listener.local_addr()?;
    let app = router(
        db,
        chisei_db,
        transform_queue,
        provider_registry_state_path,
        credential_store,
        assertion_authority,
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

async fn metrics(State(state): State<OpsState>) -> impl IntoResponse {
    let mut body = crate::obs::metrics::handle().render();
    if let Some(db) = state.transform_queue {
        let queue = tokio::task::spawn_blocking(move || {
            crate::sekai::governed_transform::transform_work_depth_metrics(
                &db,
                crate::sekai::dataset_version::now_ms(),
            )
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result);
        // Without a store read the gauges are absent; the scrape still succeeds.
        match queue {
            Ok(queue) => body.push_str(&queue),
            Err(error) => warn!(error = %error, "transform work queue gauges not read"),
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<OpsState>) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || {
        state.db.ping().map_err(std::io::Error::other)?;
        if let Some(chisei) = state.chisei_db.as_ref() {
            chisei.ping().map_err(std::io::Error::other)?;
        }
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
