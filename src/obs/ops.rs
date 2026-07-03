use crate::db::sekai::SekaiDb;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub fn router(db: Arc<SekaiDb>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(db)
}

pub async fn bind_and_spawn(
    bind: &str,
    port: u16,
    db: Arc<SekaiDb>,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::obs::metrics::handle();
    crate::obs::metrics::spawn_upkeep_task();

    let listener = TcpListener::bind((bind, port)).await?;
    let actual_addr = listener.local_addr()?;
    let app = router(db);

    info!(addr = %actual_addr, "ops listener serving health and metrics");
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

async fn readyz(State(db): State<Arc<SekaiDb>>) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || db.ping()).await {
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
