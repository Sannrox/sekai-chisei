pub use sekai_obs::{labels, logging, otel, signals};

/// Metrics wrapper so `sekai_build_info.version` is the running crate, not `sekai-obs`.
pub mod metrics {
    pub use sekai_obs::metrics::{db_lock_poisoned_total, record_db_lock_poisoned};

    pub fn handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        sekai_obs::metrics::handle(env!("CARGO_PKG_VERSION"))
    }

    pub fn spawn_upkeep_task() {
        sekai_obs::metrics::spawn_upkeep_task(env!("CARGO_PKG_VERSION"));
    }
}

pub mod console;
pub mod console_policy;
pub mod console_pressure;
pub mod console_workspace;
pub mod correlation;
pub mod grpc_layer;
pub mod ops;
