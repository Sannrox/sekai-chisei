pub use sekai_obs::{labels, logging, otel, signals};

/// Metrics wrapper so `sekai_build_info.version` is the running crate, not `sekai-obs`.
pub mod metrics {
    pub use sekai_obs::metrics::{
        db_lock_poisoned_total, record_db_lock_poisoned, search_index_lag_ms,
        set_embedding_index_lag_ms, set_search_index_lag_ms,
    };

    pub fn handle() -> &'static sekai_obs::metrics::PrometheusHandle {
        sekai_obs::metrics::handle(env!("CARGO_PKG_VERSION"))
    }

    pub fn spawn_upkeep_task() {
        sekai_obs::metrics::spawn_upkeep_task(env!("CARGO_PKG_VERSION"));
    }
}

pub mod console;
pub mod console_policy;
pub mod console_pressure;
pub mod console_transforms;
pub mod console_workspace;
pub mod correlation;
pub mod grpc_layer;
pub mod ops;

/// Serializes tests that capture logs with a scoped subscriber (#1773).
///
/// Registering a scoped subscriber recomputes tracing's process-wide
/// callsite interest and maximum level. Two tests doing so at once can
/// leave the global level below what one of them needs, so its events are
/// filtered before reaching its subscriber. Holding this lock while a
/// scoped subscriber is registered keeps those recomputations apart.
#[cfg(test)]
pub(crate) fn tracing_capture_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
