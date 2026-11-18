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
pub mod console_evals;
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
///
/// The lock cannot order threads that only hit a callsite (#2253). With a
/// single registered dispatcher, tracing computes a callsite's interest
/// from the calling thread's default alone, so another test thread hitting
/// a callsite first while a capture is live caches it as "never" for every
/// thread. A no-op dispatcher kept registered for the whole test binary
/// keeps the capture's subscriber in every interest computation.
#[cfg(test)]
pub(crate) fn tracing_capture_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static KEEP_REGISTERED: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    KEEP_REGISTERED
        .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod capture_tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer").write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// #2253: a callsite another test thread hits first, while a capture is
    /// live, must still reach the capture's subscriber.
    #[test]
    fn a_callsite_first_hit_on_another_thread_reaches_the_capture() {
        fn probe() {
            tracing::info!("probe-2253");
        }
        let _serialized = super::tracing_capture_lock();
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        std::thread::spawn(probe).join().expect("probe thread");
        probe();
        let logs = String::from_utf8(buf.0.lock().expect("log buffer").clone()).expect("utf8");
        assert!(
            logs.contains("probe-2253"),
            "capture missed the event: {logs:?}"
        );
    }
}
