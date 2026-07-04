use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
static DB_LOCK_POISONED_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn handle() -> &'static PrometheusHandle {
    HANDLE.get_or_init(|| {
        let buckets = [
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];
        let handle = PrometheusBuilder::new()
            .set_buckets(&buckets)
            .expect("valid Prometheus histogram buckets")
            .install_recorder()
            .expect("install Prometheus recorder");
        describe_gauge!("sekai_build_info", "sekai-chisei build information");
        describe_counter!(
            "db_lock_poisoned_total",
            "Database connection mutex poison recoveries"
        );
        gauge!("sekai_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
        handle
    })
}

pub fn record_db_lock_poisoned() {
    DB_LOCK_POISONED_TOTAL.fetch_add(1, Ordering::Relaxed);
    counter!("db_lock_poisoned_total").increment(1);
}

pub fn db_lock_poisoned_total() -> u64 {
    DB_LOCK_POISONED_TOTAL.load(Ordering::Relaxed)
}

pub fn spawn_upkeep_task() {
    let handle = handle().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            handle.run_upkeep();
        }
    });
}
