use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

pub use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
static DB_LOCK_POISONED_TOTAL: AtomicU64 = AtomicU64::new(0);
static SEARCH_INDEX_LAG_MS: AtomicU64 = AtomicU64::new(0);

/// Install the Prometheus recorder using the running binary's package version.
pub fn handle(pkg_version: &'static str) -> &'static PrometheusHandle {
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
        describe_gauge!(
            "sekai_search_index_lag_ms",
            "Maximum search index lag across namespaces"
        );
        describe_gauge!(
            "sekai_embedding_index_lag_ms",
            "Age of the oldest object change an embedding catch-up consumed"
        );
        describe_gauge!(
            "sekai_object_log_ingest_backlog",
            "Admitted objects still waiting to reach the object log"
        );
        describe_gauge!(
            "sekai_object_log_host_writer",
            "1 for the object-log host this process writes to, 0 for the others"
        );
        describe_gauge!(
            "sekai_object_log_host_behind",
            "Snapshots an object-log host's last reply trailed its writer"
        );
        describe_counter!(
            "sekai_object_log_host_retries_total",
            "Object-log requests sent again to another or rediscovered host"
        );
        crate::signals::describe_all();
        gauge!(
            "sekai_build_info",
            "version" => pkg_version,
            "git_version" => crate::build_info::GIT_VERSION,
            "git_commit" => crate::build_info::GIT_COMMIT
        )
        .set(1.0);
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

pub fn set_search_index_lag_ms(lag_ms: u64) {
    SEARCH_INDEX_LAG_MS.store(lag_ms, Ordering::Relaxed);
    gauge!("sekai_search_index_lag_ms").set(lag_ms as f64);
}

/// Embedding index lag: age of the oldest object change a catch-up consumed.
pub fn set_embedding_index_lag_ms(lag_ms: u64) {
    gauge!("sekai_embedding_index_lag_ms").set(lag_ms as f64);
}

/// Admitted objects still waiting to reach the object log (#2289).
pub fn set_object_log_ingest_backlog(intents: u64) {
    gauge!("sekai_object_log_ingest_backlog").set(intents as f64);
}

/// Which configured object-log host this process writes to (#2292).
pub fn set_object_log_host_writer(host: &str, writer: bool) {
    gauge!("sekai_object_log_host_writer", "host" => host.to_owned())
        .set(f64::from(u8::from(writer)));
}

/// How many snapshots an object-log host's last reply trailed its writer.
pub fn set_object_log_host_behind(host: &str, behind: u64) {
    gauge!("sekai_object_log_host_behind", "host" => host.to_owned()).set(behind as f64);
}

/// One object-log request sent again after a refusal, lost reply, or lag.
pub fn record_object_log_host_retry() {
    counter!("sekai_object_log_host_retries_total").increment(1);
}

pub fn search_index_lag_ms() -> u64 {
    SEARCH_INDEX_LAG_MS.load(Ordering::Relaxed)
}

pub fn spawn_upkeep_task(pkg_version: &'static str) {
    let handle = handle(pkg_version).clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            handle.run_upkeep();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each metric this module emits carries HELP text in a scrape.
    #[test]
    fn every_emitted_metric_is_described() {
        // Same version as the build-info test: the recorder is process-global.
        let handle = handle("9.9.9-test");
        record_db_lock_poisoned();
        set_search_index_lag_ms(1);
        set_embedding_index_lag_ms(1);
        set_object_log_ingest_backlog(1);
        set_object_log_host_writer("127.0.0.1:1", true);
        set_object_log_host_behind("127.0.0.1:1", 0);
        record_object_log_host_retry();
        let rendered = handle.render();
        for name in [
            "sekai_build_info",
            "db_lock_poisoned_total",
            "sekai_search_index_lag_ms",
            "sekai_embedding_index_lag_ms",
            "sekai_object_log_ingest_backlog",
            "sekai_object_log_host_writer",
            "sekai_object_log_host_behind",
            "sekai_object_log_host_retries_total",
        ] {
            assert!(
                rendered.contains(&format!("# HELP {name} ")),
                "{name} has no HELP text:\n{rendered}"
            );
        }
    }
}
