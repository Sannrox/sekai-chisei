//! Capacity snapshot recording and listing over the Sekai object store.
//!
//! The vocabulary and projection live in Chisei (ADR 0092 rule 3).

use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use metrics::gauge;

pub use crate::chisei::capacity::{
    CapacityMetrics, KIND_CAPACITY_SNAPSHOT, snapshot_object, snapshots_from_objects,
};

pub fn record_snapshot(db: &RuntimeDb, metrics: &CapacityMetrics) -> Result<(), String> {
    // Queue depth is emitted through the labeled operability signal so the
    // family carries one consistent label set. Emitting it here unlabeled as
    // well would render two series under one family with different dimensions,
    // which a scraper would sum across unrelated meanings.
    crate::obs::signals::set_queue_depth(
        crate::obs::labels::Subsystem::Sekai,
        metrics.queue_depth.max(0) as u64,
    );
    gauge!("sekai_running_tasks").set(metrics.running_tasks as f64);
    gauge!("sekai_agent_count").set(metrics.agent_count as f64);
    gauge!("sekai_utilization").set(metrics.utilization as f64);
    gauge!("sekai_failure_rate").set(metrics.failure_rate as f64);

    db.create_object(&snapshot_object(metrics))
}

pub fn latest_snapshots(db: &RuntimeDb, limit: usize) -> Result<Vec<CapacityMetrics>, String> {
    let objs = db.list_all_objects(&crate::domain::ListFilter {
        kind: Some(KIND_CAPACITY_SNAPSHOT.into()),
        ..Default::default()
    })?;
    Ok(snapshots_from_objects(objs, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_snapshot() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        record_snapshot(
            &db,
            &CapacityMetrics {
                timestamp: 100,
                queue_depth: 5,
                running_tasks: 3,
                agent_count: 2,
                avg_wait_seconds: 10,
                failure_rate: 20,
                utilization: 75,
            },
        )
        .unwrap();
        record_snapshot(
            &db,
            &CapacityMetrics {
                timestamp: 200,
                queue_depth: 2,
                running_tasks: 1,
                agent_count: 2,
                avg_wait_seconds: 5,
                failure_rate: 10,
                utilization: 50,
            },
        )
        .unwrap();

        let snaps = latest_snapshots(&db, 10).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].timestamp, 200); // most recent first
        assert_eq!(snaps[0].queue_depth, 2);
    }
}
