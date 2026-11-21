//! Capacity snapshot vocabulary, recording, and listing over the Sekai object
//! store (ADR 0096 rule 5).

use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};
use metrics::gauge;
use std::collections::HashMap;

pub const KIND_CAPACITY_SNAPSHOT: &str = "capacity_snapshot";

/// Newest-first page of stored capacity snapshots.
pub fn latest_snapshot_filter(limit: usize) -> ListFilter {
    ListFilter {
        kind: Some(KIND_CAPACITY_SNAPSHOT.into()),
        order_by: "created".into(),
        descending: true,
        limit: limit.min(i32::MAX as usize) as i32,
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
pub struct CapacityMetrics {
    pub timestamp: i64,
    pub queue_depth: i32,
    pub running_tasks: i32,
    pub agent_count: i32,
    pub avg_wait_seconds: i32,
    pub failure_rate: i32,
    pub utilization: i32,
}

/// The stored object for one snapshot.
pub fn snapshot_object(metrics: &CapacityMetrics) -> Object {
    let id = format!(
        "cap:{}:{}",
        metrics.timestamp,
        uuid::Uuid::new_v4().simple()
    );
    let props = HashMap::from([
        ("queue_depth".into(), metrics.queue_depth.to_string()),
        ("running_tasks".into(), metrics.running_tasks.to_string()),
        ("agent_count".into(), metrics.agent_count.to_string()),
        (
            "avg_wait_seconds".into(),
            metrics.avg_wait_seconds.to_string(),
        ),
        ("failure_rate".into(), metrics.failure_rate.to_string()),
        ("utilization".into(), metrics.utilization.to_string()),
    ]);
    Object {
        id: id.clone(),
        kind: KIND_CAPACITY_SNAPSHOT.into(),
        name: format!("snapshot-{}", metrics.timestamp),
        namespace: "".into(),
        external_id: id,
        properties: props,
        created: metrics.timestamp,
        updated: metrics.timestamp,
    }
}

/// Metrics for stored snapshot objects, in the order the store returned them.
pub fn snapshots_from_objects(objs: Vec<Object>, limit: usize) -> Vec<CapacityMetrics> {
    objs.into_iter()
        .take(limit)
        .map(|o| CapacityMetrics {
            timestamp: o.created,
            queue_depth: o
                .properties
                .get("queue_depth")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            running_tasks: o
                .properties
                .get("running_tasks")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            agent_count: o
                .properties
                .get("agent_count")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            avg_wait_seconds: o
                .properties
                .get("avg_wait_seconds")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            failure_rate: o
                .properties
                .get("failure_rate")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            utilization: o
                .properties
                .get("utilization")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        })
        .collect()
}

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
    let objs = db.list_objects(&latest_snapshot_filter(limit))?;
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

    fn metrics(timestamp: i64, queue_depth: i32) -> CapacityMetrics {
        CapacityMetrics {
            timestamp,
            queue_depth,
            running_tasks: 0,
            agent_count: 1,
            avg_wait_seconds: 0,
            failure_rate: 0,
            utilization: 0,
        }
    }

    #[test]
    fn same_millisecond_snapshots_both_record() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        record_snapshot(&db, &metrics(100, 1)).unwrap();
        record_snapshot(&db, &metrics(100, 9)).unwrap();
        let snaps = latest_snapshots(&db, 10).unwrap();
        assert_eq!(snaps.len(), 2);
        assert!(snaps.iter().all(|snap| snap.timestamp == 100));
        let depths: Vec<_> = snaps.iter().map(|snap| snap.queue_depth).collect();
        assert!(depths.contains(&1) && depths.contains(&9), "{depths:?}");
    }

    #[test]
    fn latest_snapshots_returns_the_newest_page_from_the_store() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for timestamp in 1..=30 {
            record_snapshot(&db, &metrics(timestamp, timestamp as i32)).unwrap();
        }
        let snaps = latest_snapshots(&db, 24).unwrap();
        assert_eq!(snaps.len(), 24);
        assert_eq!(
            snaps.iter().map(|snap| snap.timestamp).collect::<Vec<_>>(),
            (7..=30).rev().collect::<Vec<_>>()
        );
    }
}
