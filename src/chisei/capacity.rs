//! Capacity snapshot vocabulary and projection.
//!
//! Snapshots are stored as `capacity_snapshot` objects. Chisei reads them for
//! routing pressure; Sekai records and lists them (ADR 0092 rule 3).

use crate::domain::Object;
use std::collections::HashMap;

pub const KIND_CAPACITY_SNAPSHOT: &str = "capacity_snapshot";

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
    let id = format!("cap:{}", metrics.timestamp);
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

/// The newest `limit` snapshots, most recent first, from stored snapshot objects.
pub fn snapshots_from_objects(objs: Vec<Object>, limit: usize) -> Vec<CapacityMetrics> {
    let mut sorted = objs;
    sorted.sort_by_key(|o| std::cmp::Reverse(o.created));
    sorted.truncate(limit);
    sorted
        .into_iter()
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
