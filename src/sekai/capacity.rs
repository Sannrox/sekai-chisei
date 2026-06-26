use crate::db::sekai::SekaiDb;
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

pub fn record_snapshot(db: &SekaiDb, metrics: &CapacityMetrics) -> Result<(), String> {
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
    let obj = Object {
        id: id.clone(),
        kind: KIND_CAPACITY_SNAPSHOT.into(),
        name: format!("snapshot-{}", metrics.timestamp),
        namespace: "".into(),
        external_id: id,
        properties: props,
        created: metrics.timestamp,
        updated: metrics.timestamp,
    };
    db.create_object(&obj)
}

pub fn latest_snapshots(db: &SekaiDb, limit: usize) -> Result<Vec<CapacityMetrics>, String> {
    let objs = db.list_objects(&crate::domain::ListFilter {
        kind: Some(KIND_CAPACITY_SNAPSHOT.into()),
        ..Default::default()
    })?;
    let mut sorted = objs;
    sorted.sort_by_key(|o| std::cmp::Reverse(o.created));
    sorted.truncate(limit);
    Ok(sorted
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
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_snapshot() {
        let db = SekaiDb::new(":memory:").unwrap();
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
