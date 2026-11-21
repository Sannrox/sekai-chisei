//! Capacity snapshot vocabulary lives in Sekai (ADR 0096 rule 5).

pub use sekai_core::sekai::capacity::{
    CapacityMetrics, KIND_CAPACITY_SNAPSHOT, latest_snapshot_filter, snapshot_object,
    snapshots_from_objects,
};
