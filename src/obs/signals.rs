//! Control-plane operability signals.
//!
//! Covers the signal families Issue #98 requires: control-plane overhead,
//! saturation, database waits, queue depth, cache behavior, receipt and audit
//! lag, fallback, and rejected work.
//!
//! Every label position takes a closed enum from [`crate::obs::labels`], so no
//! call site can attach an object id, namespace, or content digest to a time
//! series. Durations are recorded in seconds to match Prometheus convention and
//! the histogram buckets installed in [`crate::obs::metrics::handle`].

use crate::obs::labels::{
    Cache, CacheOutcome, FallbackTrigger, LagSurface, Outcome, RejectionReason, Subsystem, WaitKind,
};
use metrics::{
    Unit, counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
};
use std::time::Duration;

pub const CONTROL_PLANE_OVERHEAD: &str = "sekai_control_plane_overhead_seconds";
pub const SATURATION_RATIO: &str = "sekai_saturation_ratio";
pub const DB_WAIT: &str = "sekai_db_wait_seconds";
pub const QUEUE_DEPTH: &str = "sekai_queue_depth";
pub const CACHE_EVENTS: &str = "sekai_cache_events_total";
pub const DURABILITY_LAG: &str = "sekai_durability_lag_seconds";
pub const FALLBACK_TOTAL: &str = "sekai_fallback_total";
pub const REJECTED_WORK_TOTAL: &str = "sekai_rejected_work_total";

/// Register descriptions for every signal family.
///
/// Called once from [`crate::obs::metrics::handle`] so that a scrape carries
/// HELP text even before any signal has been emitted.
pub fn describe_all() {
    describe_histogram!(
        CONTROL_PLANE_OVERHEAD,
        Unit::Seconds,
        "Control-plane time spent outside provider execution"
    );
    describe_gauge!(
        SATURATION_RATIO,
        "Utilization of a bounded resource, 0.0 to 1.0"
    );
    describe_histogram!(
        DB_WAIT,
        Unit::Seconds,
        "Time waiting on database work before progress"
    );
    describe_gauge!(QUEUE_DEPTH, "Items currently admitted and awaiting work");
    describe_counter!(CACHE_EVENTS, "Cache lookups by outcome");
    describe_histogram!(
        DURABILITY_LAG,
        Unit::Seconds,
        "Delay between producing a record and its durable visibility"
    );
    describe_counter!(FALLBACK_TOTAL, "Requests that left their preferred path");
    describe_counter!(REJECTED_WORK_TOTAL, "Work refused, by coarse reason");
}

/// Record control-plane overhead attributable to a subsystem.
pub fn record_control_plane_overhead(subsystem: Subsystem, outcome: Outcome, elapsed: Duration) {
    histogram!(
        CONTROL_PLANE_OVERHEAD,
        "subsystem" => subsystem.as_str(),
        "outcome" => outcome.as_str(),
    )
    .record(elapsed.as_secs_f64());
}

/// Set utilization of a bounded resource.
///
/// The ratio is clamped to `0.0..=1.0`: a saturation gauge above one is not
/// meaningful and usually signals a miscounted denominator, which would be
/// worse to display than to clamp.
pub fn set_saturation(subsystem: Subsystem, ratio: f64) {
    let clamped = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    gauge!(SATURATION_RATIO, "subsystem" => subsystem.as_str()).set(clamped);
}

/// Record a wait observed before database progress.
pub fn record_db_wait(kind: WaitKind, outcome: Outcome, waited: Duration) {
    histogram!(
        DB_WAIT,
        "wait_kind" => kind.as_str(),
        "outcome" => outcome.as_str(),
    )
    .record(waited.as_secs_f64());
}

/// Set current queue depth for a subsystem.
pub fn set_queue_depth(subsystem: Subsystem, depth: u64) {
    gauge!(QUEUE_DEPTH, "subsystem" => subsystem.as_str()).set(depth as f64);
}

/// Record a cache lookup outcome.
pub fn record_cache_event(cache: Cache, outcome: CacheOutcome) {
    counter!(
        CACHE_EVENTS,
        "cache" => cache.as_str(),
        "outcome" => outcome.as_str(),
    )
    .increment(1);
}

/// Record delay between producing a record and its durable visibility.
pub fn record_durability_lag(surface: LagSurface, lag: Duration) {
    histogram!(DURABILITY_LAG, "surface" => surface.as_str()).record(lag.as_secs_f64());
}

/// Record that a request left its preferred execution path.
pub fn record_fallback(subsystem: Subsystem, trigger: FallbackTrigger) {
    counter!(
        FALLBACK_TOTAL,
        "subsystem" => subsystem.as_str(),
        "trigger" => trigger.as_str(),
    )
    .increment(1);
}

/// Record refused work.
pub fn record_rejected_work(subsystem: Subsystem, reason: RejectionReason) {
    counter!(
        REJECTED_WORK_TOTAL,
        "subsystem" => subsystem.as_str(),
        "reason" => reason.as_str(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Clamping and label rendering are asserted end-to-end against real
    // scraped output in `tests/observability.rs`, not against a reimplemented
    // copy of the logic here.

    #[test]
    fn signal_names_are_prometheus_compatible() {
        for name in [
            CONTROL_PLANE_OVERHEAD,
            SATURATION_RATIO,
            DB_WAIT,
            QUEUE_DEPTH,
            CACHE_EVENTS,
            DURABILITY_LAG,
            FALLBACK_TOTAL,
            REJECTED_WORK_TOTAL,
        ] {
            assert!(name.starts_with("sekai_"), "{name} lacks the sekai_ prefix");
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "{name} is not a valid Prometheus metric name"
            );
        }
    }

    #[test]
    fn counter_families_end_in_total() {
        for name in [CACHE_EVENTS, FALLBACK_TOTAL, REJECTED_WORK_TOTAL] {
            assert!(
                name.ends_with("_total"),
                "{name} is a counter without _total"
            );
        }
    }

    #[test]
    fn duration_families_end_in_seconds() {
        for name in [CONTROL_PLANE_OVERHEAD, DB_WAIT, DURABILITY_LAG] {
            assert!(
                name.ends_with("_seconds"),
                "{name} records a duration but is not suffixed _seconds"
            );
        }
    }
}
