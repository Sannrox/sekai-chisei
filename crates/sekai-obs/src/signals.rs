//! Control-plane operability signals.
//!
//! Covers the signal families Issue #98 requires: control-plane overhead,
//! saturation, database waits, queue depth, cache behavior, receipt and audit
//! lag, fallback, and rejected work.
//!
//! Every label position takes a closed enum from [`crate::labels`], so no
//! call site can attach an object id, namespace, or content digest to a time
//! series. Durations are recorded in seconds to match Prometheus convention and
//! the histogram buckets installed in [`crate::metrics::handle`].

use crate::labels::{
    Cache, CacheOutcome, DeduplicationEvent, FallbackTrigger, LagSurface, LookupFirstPath, Outcome,
    PoolPlane, RejectionReason, Subsystem, WaitKind,
};
use metrics::{
    Unit, counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
};
use std::time::Duration;

pub const CONTROL_PLANE_OVERHEAD: &str = "sekai_control_plane_overhead_seconds";
pub const SATURATION_RATIO: &str = "sekai_saturation_ratio";
pub const DB_WAIT: &str = "sekai_db_wait_seconds";
pub const POOL_CHECKOUT: &str = "sekai_db_pool_checkout_seconds";
pub const POOL_IN_USE_RATIO: &str = "sekai_db_pool_in_use_ratio";
pub const QUEUE_DEPTH: &str = "sekai_queue_depth";
pub const CACHE_EVENTS: &str = "sekai_cache_events_total";
pub const DURABILITY_LAG: &str = "sekai_durability_lag_seconds";
pub const FALLBACK_TOTAL: &str = "sekai_fallback_total";
/// 1 when a named upstream provider circuit is open, else 0.
pub const PROVIDER_CIRCUIT_OPEN: &str = "sekai_provider_circuit_open";
pub const REJECTED_WORK_TOTAL: &str = "sekai_rejected_work_total";
pub const DEDUPLICATION_TOTAL: &str = "sekai_deduplication_events_total";
pub const LOOKUP_FIRST_TOTAL: &str = "sekai_lookup_first_total";
pub const EVALUATION_STEP_TOTAL: &str = "sekai_evaluation_step_total";
pub const EVALUATION_STEP_DURATION: &str = "sekai_evaluation_step_duration_seconds";
pub const TRANSFORM_WORK_QUEUED: &str = "sekai_transform_work_queued";
pub const TRANSFORM_WORK_CLAIMABLE: &str = "sekai_transform_work_claimable";
pub const TRANSFORM_WORK_OLDEST_CLAIMABLE_AGE: &str =
    "sekai_transform_work_oldest_claimable_age_seconds";
/// Named worker pools exported per profile besides `default`; later pools
/// in label order fold into [`TRANSFORM_POOL_OTHER`].
pub const MAX_TRANSFORM_POOLS: usize = 32;
pub const TRANSFORM_POOL_OTHER: &str = "other";

/// Register descriptions for every signal family.
///
/// Called once from [`crate::metrics::handle`] so that a scrape carries
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
    describe_histogram!(
        POOL_CHECKOUT,
        Unit::Seconds,
        "Time waiting to check a connection out of a store plane's pool"
    );
    describe_gauge!(
        POOL_IN_USE_RATIO,
        "Share of a store plane's pool checked out at the last checkout, 0.0 to 1.0"
    );
    describe_gauge!(QUEUE_DEPTH, "Items currently admitted and awaiting work");
    describe_counter!(CACHE_EVENTS, "Cache lookups by outcome");
    describe_histogram!(
        DURABILITY_LAG,
        Unit::Seconds,
        "Delay between producing a record and its durable visibility"
    );
    describe_counter!(FALLBACK_TOTAL, "Requests that left their preferred path");
    describe_gauge!(
        PROVIDER_CIRCUIT_OPEN,
        "1 when a named upstream provider circuit is open"
    );
    describe_counter!(REJECTED_WORK_TOTAL, "Work refused, by coarse reason");
    describe_counter!(
        DEDUPLICATION_TOTAL,
        "Deduplication and idempotency decisions"
    );
    describe_counter!(
        LOOKUP_FIRST_TOTAL,
        "Lookup-first answer path decisions (hit vs model)"
    );
    describe_counter!(
        EVALUATION_STEP_TOTAL,
        "Deterministic evaluation steps by compiled static evaluator label, version, and closed status"
    );
    describe_histogram!(
        EVALUATION_STEP_DURATION,
        Unit::Seconds,
        "Deterministic evaluation step latency by compiled static evaluator label, version, and closed status"
    );
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

/// Record one connection checkout from a store plane's pool and the share of
/// that pool in use right after it. Split pools report per plane so a starved
/// plane is visible against the Shared baseline.
pub fn record_pool_checkout(plane: PoolPlane, outcome: Outcome, waited: Duration, in_use: f64) {
    histogram!(
        POOL_CHECKOUT,
        "plane" => plane.as_str(),
        "outcome" => outcome.as_str(),
    )
    .record(waited.as_secs_f64());
    if outcome == Outcome::Ok {
        let clamped = if in_use.is_finite() {
            in_use.clamp(0.0, 1.0)
        } else {
            0.0
        };
        gauge!(POOL_IN_USE_RATIO, "plane" => plane.as_str()).set(clamped);
    }
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

/// Publish whether a bounded provider circuit is currently open.
///
/// `provider` must be a short runtime id (openai, anthropic, ollama, …), not a
/// free-form model name, to keep Prometheus cardinality bounded.
pub fn set_provider_circuit_open(provider: &str, open: bool) {
    gauge!(
        PROVIDER_CIRCUIT_OPEN,
        "provider" => provider.to_string(),
    )
    .set(if open { 1.0 } else { 0.0 });
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

/// Record a deduplication or idempotency decision.
pub fn record_deduplication(subsystem: Subsystem, event: DeduplicationEvent) {
    counter!(
        DEDUPLICATION_TOTAL,
        "subsystem" => subsystem.as_str(),
        "event" => event.as_str(),
    )
    .increment(1);
}

/// Record a lookup-first answer path decision (#281).
pub fn record_lookup_first(path: LookupFirstPath) {
    counter!(LOOKUP_FIRST_TOTAL, "path" => path.as_str()).increment(1);
}

pub fn record_evaluation_step(
    evaluator: &'static str,
    version: &'static str,
    status: &str,
    elapsed: Duration,
) {
    let status = match status {
        "pass" => "pass",
        "fail" => "fail",
        "unknown" => "unknown",
        "unavailable" => "unavailable",
        "error" => "error",
        "skipped" => "skipped",
        _ => "invalid",
    };
    counter!(
        EVALUATION_STEP_TOTAL,
        "evaluator" => evaluator,
        "version" => version,
        "status" => status,
    )
    .increment(1);
    histogram!(
        EVALUATION_STEP_DURATION,
        "evaluator" => evaluator,
        "version" => version,
        "status" => status,
    )
    .record(elapsed.as_secs_f64());
}

/// Queue depth of one transform worker pool at one refresh (#1732).
#[derive(Debug, Clone, PartialEq)]
pub struct TransformPoolGauge {
    pub pool: String,
    pub queued: u64,
    pub claimable: u64,
    pub oldest_claimable_age_seconds: f64,
}

/// Prometheus text for the transform work queue gauges of one snapshot,
/// appended to a scrape (#1732). Rendered here rather than through the
/// recorder, which keeps every series it has seen: a pool that is gone from
/// the store is absent from the next scrape, and the output is a function of
/// the snapshot alone, identical on every plane reading the same store.
/// `pool` values must already be bounded, non-identifying labels. Each
/// profile (the isolated-process transform queue, the `agent-turn` queue of
/// ADR 0137) renders under one HELP and TYPE header per family.
pub fn render_transform_work_depth(profiles: Vec<(&str, Vec<TransformPoolGauge>)>) -> String {
    let profiles: Vec<_> = profiles
        .into_iter()
        .map(|(profile, pools)| (profile, fold_transform_pools(pools)))
        .collect();
    let mut out = String::new();
    for (name, help, value) in [
        (
            TRANSFORM_WORK_QUEUED,
            "Transform runs waiting for a worker, by profile and pool",
            (|gauge: &TransformPoolGauge| gauge.queued as f64) as fn(&TransformPoolGauge) -> f64,
        ),
        (
            TRANSFORM_WORK_CLAIMABLE,
            "Waiting transform runs a registered runtime may claim, by profile and pool",
            |gauge| gauge.claimable as f64,
        ),
        (
            TRANSFORM_WORK_OLDEST_CLAIMABLE_AGE,
            "Age of the oldest claimable transform run, 0 when none, by profile and pool",
            |gauge| gauge.oldest_claimable_age_seconds,
        ),
    ] {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        for (profile, pools) in &profiles {
            for gauge in pools {
                out.push_str(&format!(
                    "{name}{{profile=\"{profile}\",pool=\"{}\"}} {}\n",
                    gauge.pool,
                    value(gauge)
                ));
            }
        }
    }
    out
}

/// Bounds a snapshot to `default` plus [`MAX_TRANSFORM_POOLS`] pools named
/// in label order; later pools are summed into `other` (oldest age is the
/// maximum), which is present only when something overflowed.
fn fold_transform_pools(mut pools: Vec<TransformPoolGauge>) -> Vec<TransformPoolGauge> {
    pools.sort_by(|left, right| {
        (left.pool != "default")
            .cmp(&(right.pool != "default"))
            .then_with(|| left.pool.cmp(&right.pool))
    });
    let named = MAX_TRANSFORM_POOLS
        + usize::from(pools.first().is_some_and(|gauge| gauge.pool == "default"));
    if pools.len() <= named {
        return pools;
    }
    let other = pools.split_off(named).into_iter().fold(
        TransformPoolGauge {
            pool: TRANSFORM_POOL_OTHER.into(),
            queued: 0,
            claimable: 0,
            oldest_claimable_age_seconds: 0.0,
        },
        |mut other, gauge| {
            other.queued += gauge.queued;
            other.claimable += gauge.claimable;
            other.oldest_claimable_age_seconds = other
                .oldest_claimable_age_seconds
                .max(gauge.oldest_claimable_age_seconds);
            other
        },
    );
    pools.push(other);
    pools
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
            POOL_CHECKOUT,
            QUEUE_DEPTH,
            CACHE_EVENTS,
            DURABILITY_LAG,
            FALLBACK_TOTAL,
            PROVIDER_CIRCUIT_OPEN,
            REJECTED_WORK_TOTAL,
            DEDUPLICATION_TOTAL,
            LOOKUP_FIRST_TOTAL,
            EVALUATION_STEP_TOTAL,
            EVALUATION_STEP_DURATION,
            TRANSFORM_WORK_QUEUED,
            TRANSFORM_WORK_CLAIMABLE,
            TRANSFORM_WORK_OLDEST_CLAIMABLE_AGE,
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
    fn transform_pools_fold_by_label_whatever_the_input_order() {
        let depth = |pool: String, queued: u64| TransformPoolGauge {
            pool,
            queued,
            claimable: queued,
            oldest_claimable_age_seconds: queued as f64,
        };
        let pools: Vec<_> = (0..MAX_TRANSFORM_POOLS as u64 + 2)
            .map(|index| depth(format!("p{index:02}"), index + 1))
            .chain([depth("default".into(), 0)])
            .collect();
        let mut reversed = pools.clone();
        reversed.reverse();
        let rendered = render_transform_work_depth(vec![("isolated_process", pools)]);
        // Two refreshers seeing one store state in any order render the same.
        assert_eq!(
            rendered,
            render_transform_work_depth(vec![("isolated_process", reversed)])
        );
        let series = |pool: &str| {
            rendered
                .lines()
                .find(|line| {
                    line.starts_with(&format!(
                        r#"{TRANSFORM_WORK_QUEUED}{{profile="isolated_process",pool="{pool}"}} "#
                    ))
                })
                .map(|line| line.rsplit(' ').next().unwrap().to_string())
        };
        // `default` and the first pools by label are named; the last two fold.
        assert_eq!(series("default").as_deref(), Some("0"));
        assert_eq!(series("p00").as_deref(), Some("1"));
        assert_eq!(series("p31").as_deref(), Some("32"));
        assert_eq!(series("p32"), None);
        assert_eq!(series(TRANSFORM_POOL_OTHER).as_deref(), Some("67"));
        assert!(rendered.contains(&format!(
            r#"{TRANSFORM_WORK_OLDEST_CLAIMABLE_AGE}{{profile="isolated_process",pool="other"}} 34"#
        )));
        let small = render_transform_work_depth(vec![(
            "isolated_process",
            vec![depth("default".into(), 1)],
        )]);
        assert!(!small.contains("pool=\"other\""));
    }

    #[test]
    fn counter_families_end_in_total() {
        for name in [
            CACHE_EVENTS,
            FALLBACK_TOTAL,
            REJECTED_WORK_TOTAL,
            DEDUPLICATION_TOTAL,
            LOOKUP_FIRST_TOTAL,
            EVALUATION_STEP_TOTAL,
        ] {
            assert!(
                name.ends_with("_total"),
                "{name} is a counter without _total"
            );
        }
    }

    #[test]
    fn duration_families_end_in_seconds() {
        for name in [
            CONTROL_PLANE_OVERHEAD,
            DB_WAIT,
            POOL_CHECKOUT,
            DURABILITY_LAG,
            EVALUATION_STEP_DURATION,
            TRANSFORM_WORK_OLDEST_CLAIMABLE_AGE,
        ] {
            assert!(
                name.ends_with("_seconds"),
                "{name} records a duration but is not suffixed _seconds"
            );
        }
    }
}
