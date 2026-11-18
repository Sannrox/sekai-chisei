//! The plane's own signals during benchmark workloads.
//!
//! A benchmark workload may name plane signals in its manifest `observes`
//! list. The bench installs [`SignalRecorder`] as the process metrics
//! recorder, resets it after warmup, and reads each named signal after the
//! sampled iterations. A named signal the run never emitted fails the run.
//! `perf-gate` then gates the recorded values against per-signal manifest
//! budgets ([`evaluate_signals`]) and a baseline ([`compare_signals_to_baseline`]).
//!
//! Other `observes` entries (latency, throughput, ...) describe what the bench
//! measures directly and are not read from the recorder.

use crate::obs::labels::CacheOutcome;
use crate::obs::signals::{CACHE_EVENTS, DB_WAIT, QUEUE_DEPTH};
use crate::perf_regression::{
    Ineligibility, MIN_REPETITIONS, NOISE_CEILING_RSD_PERCENT, SIGNIFICANCE_FACTOR, median,
    spread_percent,
};
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

/// Which way a signal moves when the plane gets worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SignalDirection {
    LowerIsBetter,
    HigherIsBetter,
}

/// Plane signals a workload can name in `observes`:
///
/// - `database_wait_time`: microseconds per sampled iteration spent waiting
///   on the database (`sekai_db_wait_seconds`, every wait kind);
/// - `queue_depth`: the highest admitted-work depth set during the samples
///   (`sekai_queue_depth`, every subsystem);
/// - `cache_hit_rate`: hits over hits plus misses (`sekai_cache_events_total`).
pub const PLANE_SIGNALS: &[(&str, SignalDirection)] = &[
    ("database_wait_time", SignalDirection::LowerIsBetter),
    ("queue_depth", SignalDirection::LowerIsBetter),
    ("cache_hit_rate", SignalDirection::HigherIsBetter),
];

/// The direction of a plane signal, or `None` when `name` is not one.
pub fn plane_signal_direction(name: &str) -> Option<SignalDirection> {
    PLANE_SIGNALS
        .iter()
        .find(|(signal, _)| *signal == name)
        .map(|(_, direction)| *direction)
}

/// Metrics recorder that keeps every series the plane emits, in process.
///
/// Cloning shares the same series, so the bench keeps one clone to read from
/// and installs the other as the global recorder.
#[derive(Clone, Default)]
pub struct SignalRecorder {
    series: Arc<Mutex<HashMap<Key, Arc<Series>>>>,
}

#[derive(Default)]
struct Series {
    state: Mutex<SeriesState>,
}

#[derive(Clone, Copy, Default)]
struct SeriesState {
    updates: u64,
    counter: u64,
    gauge: f64,
    gauge_max: f64,
    histogram_sum: f64,
}

impl Series {
    fn update(&self, apply: impl FnOnce(&mut SeriesState)) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.updates += 1;
        apply(&mut state);
    }

    fn set_gauge(state: &mut SeriesState, value: f64) {
        state.gauge = value;
        state.gauge_max = if state.updates == 1 {
            value
        } else {
            state.gauge_max.max(value)
        };
    }
}

impl CounterFn for Series {
    fn increment(&self, value: u64) {
        self.update(|state| state.counter += value);
    }

    fn absolute(&self, value: u64) {
        self.update(|state| state.counter = value);
    }
}

impl GaugeFn for Series {
    fn increment(&self, value: f64) {
        self.update(|state| Self::set_gauge(state, state.gauge + value));
    }

    fn decrement(&self, value: f64) {
        self.update(|state| Self::set_gauge(state, state.gauge - value));
    }

    fn set(&self, value: f64) {
        self.update(|state| Self::set_gauge(state, value));
    }
}

impl HistogramFn for Series {
    fn record(&self, value: f64) {
        self.update(|state| state.histogram_sum += value);
    }
}

impl Recorder for SignalRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        Counter::from_arc(self.series(key))
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(self.series(key))
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(self.series(key))
    }
}

impl SignalRecorder {
    fn series(&self, key: &Key) -> Arc<Series> {
        self.series
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.clone())
            .or_default()
            .clone()
    }

    /// Forgets every value recorded so far, so the next read covers only what
    /// follows. Series stay registered for handles still held elsewhere.
    pub fn reset(&self) {
        for series in self
            .series
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            *series.state.lock().unwrap_or_else(PoisonError::into_inner) = SeriesState::default();
        }
    }

    /// Emitted states of every series named `name`, with the series key.
    fn emitted(&self, name: &str) -> Vec<(Key, SeriesState)> {
        self.series
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(key, _)| key.name() == name)
            .map(|(key, series)| {
                let state = *series.state.lock().unwrap_or_else(PoisonError::into_inner);
                (key.clone(), state)
            })
            .filter(|(_, state)| state.updates > 0)
            .collect()
    }

    /// Value of plane signal `name` since the last [`reset`](Self::reset), or
    /// `Ok(None)` when the run did not emit it. Unknown names are an error.
    pub fn read(&self, name: &str, sample_iterations: usize) -> Result<Option<f64>, String> {
        let value = match name {
            "database_wait_time" => {
                let waits = self.emitted(DB_WAIT);
                (!waits.is_empty()).then(|| {
                    let seconds: f64 = waits.iter().map(|(_, state)| state.histogram_sum).sum();
                    seconds * 1_000_000.0 / sample_iterations.max(1) as f64
                })
            }
            "queue_depth" => self
                .emitted(QUEUE_DEPTH)
                .iter()
                .map(|(_, state)| state.gauge_max)
                .reduce(f64::max),
            "cache_hit_rate" => {
                let count = |outcome: CacheOutcome| -> u64 {
                    self.emitted(CACHE_EVENTS)
                        .iter()
                        .filter(|(key, _)| {
                            key.labels().any(|label| {
                                label.key() == "outcome" && label.value() == outcome.as_str()
                            })
                        })
                        .map(|(_, state)| state.counter)
                        .sum()
                };
                let hits = count(CacheOutcome::Hit);
                let lookups = hits + count(CacheOutcome::Miss);
                (lookups > 0).then(|| hits as f64 / lookups as f64)
            }
            other => return Err(format!("{other} is not a plane signal")),
        };
        Ok(value)
    }
}

/// The signal values one report recorded for one workload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkloadSignals {
    pub id: String,
    /// Absent in reports written before signals were recorded.
    #[serde(default)]
    pub signals: BTreeMap<String, f64>,
}

/// Outcome of gating one workload signal against its manifest budget.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum SignalOutcome {
    WithinBudget,
    /// The median is worse than the budget by more than the measured spread.
    Regression {
        worse_by_percent: f64,
    },
    /// The median is worse than the budget, but within the measured spread.
    InconclusiveBreach {
        worse_by_percent: f64,
        dispersion_percent: f64,
    },
    NotGateable(Ineligibility),
}

impl SignalOutcome {
    pub fn fails_gate(&self) -> bool {
        matches!(self, Self::Regression { .. })
    }
}

/// Budget decision for one signal of one workload.
#[derive(Debug, Clone, Serialize)]
pub struct SignalDecision {
    pub id: String,
    pub signal: String,
    pub median: f64,
    pub budget: f64,
    pub spread_percent: f64,
    pub outcome: SignalOutcome,
}

/// How much worse `value` is than `reference`, in percent (negative is better).
fn worse_by_percent(direction: SignalDirection, value: f64, reference: f64) -> f64 {
    let delta = match direction {
        SignalDirection::LowerIsBetter => value - reference,
        SignalDirection::HigherIsBetter => reference - value,
    };
    delta / reference * 100.0
}

/// Values of each workload signal across the repeated runs.
fn signal_values(runs: &[Vec<WorkloadSignals>]) -> BTreeMap<(String, String), Vec<f64>> {
    let mut values: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    for run in runs {
        for workload in run {
            for (signal, value) in &workload.signals {
                values
                    .entry((workload.id.clone(), signal.clone()))
                    .or_default()
                    .push(*value);
            }
        }
    }
    values
}

/// Gates each budgeted signal on its median across runs, like the latency
/// gate: a breach counts only beyond the runs' own spread.
///
/// `budgets` maps workload id to signal name to the worst acceptable value.
pub fn evaluate_signals(
    runs: &[Vec<WorkloadSignals>],
    budgets: &BTreeMap<String, BTreeMap<String, f64>>,
) -> Vec<SignalDecision> {
    let values = signal_values(runs);
    let mut decisions = Vec::new();
    for (id, signals) in budgets {
        for (signal, budget) in signals {
            let Some(direction) = plane_signal_direction(signal) else {
                continue;
            };
            let mut samples = values
                .get(&(id.clone(), signal.clone()))
                .cloned()
                .unwrap_or_default();
            let mut decision = SignalDecision {
                id: id.clone(),
                signal: signal.clone(),
                median: 0.0,
                budget: *budget,
                spread_percent: 0.0,
                outcome: SignalOutcome::NotGateable(Ineligibility::InsufficientSamples),
            };
            if samples.len() < MIN_REPETITIONS {
                decisions.push(decision);
                continue;
            }
            decision.median = median(&mut samples);
            decision.spread_percent = spread_percent(&samples, decision.median);
            let worse_by = worse_by_percent(direction, decision.median, *budget);
            decision.outcome = if worse_by <= 0.0 {
                SignalOutcome::WithinBudget
            } else if decision.spread_percent >= NOISE_CEILING_RSD_PERCENT {
                SignalOutcome::NotGateable(Ineligibility::NoiseDominated)
            } else if worse_by > decision.spread_percent * SIGNIFICANCE_FACTOR {
                SignalOutcome::Regression {
                    worse_by_percent: worse_by,
                }
            } else {
                SignalOutcome::InconclusiveBreach {
                    worse_by_percent: worse_by,
                    dispersion_percent: decision.spread_percent,
                }
            };
            decisions.push(decision);
        }
    }
    decisions
}

/// How a workload signal compares against its baseline value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum SignalVerdict {
    Unchanged,
    Improved {
        worse_by_percent: f64,
    },
    Regressed {
        worse_by_percent: f64,
        threshold_percent: f64,
    },
    /// The baseline predates signal recording or lacks this signal.
    SkippedAbsentFromBaseline,
    /// A zero baseline has no relative change to compare.
    SkippedZeroBaseline,
    NotComparable(Ineligibility),
}

impl SignalVerdict {
    pub fn is_regression(&self) -> bool {
        matches!(self, Self::Regressed { .. })
    }
}

/// One workload signal compared against baseline.
#[derive(Debug, Clone, Serialize)]
pub struct SignalComparison {
    pub id: String,
    pub signal: String,
    pub baseline: Option<f64>,
    pub current_median: f64,
    pub verdict: SignalVerdict,
}

/// Compares every recorded signal's median against the baseline value.
/// A change counts only beyond `min_regression_percent` and the runs' spread.
pub fn compare_signals_to_baseline(
    runs: &[Vec<WorkloadSignals>],
    baseline: &[WorkloadSignals],
    min_regression_percent: f64,
) -> Vec<SignalComparison> {
    let baseline: BTreeMap<(&str, &str), f64> = baseline
        .iter()
        .flat_map(|workload| {
            workload
                .signals
                .iter()
                .map(|(signal, value)| ((workload.id.as_str(), signal.as_str()), *value))
        })
        .collect();
    signal_values(runs)
        .into_iter()
        .filter_map(|((id, signal), mut samples)| {
            let direction = plane_signal_direction(&signal)?;
            let current_median = median(&mut samples);
            let reference = baseline.get(&(id.as_str(), signal.as_str())).copied();
            let verdict = match reference {
                None => SignalVerdict::SkippedAbsentFromBaseline,
                Some(_) if samples.len() < MIN_REPETITIONS => {
                    SignalVerdict::NotComparable(Ineligibility::InsufficientSamples)
                }
                Some(0.0) => SignalVerdict::SkippedZeroBaseline,
                Some(reference) => {
                    let spread = spread_percent(&samples, current_median);
                    let worse_by = worse_by_percent(direction, current_median, reference);
                    let threshold = (spread * SIGNIFICANCE_FACTOR).max(min_regression_percent);
                    if spread >= NOISE_CEILING_RSD_PERCENT {
                        SignalVerdict::NotComparable(Ineligibility::NoiseDominated)
                    } else if worse_by > threshold {
                        SignalVerdict::Regressed {
                            worse_by_percent: worse_by,
                            threshold_percent: threshold,
                        }
                    } else if -worse_by > threshold {
                        SignalVerdict::Improved {
                            worse_by_percent: worse_by,
                        }
                    } else {
                        SignalVerdict::Unchanged
                    }
                }
            };
            Some(SignalComparison {
                id,
                signal,
                baseline: reference,
                current_median,
                verdict,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obs::labels::{Cache, Outcome, Subsystem, WaitKind};
    use crate::obs::signals;
    use std::time::Duration;

    fn run(signal: &str, value: f64) -> Vec<WorkloadSignals> {
        vec![WorkloadSignals {
            id: "persistence".into(),
            signals: BTreeMap::from([(signal.into(), value)]),
        }]
    }

    fn budget(signal: &str, value: f64) -> BTreeMap<String, BTreeMap<String, f64>> {
        BTreeMap::from([(
            "persistence".into(),
            BTreeMap::from([(signal.into(), value)]),
        )])
    }

    #[test]
    fn recorder_reads_named_signals_since_reset() {
        let recorder = SignalRecorder::default();
        metrics::with_local_recorder(&recorder, || {
            signals::record_db_wait(
                WaitKind::ConnectionAcquire,
                Outcome::Ok,
                Duration::from_millis(5),
            );
            recorder.reset();
            assert_eq!(recorder.read("database_wait_time", 10).unwrap(), None);
            for _ in 0..4 {
                signals::record_db_wait(WaitKind::Query, Outcome::Ok, Duration::from_millis(5));
            }
            signals::set_queue_depth(Subsystem::Sekai, 7);
            signals::set_queue_depth(Subsystem::Sekai, 2);
            for outcome in [CacheOutcome::Hit, CacheOutcome::Hit, CacheOutcome::Miss] {
                signals::record_cache_event(Cache::GatewayKey, outcome);
            }
            signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Evicted);
        });
        // 20 ms of waits over 10 iterations.
        let wait = recorder.read("database_wait_time", 10).unwrap().unwrap();
        assert!((wait - 2_000.0).abs() < 1e-6, "{wait}");
        assert_eq!(recorder.read("queue_depth", 10).unwrap(), Some(7.0));
        let rate = recorder.read("cache_hit_rate", 10).unwrap().unwrap();
        assert!((rate - 2.0 / 3.0).abs() < 1e-9);
        assert!(recorder.read("throughput", 10).is_err());
        for (signal, _) in PLANE_SIGNALS {
            assert!(SignalRecorder::default().read(signal, 1).unwrap().is_none());
        }
    }

    #[test]
    fn a_signal_over_budget_regresses_while_latency_is_not_involved() {
        let runs = [
            run("database_wait_time", 2_100.0),
            run("database_wait_time", 2_000.0),
            run("database_wait_time", 2_050.0),
        ];
        let decisions = evaluate_signals(&runs, &budget("database_wait_time", 1_000.0));
        assert_eq!(decisions.len(), 1);
        assert!(decisions[0].outcome.fails_gate(), "{:?}", decisions[0]);

        let within = evaluate_signals(&runs, &budget("database_wait_time", 5_000.0));
        assert_eq!(within[0].outcome, SignalOutcome::WithinBudget);

        // Higher is better: a hit rate below its floor regresses.
        let rates = [
            run("cache_hit_rate", 0.5),
            run("cache_hit_rate", 0.5),
            run("cache_hit_rate", 0.5),
        ];
        let decisions = evaluate_signals(&rates, &budget("cache_hit_rate", 0.9));
        assert!(decisions[0].outcome.fails_gate());
    }

    #[test]
    fn a_missing_signal_is_not_gateable_and_noise_is_inconclusive() {
        let runs = [run("database_wait_time", 2_000.0)];
        let decisions = evaluate_signals(&runs, &budget("database_wait_time", 1_000.0));
        assert_eq!(
            decisions[0].outcome,
            SignalOutcome::NotGateable(Ineligibility::InsufficientSamples)
        );
        // 10% over budget inside a 20% spread is not significant.
        let noisy = [
            run("database_wait_time", 1_000.0),
            run("database_wait_time", 1_100.0),
            run("database_wait_time", 1_200.0),
        ];
        let decisions = evaluate_signals(&noisy, &budget("database_wait_time", 1_000.0));
        assert!(matches!(
            decisions[0].outcome,
            SignalOutcome::InconclusiveBreach { .. }
        ));
    }

    #[test]
    fn baseline_comparison_skips_signals_an_old_baseline_lacks() {
        let runs = [
            run("database_wait_time", 2_000.0),
            run("database_wait_time", 2_000.0),
            run("database_wait_time", 2_000.0),
        ];
        let old: Vec<WorkloadSignals> =
            serde_json::from_str(r#"[{"id":"persistence","p95_latency_us":10.0}]"#).unwrap();
        let comparison = compare_signals_to_baseline(&runs, &old, 5.0);
        assert_eq!(
            comparison[0].verdict,
            SignalVerdict::SkippedAbsentFromBaseline
        );

        let regressed =
            compare_signals_to_baseline(&runs, &run("database_wait_time", 1_000.0), 5.0);
        assert!(regressed[0].verdict.is_regression());
        let unchanged =
            compare_signals_to_baseline(&runs, &run("database_wait_time", 1_950.0), 5.0);
        assert_eq!(unchanged[0].verdict, SignalVerdict::Unchanged);
        let improved = compare_signals_to_baseline(&runs, &run("database_wait_time", 4_000.0), 5.0);
        assert!(matches!(
            improved[0].verdict,
            SignalVerdict::Improved { .. }
        ));
    }
}
