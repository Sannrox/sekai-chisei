//! The decision trend report (#2122, #3090): how governed decisions shift
//! between a window and the baseline window of the same length just before
//! it. [`decision_trend`] reads each window through `ListActionInstances`
//! pages with a created window, and [`reduce`] turns them into the report.
//! `sekaictl report decisions` reads over a client and
//! `SekaiService.GetDecisionTrend` reads through the plane's own handler, so
//! both return the same report. The report lists the instance ids it read and
//! carries a digest over its inputs and results, so a verifier who fetches
//! those instances recomputes the same report.

use sekai_proto::sekai::{ActionInstance, ListActionInstancesRequest, ListActionInstancesResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;

pub const DECISION_TREND_VERSION: &str = "decision_trend/v1";
/// Most instances one window may hold, withheld ones included.
pub const WINDOW_BOUND: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionTrendReport {
    pub version: String,
    pub namespace: String,
    pub window: WindowInput,
    pub baseline: WindowInput,
    pub thresholds: Thresholds,
    /// One entry per action type seen in either window, by type id.
    pub types: Vec<TypeTrend>,
    pub drifted: u32,
    /// `sha256:` over this report with `digest` empty.
    pub digest: String,
}

/// The instances read for one window `[from_ms, before_ms)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowInput {
    pub from_ms: i64,
    pub before_ms: i64,
    /// Sorted.
    pub instance_ids: Vec<String>,
    /// Instances in the window the caller may not read.
    pub withheld: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Fewest instances in each window's denominator before a series is judged.
    pub min_count: u32,
    /// A judged series drifts when its share moves by more than this.
    pub max_share_shift_bps: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_count: 30,
            max_share_shift_bps: 1500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeTrend {
    pub type_id: String,
    pub current: WindowStats,
    pub baseline: WindowStats,
    pub series: Vec<Series>,
}

/// Counts for one action type in one window. Parked counts every instance
/// that waited for an approver; decided counts those an approver (or an
/// expired review queue) granted or denied.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WindowStats {
    pub instances: u32,
    pub policy_allow: u32,
    pub policy_deny: u32,
    pub policy_require_approval: u32,
    pub policy_other: u32,
    pub parked: u32,
    pub approval_grant: u32,
    pub approval_deny: u32,
    pub approval_pending: u32,
    pub decided: u32,
    pub median_time_to_decision_ms: Option<i64>,
    pub p95_time_to_decision_ms: Option<i64>,
    /// Decided after its review deadline, or escalated.
    pub review_missed: u32,
    pub agent_decided: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Series {
    pub name: String,
    pub current_count: u32,
    pub baseline_count: u32,
    /// Share of the denominator in basis points; `None` when it is empty.
    pub current_share_bps: Option<u32>,
    pub baseline_share_bps: Option<u32>,
    pub state: SeriesState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SeriesState {
    Drifted,
    Stable,
    /// A denominator is below `min_count`; the series is not judged.
    LowCount,
}

impl SeriesState {
    /// The state as the report's JSON spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drifted => "drifted",
            Self::Stable => "stable",
            Self::LowCount => "low_count",
        }
    }
}

/// A series' numerator and denominator in one window.
type Share = fn(&WindowStats) -> (u32, u32);

/// Each series by name.
const SERIES: [(&str, Share); 8] = [
    ("policy_allow", |s| (s.policy_allow, s.instances)),
    ("policy_deny", |s| (s.policy_deny, s.instances)),
    ("policy_require_approval", |s| {
        (s.policy_require_approval, s.instances)
    }),
    ("approval_grant", |s| (s.approval_grant, s.parked)),
    ("approval_deny", |s| (s.approval_deny, s.parked)),
    ("approval_pending", |s| (s.approval_pending, s.parked)),
    ("review_missed", |s| (s.review_missed, s.decided)),
    ("agent_decision", |s| (s.agent_decided, s.decided)),
];

/// Reduces the instances of both windows into a report. Pure: the same
/// instances in any order give the same report and digest.
pub fn reduce(
    namespace: &str,
    (window, current): (WindowInput, &[ActionInstance]),
    (baseline, previous): (WindowInput, &[ActionInstance]),
    thresholds: Thresholds,
) -> DecisionTrendReport {
    let mut by_type: BTreeMap<&str, (Vec<&ActionInstance>, Vec<&ActionInstance>)> = BTreeMap::new();
    for instance in current {
        by_type
            .entry(&instance.type_id)
            .or_default()
            .0
            .push(instance);
    }
    for instance in previous {
        by_type
            .entry(&instance.type_id)
            .or_default()
            .1
            .push(instance);
    }
    let types: Vec<TypeTrend> = by_type
        .into_iter()
        .map(|(type_id, (current, previous))| {
            let current = window_stats(&current);
            let baseline = window_stats(&previous);
            let series = SERIES
                .iter()
                .map(|(name, of)| series(name, of(&current), of(&baseline), thresholds))
                .collect();
            TypeTrend {
                type_id: type_id.to_string(),
                current,
                baseline,
                series,
            }
        })
        .collect();
    let drifted = types
        .iter()
        .flat_map(|trend| &trend.series)
        .filter(|series| series.state == SeriesState::Drifted)
        .count() as u32;
    let mut report = DecisionTrendReport {
        version: DECISION_TREND_VERSION.into(),
        namespace: namespace.into(),
        window: sorted_ids(window),
        baseline: sorted_ids(baseline),
        thresholds,
        types,
        drifted,
        digest: String::new(),
    };
    report.digest = digest(&report);
    report
}

/// `sha256:` over `report` with its digest empty.
pub fn digest(report: &DecisionTrendReport) -> String {
    let bytes = serde_json::to_vec(&DecisionTrendReport {
        digest: String::new(),
        ..report.clone()
    })
    .expect("a report always serializes");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn sorted_ids(mut input: WindowInput) -> WindowInput {
    input.instance_ids.sort();
    input
}

fn window_stats(instances: &[&ActionInstance]) -> WindowStats {
    let mut stats = WindowStats {
        instances: instances.len() as u32,
        ..Default::default()
    };
    let mut times = Vec::new();
    for instance in instances {
        match instance.policy_decision.as_str() {
            "allow" | "auto_apply" => stats.policy_allow += 1,
            "deny" => stats.policy_deny += 1,
            decision if decision.starts_with("require_approval") => {
                stats.policy_require_approval += 1
            }
            _ => stats.policy_other += 1,
        }
        let decided = matches!(instance.approval_decision.as_str(), "grant" | "deny");
        if !decided && instance.status != "parked" {
            continue;
        }
        stats.parked += 1;
        match instance.approval_decision.as_str() {
            "grant" => stats.approval_grant += 1,
            "deny" => stats.approval_deny += 1,
            _ => stats.approval_pending += 1,
        }
        if !decided {
            continue;
        }
        stats.decided += 1;
        times.push((instance.decided_at_ms - instance.created_at_ms).max(0));
        if instance.review_escalated
            || (instance.review_sla_deadline_ms > 0
                && instance.decided_at_ms > instance.review_sla_deadline_ms)
        {
            stats.review_missed += 1;
        }
        if instance.agent_decision {
            stats.agent_decided += 1;
        }
    }
    times.sort_unstable();
    stats.median_time_to_decision_ms = nearest_rank(&times, 50);
    stats.p95_time_to_decision_ms = nearest_rank(&times, 95);
    stats
}

fn nearest_rank(sorted: &[i64], percentile: usize) -> Option<i64> {
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted.get(rank.max(1) - 1).copied()
}

fn series(
    name: &str,
    (current_part, current_count): (u32, u32),
    (baseline_part, baseline_count): (u32, u32),
    thresholds: Thresholds,
) -> Series {
    let share = |part: u32, count: u32| {
        (count > 0).then(|| (u64::from(part) * 10_000 / u64::from(count)) as u32)
    };
    let current_share_bps = share(current_part, current_count);
    let baseline_share_bps = share(baseline_part, baseline_count);
    let state = match (current_share_bps, baseline_share_bps) {
        (Some(current), Some(baseline))
            if current_count >= thresholds.min_count && baseline_count >= thresholds.min_count =>
        {
            if current.abs_diff(baseline) > thresholds.max_share_shift_bps {
                SeriesState::Drifted
            } else {
                SeriesState::Stable
            }
        }
        _ => SeriesState::LowCount,
    };
    Series {
        name: name.into(),
        current_count,
        baseline_count,
        current_share_bps,
        baseline_share_bps,
        state,
    }
}

/// Why no report was produced.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecisionTrendError {
    /// A `ListActionInstances` page failed.
    Read(tonic::Status),
    /// A row fell outside the requested window: the server predates the
    /// created window filter and ignored it.
    UnsupportedServer,
    /// The window holds more than [`WINDOW_BOUND`] instances.
    WindowTooLarge { from_ms: i64, before_ms: i64 },
}

impl std::fmt::Display for DecisionTrendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(status) => write!(f, "{}", status.message()),
            Self::UnsupportedServer => f.write_str("server does not support windowed listing"),
            Self::WindowTooLarge { from_ms, before_ms } => write!(
                f,
                "window [{from_ms}..{before_ms}) holds more than {WINDOW_BOUND} governed action instances; narrow the window"
            ),
        }
    }
}

impl std::error::Error for DecisionTrendError {}

/// Reads every instance of `namespace` created in `[from_ms, before_ms)`
/// through `list`, page by page, with the count the caller may not read.
pub async fn list_window<F, Fut>(
    list: &mut F,
    namespace: &str,
    from_ms: i64,
    before_ms: i64,
) -> Result<(Vec<ActionInstance>, u32), DecisionTrendError>
where
    F: FnMut(ListActionInstancesRequest) -> Fut,
    Fut: Future<Output = Result<ListActionInstancesResponse, tonic::Status>>,
{
    let mut instances = Vec::new();
    let mut withheld = 0u32;
    let mut page_token = String::new();
    loop {
        let page = list(ListActionInstancesRequest {
            namespace: namespace.into(),
            limit: 500,
            created_from_ms: Some(from_ms),
            created_before_ms: Some(before_ms),
            page_token,
            ..Default::default()
        })
        .await
        .map_err(DecisionTrendError::Read)?;
        if page
            .instances
            .iter()
            .any(|instance| !(from_ms..before_ms).contains(&instance.created_at_ms))
        {
            return Err(DecisionTrendError::UnsupportedServer);
        }
        instances.extend(page.instances);
        withheld = withheld.saturating_add(page.withheld_count);
        if instances.len() + withheld as usize > WINDOW_BOUND {
            return Err(DecisionTrendError::WindowTooLarge { from_ms, before_ms });
        }
        if page.next_page_token.is_empty() {
            return Ok((instances, withheld));
        }
        page_token = page.next_page_token;
    }
}

/// Reads the window `[until_ms - window_ms, until_ms)` and its baseline
/// through `list` and reduces them.
pub async fn decision_trend<F, Fut>(
    mut list: F,
    namespace: &str,
    window_ms: i64,
    until_ms: i64,
    thresholds: Thresholds,
) -> Result<DecisionTrendReport, DecisionTrendError>
where
    F: FnMut(ListActionInstancesRequest) -> Fut,
    Fut: Future<Output = Result<ListActionInstancesResponse, tonic::Status>>,
{
    let from_ms = until_ms - window_ms;
    let baseline_from_ms = from_ms - window_ms;
    let (current, withheld) = list_window(&mut list, namespace, from_ms, until_ms).await?;
    let (previous, baseline_withheld) =
        list_window(&mut list, namespace, baseline_from_ms, from_ms).await?;
    let input = |from_ms, before_ms, instances: &[ActionInstance], withheld| WindowInput {
        from_ms,
        before_ms,
        instance_ids: instances.iter().map(|i| i.instance_id.clone()).collect(),
        withheld,
    };
    Ok(reduce(
        namespace,
        (input(from_ms, until_ms, &current, withheld), &current),
        (
            input(baseline_from_ms, from_ms, &previous, baseline_withheld),
            &previous,
        ),
        thresholds,
    ))
}
