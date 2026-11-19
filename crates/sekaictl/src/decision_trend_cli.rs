//! `sekaictl report decisions` (#2122): how governed decisions shift between
//! a window and the baseline window of the same length just before it. The
//! CLI reads each window through `ListActionInstances` with a created window
//! and page tokens, and reduces it locally with [`reduce`]. The report lists
//! the instance ids it read and carries a digest over its inputs and results,
//! so a verifier who fetches those instances recomputes the same report.

use sekai_admin_client::client::{GatewayClient, connect_sekai};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{ActionInstance, ListActionInstancesRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub const DECISION_TREND_VERSION: &str = "decision_trend/v1";
/// Most instances one window may hold, withheld ones included.
const WINDOW_BOUND: usize = 4096;

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

/// Reads every instance of `namespace` created in `[from_ms, before_ms)`,
/// page by page, with the count the caller may not read. Fails when the
/// window holds more than [`WINDOW_BOUND`] instances, and when a row falls
/// outside the window: a server that predates the window filter ignores it.
async fn list_window(
    client: &mut SekaiServiceClient<GatewayClient>,
    namespace: &str,
    from_ms: i64,
    before_ms: i64,
) -> Result<(Vec<ActionInstance>, u32), BoxErr> {
    let mut instances = Vec::new();
    let mut withheld = 0u32;
    let mut page_token = String::new();
    loop {
        let page = client
            .list_action_instances(ListActionInstancesRequest {
                namespace: namespace.into(),
                limit: 500,
                created_from_ms: Some(from_ms),
                created_before_ms: Some(before_ms),
                page_token,
                ..Default::default()
            })
            .await?
            .into_inner();
        if page
            .instances
            .iter()
            .any(|instance| !(from_ms..before_ms).contains(&instance.created_at_ms))
        {
            return Err(std::io::Error::other("server does not support windowed listing").into());
        }
        instances.extend(page.instances);
        withheld = withheld.saturating_add(page.withheld_count);
        if instances.len() + withheld as usize > WINDOW_BOUND {
            return Err(std::io::Error::other(format!(
                "window [{from_ms}..{before_ms}) holds more than {WINDOW_BOUND} governed action instances; narrow the window"
            ))
            .into());
        }
        if page.next_page_token.is_empty() {
            return Ok((instances, withheld));
        }
        page_token = page.next_page_token;
    }
}

/// Reads both windows ending at `until_ms` and reduces them.
async fn decision_trend(
    client: &mut SekaiServiceClient<GatewayClient>,
    namespace: &str,
    window_ms: i64,
    until_ms: i64,
    thresholds: Thresholds,
) -> Result<DecisionTrendReport, BoxErr> {
    let from_ms = until_ms - window_ms;
    let baseline_from_ms = from_ms - window_ms;
    let (current, withheld) = list_window(client, namespace, from_ms, until_ms).await?;
    let (previous, baseline_withheld) =
        list_window(client, namespace, baseline_from_ms, from_ms).await?;
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

/// `sekaictl report decisions`: reads both windows from the plane at
/// `CHISEI_GRPC_URL` or `SEKAI_SOCKET`.
pub async fn run(args: &[String]) -> Result<(), BoxErr> {
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let mut client = SekaiServiceClient::new(connect_sekai(&target).await?);
    report_command(&mut client, args).await
}

/// Runs the parsed command against `client`. With `--fail-on-drift`, a
/// report with a drifted series is printed, then returned as an error.
async fn report_command(
    client: &mut SekaiServiceClient<GatewayClient>,
    args: &[String],
) -> Result<(), BoxErr> {
    // A misspelled --fail-on-drift must fail, not silently turn off the alert.
    let value_args: Vec<String> = args
        .iter()
        .filter(|arg| !SWITCHES.contains(&arg.as_str()))
        .cloned()
        .collect();
    crate::value_flags::check_value_flags(&value_args, &VALUE_FLAGS)
        .map_err(std::io::Error::other)?;
    let namespace = flag(args, "--namespace")
        .ok_or_else(|| std::io::Error::other("--namespace is required"))?;
    let window_ms = parse_duration_ms(
        &flag(args, "--window").ok_or_else(|| std::io::Error::other("--window is required"))?,
    )?;
    let until_ms =
        number_flag(args, "--until-ms")?.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
    let defaults = Thresholds::default();
    let thresholds = Thresholds {
        min_count: number_flag(args, "--min-count")?.unwrap_or(defaults.min_count),
        max_share_shift_bps: number_flag(args, "--max-share-shift-bps")?
            .unwrap_or(defaults.max_share_shift_bps),
    };
    let report = decision_trend(client, &namespace, window_ms, until_ms, thresholds).await?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = flag(args, "--output") {
        std::fs::write(&output, format!("{json}\n"))?;
        println!("created {output}");
    } else if args.iter().any(|arg| arg == "--json") {
        println!("{json}");
    } else {
        print!("{}", render(&report));
    }
    if report.drifted > 0 && args.iter().any(|arg| arg == "--fail-on-drift") {
        return Err(std::io::Error::other(format!("{} series drifted", report.drifted)).into());
    }
    Ok(())
}

/// `<n>ms`, `<n>s`, `<n>m`, `<n>h` or `<n>d`, greater than zero.
fn parse_duration_ms(value: &str) -> Result<i64, BoxErr> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let unit_ms = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => 0,
    };
    number
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(unit_ms))
        .filter(|ms| *ms > 0)
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "--window {value} is not a duration such as 7d, 12h or 30m"
            ))
            .into()
        })
}

fn render(report: &DecisionTrendReport) -> String {
    let mut out = format!(
        "namespace: {}\nwindow: [{}..{}) instances={} withheld={}\nbaseline: [{}..{}) instances={} withheld={}\nmin_count: {}\nmax_share_shift_bps: {}\ndrifted: {}\ndigest: {}\n",
        report.namespace,
        report.window.from_ms,
        report.window.before_ms,
        report.window.instance_ids.len(),
        report.window.withheld,
        report.baseline.from_ms,
        report.baseline.before_ms,
        report.baseline.instance_ids.len(),
        report.baseline.withheld,
        report.thresholds.min_count,
        report.thresholds.max_share_shift_bps,
        report.drifted,
        report.digest,
    );
    let ms = |value: Option<i64>| value.map_or("-".into(), |ms| ms.to_string());
    let bps = |value: Option<u32>| value.map_or("-".into(), |bps| bps.to_string());
    for trend in &report.types {
        out.push_str(&format!(
            "type: {} instances={}/{} decided={}/{} median_decision_ms={}/{} p95_decision_ms={}/{}\n",
            trend.type_id,
            trend.current.instances,
            trend.baseline.instances,
            trend.current.decided,
            trend.baseline.decided,
            ms(trend.current.median_time_to_decision_ms),
            ms(trend.baseline.median_time_to_decision_ms),
            ms(trend.current.p95_time_to_decision_ms),
            ms(trend.baseline.p95_time_to_decision_ms),
        ));
        for series in &trend.series {
            out.push_str(&format!(
                "  {}: share_bps={}/{} count={}/{} {}\n",
                series.name,
                bps(series.current_share_bps),
                bps(series.baseline_share_bps),
                series.current_count,
                series.baseline_count,
                match series.state {
                    SeriesState::Drifted => "drifted",
                    SeriesState::Stable => "stable",
                    SeriesState::LowCount => "low_count",
                },
            ));
        }
    }
    out
}

const VALUE_FLAGS: [&str; 6] = [
    "--namespace",
    "--window",
    "--until-ms",
    "--min-count",
    "--max-share-shift-bps",
    "--output",
];
const SWITCHES: [&str; 2] = ["--json", "--fail-on-drift"];

fn number_flag<T: std::str::FromStr>(args: &[String], name: &str) -> Result<Option<T>, BoxErr> {
    flag(args, name)
        .map(|value| {
            value.parse().map_err(|_| {
                std::io::Error::other(format!("{name} {value} is not a number")).into()
            })
        })
        .transpose()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_proto::sekai::ListActionInstancesResponse;
    use sekai_proto::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
    use tonic::{Request, Response, Status};

    /// A plane holding `instances`, newest first, that pages `page` at a time.
    /// Ids starting with `hidden` are withheld. `windowed: false` is a plane
    /// that predates the created window and ignores it.
    struct Plane {
        instances: Vec<ActionInstance>,
        page: usize,
        windowed: bool,
    }

    #[tonic::async_trait]
    impl SekaiService for Plane {
        async fn list_action_instances(
            &self,
            request: Request<ListActionInstancesRequest>,
        ) -> Result<Response<ListActionInstancesResponse>, Status> {
            let request = request.into_inner();
            if !self.windowed {
                return Ok(Response::new(ListActionInstancesResponse {
                    instances: self.instances.iter().take(self.page).cloned().collect(),
                    ..Default::default()
                }));
            }
            let window = request.created_from_ms.unwrap()..request.created_before_ms.unwrap();
            let start: usize = request.page_token.parse().unwrap_or(0);
            let matching: Vec<_> = self
                .instances
                .iter()
                .filter(|instance| window.contains(&instance.created_at_ms))
                .collect();
            let page: Vec<_> = matching.iter().skip(start).take(self.page).collect();
            let next = start + page.len();
            Ok(Response::new(ListActionInstancesResponse {
                withheld_count: page
                    .iter()
                    .filter(|instance| instance.instance_id.starts_with("hidden"))
                    .count() as u32,
                instances: page
                    .into_iter()
                    .filter(|instance| !instance.instance_id.starts_with("hidden"))
                    .map(|instance| (*instance).clone())
                    .collect(),
                next_page_token: if next < matching.len() {
                    next.to_string()
                } else {
                    String::new()
                },
            }))
        }
    }

    async fn client(plane: Plane) -> SekaiServiceClient<GatewayClient> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SekaiServiceServer::new(plane))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        SekaiServiceClient::new(connect_sekai(&format!("http://{address}")).await.unwrap())
    }

    /// A parked instance of `review` created at `at`, decided `decision`.
    fn parked(id: String, at: i64, decision: &str) -> ActionInstance {
        ActionInstance {
            instance_id: id,
            namespace: "acme".into(),
            type_id: "review".into(),
            status: if decision.is_empty() {
                "parked"
            } else {
                "admitted"
            }
            .into(),
            policy_decision: "require_approval".into(),
            created_at_ms: at,
            decided_at_ms: if decision.is_empty() { 0 } else { at + 60_000 },
            decided_by: "approver".into(),
            approval_decision: decision.into(),
            ..Default::default()
        }
    }

    /// Baseline [0, 1d): 40 parked, half granted. Window [1d, 2d): 40
    /// parked, all granted by the same approver, plus two withheld.
    fn fixture() -> Vec<ActionInstance> {
        let day = 86_400_000;
        let mut instances: Vec<_> = (0..40)
            .map(|n| {
                let decision = if n % 2 == 0 { "grant" } else { "deny" };
                parked(format!("base-{n:02}"), 1_000 + n, decision)
            })
            .chain((0..40).map(|n| parked(format!("cur-{n:02}"), day + 1_000 + n, "grant")))
            .chain((0..2).map(|n| parked(format!("hidden-{n}"), day + 5, "")))
            .collect();
        instances.sort_by_key(|instance| std::cmp::Reverse(instance.created_at_ms));
        instances
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[tokio::test]
    async fn an_approver_who_starts_granting_everything_drifts_and_fails_the_check() {
        let mut client = client(Plane {
            instances: fixture(),
            page: 7,
            windowed: true,
        })
        .await;
        let thresholds = Thresholds::default();
        let report = decision_trend(&mut client, "acme", 86_400_000, 172_800_000, thresholds)
            .await
            .unwrap();
        let review = &report.types[0];
        let grant = review
            .series
            .iter()
            .find(|series| series.name == "approval_grant")
            .unwrap();
        assert_eq!(
            (
                grant.baseline_share_bps,
                grant.current_share_bps,
                grant.state
            ),
            (Some(5_000), Some(10_000), SeriesState::Drifted)
        );
        assert_eq!(report.window.instance_ids.len(), 40);
        assert_eq!(report.window.withheld, 2);
        assert_eq!(review.current.median_time_to_decision_ms, Some(60_000));

        let check = args(&[
            "--namespace",
            "acme",
            "--window",
            "1d",
            "--until-ms",
            "172800000",
            "--json",
        ]);
        report_command(&mut client, &check).await.unwrap();
        let failed = report_command(
            &mut client,
            &[check.clone(), args(&["--fail-on-drift"])].concat(),
        )
        .await
        .unwrap_err();
        assert!(failed.to_string().contains("series drifted"), "{failed}");
        let misspelled = report_command(&mut client, &[check, args(&["--fail-on-drft"])].concat())
            .await
            .unwrap_err();
        assert_eq!(misspelled.to_string(), "unknown option --fail-on-drft");
    }

    /// A verifier who fetched the listed instances, in any order, recomputes
    /// the same report and digest.
    #[test]
    fn the_digest_is_recomputed_from_the_listed_instances() {
        let day = 86_400_000;
        let instances = fixture();
        let input = |from_ms, before_ms, rows: &[ActionInstance]| WindowInput {
            from_ms,
            before_ms,
            instance_ids: rows.iter().map(|i| i.instance_id.clone()).collect(),
            withheld: 0,
        };
        let (current, baseline): (Vec<_>, Vec<_>) = instances
            .into_iter()
            .partition(|instance| instance.created_at_ms >= day);
        let report = reduce(
            "acme",
            (input(day, 2 * day, &current), &current),
            (input(0, day, &baseline), &baseline),
            Thresholds::default(),
        );
        let reversed = |rows: &[ActionInstance]| rows.iter().rev().cloned().collect::<Vec<_>>();
        let (current, baseline) = (reversed(&current), reversed(&baseline));
        let again = reduce(
            "acme",
            (input(day, 2 * day, &current), &current),
            (input(0, day, &baseline), &baseline),
            Thresholds::default(),
        );
        assert_eq!(again, report);
        assert_eq!(digest(&report), report.digest);
    }

    #[tokio::test]
    async fn an_old_server_and_an_oversized_window_are_refused() {
        let mut old = client(Plane {
            instances: fixture(),
            page: 500,
            windowed: false,
        })
        .await;
        let error = list_window(&mut old, "acme", 86_400_000, 172_800_000)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "server does not support windowed listing"
        );

        let mut full = client(Plane {
            instances: (0..=WINDOW_BOUND as i64)
                .map(|n| parked(format!("i-{n}"), n, "grant"))
                .collect(),
            page: 500,
            windowed: true,
        })
        .await;
        let error = list_window(&mut full, "acme", 0, 1_000_000)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("narrow the window"), "{error}");
    }
}
