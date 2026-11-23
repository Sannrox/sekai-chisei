//! `sekaictl report decisions` (#2122): how governed decisions shift between
//! a window and the baseline window of the same length just before it. The
//! reduction and the window reader live in
//! [`sekai_admin_client::decision_trend`], shared with
//! `SekaiService.GetDecisionTrend` (#3090); this module parses flags, reads
//! over a client and renders the report.

use sekai_admin_client::client::{GatewayClient, connect_sekai};
pub use sekai_admin_client::decision_trend::{
    DECISION_TREND_VERSION, DecisionTrendReport, Series, SeriesState, Thresholds, TypeTrend,
    WindowInput, WindowStats, digest, reduce,
};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Reads both windows ending at `until_ms` from `client` and reduces them.
async fn decision_trend(
    client: &mut SekaiServiceClient<GatewayClient>,
    namespace: &str,
    window_ms: i64,
    until_ms: i64,
    thresholds: Thresholds,
) -> Result<DecisionTrendReport, BoxErr> {
    let list = |request| {
        let mut client = client.clone();
        async move {
            client
                .list_action_instances(request)
                .await
                .map(tonic::Response::into_inner)
        }
    };
    Ok(sekai_admin_client::decision_trend::decision_trend(
        list, namespace, window_ms, until_ms, thresholds,
    )
    .await?)
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
                series.state.as_str(),
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
    use sekai_admin_client::decision_trend::WINDOW_BOUND;
    use sekai_proto::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
    use sekai_proto::sekai::{
        ActionInstance, ListActionInstancesRequest, ListActionInstancesResponse,
    };
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
        let error = decision_trend(
            &mut old,
            "acme",
            86_400_000,
            172_800_000,
            Thresholds::default(),
        )
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
        let error = decision_trend(
            &mut full,
            "acme",
            1_000_000,
            1_000_000,
            Thresholds::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("narrow the window"), "{error}");
    }
}
