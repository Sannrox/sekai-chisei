use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use tonic::Request as GrpcRequest;

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{QueryRowsRequest, Row, RowFilter, RowQuery};

const LLM_CALLS_DATASET: &str = "llm_calls";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReportConfig {
    pub chisei_grpc_target: String,
    pub group_by: ReportGroupBy,
    pub since_ms: i64,
    pub limit: i32,
    pub html_output: Option<PathBuf>,
}

impl GatewayReportConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = Self {
            chisei_grpc_target: std::env::var("CHISEI_GRPC_URL")
                .or_else(|_| std::env::var("SEKAI_SOCKET"))
                .unwrap_or_else(|_| "./data/sekai.sock".to_string()),
            group_by: ReportGroupBy::Agent,
            since_ms: Utc::now().timestamp_millis() - parse_duration_ms("24h")?,
            limit: 10_000,
            html_output: None,
        };

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--chisei-grpc-url" | "--target" => {
                    config.chisei_grpc_target = next_arg(&mut args, &arg)?;
                }
                "--by" | "--group-by" => {
                    config.group_by = next_arg(&mut args, &arg)?.parse()?;
                }
                "--since" => {
                    config.since_ms = Utc::now().timestamp_millis()
                        - parse_duration_ms(&next_arg(&mut args, &arg)?)?;
                }
                "--limit" => {
                    config.limit = next_arg(&mut args, &arg)?
                        .parse()
                        .map_err(|_| format!("{arg} must be an integer"))?;
                }
                "--html" => {
                    config.html_output = Some(PathBuf::from(next_arg(&mut args, &arg)?));
                }
                "--help" | "-h" => return Err(report_usage()),
                other => return Err(format!("unknown argument {other:?}\n\n{}", report_usage())),
            }
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.chisei_grpc_target.trim().is_empty() {
            return Err("chisei_grpc_target must not be empty".to_string());
        }
        if self.limit < 0 {
            return Err("limit must not be negative".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportGroupBy {
    Project,
    Agent,
    Model,
}

impl ReportGroupBy {
    fn label(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Model => "model",
        }
    }
}

impl std::str::FromStr for ReportGroupBy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "project" => Ok(Self::Project),
            "agent" => Ok(Self::Agent),
            "model" => Ok(Self::Model),
            other => Err(format!(
                "unsupported report group {other:?}; expected project, agent, or model"
            )),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayReportRow {
    pub group: String,
    pub calls: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub cost_usd_micros: i64,
}

pub async fn run_report(
    config: GatewayReportConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.chisei_grpc_target).await?;
    let mut sekai = SekaiServiceClient::new(channel);
    let resp = sekai
        .query_rows(gateway_request(QueryRowsRequest {
            dataset_id: LLM_CALLS_DATASET.to_string(),
            query: Some(RowQuery {
                filters: vec![RowFilter {
                    column: "timestamp_ms".to_string(),
                    op: "gte".to_string(),
                    value: config.since_ms.to_string(),
                }],
                columns: vec![
                    "project".to_string(),
                    "agent".to_string(),
                    "model".to_string(),
                    "resolved_model".to_string(),
                    "work_unit_id".to_string(),
                    "pipeline_sampled".to_string(),
                    "sample_reason".to_string(),
                    "sample_rate".to_string(),
                    "input_tokens".to_string(),
                    "output_tokens".to_string(),
                    "total_tokens".to_string(),
                    "cost_usd_micros".to_string(),
                    "cost_usd".to_string(),
                ],
                limit: config.limit,
                offset: 0,
            }),
        }))
        .await?
        .into_inner();

    if let Some(path) = &config.html_output {
        let html = render_dashboard(&resp.rows, config.since_ms);
        std::fs::write(path, html)?;
        println!("wrote chisei gateway dashboard: {}", path.display());
    } else {
        let rows = summarize_rows(resp.rows, config.group_by);
        print_report(config.group_by, &rows);
    }
    Ok(())
}

pub fn summarize_rows(rows: Vec<Row>, group_by: ReportGroupBy) -> Vec<GatewayReportRow> {
    let mut groups: BTreeMap<String, GatewayReportRow> = BTreeMap::new();
    for row in rows {
        let group = report_group(&row, group_by);
        let summary = groups.entry(group.clone()).or_insert(GatewayReportRow {
            group,
            ..Default::default()
        });
        summary.calls += 1;
        summary.input_tokens += parse_i64(row.values.get("input_tokens"));
        summary.output_tokens += parse_i64(row.values.get("output_tokens"));
        summary.total_tokens += parse_i64(row.values.get("total_tokens"));
        summary.cost_usd_micros += parse_i64(row.values.get("cost_usd_micros"));
    }
    let mut summaries = groups.into_values().collect::<Vec<_>>();
    summaries.sort_by(|a, b| {
        b.total_tokens
            .cmp(&a.total_tokens)
            .then_with(|| b.calls.cmp(&a.calls))
            .then_with(|| a.group.cmp(&b.group))
    });
    summaries
}

fn report_group(row: &Row, group_by: ReportGroupBy) -> String {
    let value = match group_by {
        ReportGroupBy::Project => row.values.get("project"),
        ReportGroupBy::Agent => row.values.get("agent"),
        ReportGroupBy::Model => row
            .values
            .get("resolved_model")
            .filter(|model| !model.is_empty())
            .or_else(|| row.values.get("model")),
    };
    value
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn print_report(group_by: ReportGroupBy, rows: &[GatewayReportRow]) {
    println!(
        "{:<24} {:>8} {:>14} {:>14} {:>14} {:>14}",
        group_by.label(),
        "calls",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "est_cost_usd"
    );
    println!("{}", "-".repeat(96));
    for row in rows {
        println!(
            "{:<24} {:>8} {:>14} {:>14} {:>14} {:>14}",
            truncate(&row.group, 24),
            row.calls,
            row.input_tokens,
            row.output_tokens,
            row.total_tokens,
            format_usd_micros(row.cost_usd_micros)
        );
    }
}

pub fn render_dashboard(rows: &[Row], since_ms: i64) -> String {
    let by_project = summarize_rows(rows.to_vec(), ReportGroupBy::Project);
    let by_agent = summarize_rows(rows.to_vec(), ReportGroupBy::Agent);
    let by_model = summarize_rows(rows.to_vec(), ReportGroupBy::Model);
    let totals = rows
        .iter()
        .fold(GatewayReportRow::default(), |mut total, row| {
            total.calls += 1;
            total.input_tokens += parse_i64(row.values.get("input_tokens"));
            total.output_tokens += parse_i64(row.values.get("output_tokens"));
            total.total_tokens += parse_i64(row.values.get("total_tokens"));
            total.cost_usd_micros += parse_i64(row.values.get("cost_usd_micros"));
            total
        });
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chisei Gateway Usage</title>
<style>
:root {{ color-scheme: light; --ink:#18212f; --muted:#667085; --line:#d9dee8; --panel:#f7f9fc; --accent:#1565c0; }}
body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:white; }}
main {{ max-width:1120px; margin:0 auto; padding:32px 20px 48px; }}
h1 {{ font-size:28px; margin:0 0 4px; letter-spacing:0; }}
h2 {{ font-size:18px; margin:28px 0 10px; letter-spacing:0; }}
p {{ color:var(--muted); margin:0 0 20px; }}
.metrics {{ display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:12px; margin:22px 0 18px; }}
.metric {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }}
.label {{ color:var(--muted); font-size:13px; }}
.value {{ font-size:24px; font-weight:700; margin-top:4px; }}
table {{ width:100%; border-collapse:collapse; border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:right; font-variant-numeric: tabular-nums; }}
th:first-child, td:first-child {{ text-align:left; }}
th {{ background:var(--panel); color:#344054; font-size:13px; }}
tr:last-child td {{ border-bottom:0; }}
.bar {{ display:inline-block; height:8px; background:var(--accent); border-radius:999px; min-width:2px; vertical-align:middle; margin-left:10px; }}
@media (max-width: 760px) {{ .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} main {{ padding:22px 12px 36px; }} table {{ font-size:13px; }} th, td {{ padding:8px; }} }}
</style>
</head>
<body>
<main>
<h1>Chisei Gateway Usage</h1>
<p>Rows since {since}. Generated from the <code>llm_calls</code> dataset.</p>
<section class="metrics">
{metrics}
</section>
{project}
{agent}
{model}
</main>
</body>
</html>
"#,
        since = html_escape(&since_ms.to_string()),
        metrics = render_metric_cards(&totals),
        project = render_section("By Project", "project", &by_project),
        agent = render_section("By Agent", "agent", &by_agent),
        model = render_section("By Model", "model", &by_model),
    )
}

fn render_metric_cards(total: &GatewayReportRow) -> String {
    [
        ("Calls", total.calls.to_string()),
        ("Input tokens", total.input_tokens.to_string()),
        ("Output tokens", total.output_tokens.to_string()),
        ("Total tokens", total.total_tokens.to_string()),
        (
            "Estimated cost",
            format!("${}", format_usd_micros(total.cost_usd_micros)),
        ),
    ]
    .into_iter()
    .map(|(label, value)| {
        format!(
            r#"<div class="metric"><div class="label">{}</div><div class="value">{}</div></div>"#,
            html_escape(label),
            value
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_section(title: &str, first_column: &str, rows: &[GatewayReportRow]) -> String {
    let max_tokens = rows.iter().map(|row| row.total_tokens).max().unwrap_or(0);
    let body = rows
        .iter()
        .map(|row| {
            let width = if max_tokens > 0 {
                ((row.total_tokens * 100) / max_tokens).max(2)
            } else {
                0
            };
            format!(
                r#"<tr><td>{group}<span class="bar" style="width:{width}%"></span></td><td>{calls}</td><td>{input}</td><td>{output}</td><td>{total}</td><td>${cost}</td></tr>"#,
                group = html_escape(&row.group),
                width = width,
                calls = row.calls,
                input = row.input_tokens,
                output = row.output_tokens,
                total = row.total_tokens,
                cost = format_usd_micros(row.cost_usd_micros)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<section>
<h2>{title}</h2>
<table>
<thead><tr><th>{first_column}</th><th>calls</th><th>input tokens</th><th>output tokens</th><th>total tokens</th><th>est. cost</th></tr></thead>
<tbody>
{body}
</tbody>
</table>
</section>"#,
        title = html_escape(title),
        first_column = html_escape(first_column),
        body = body
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn parse_i64(value: Option<&String>) -> i64 {
    value
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
}

fn format_usd_micros(value: i64) -> String {
    format!("{}.{:06}", value / 1_000_000, (value % 1_000_000).abs())
}

fn parse_duration_ms(value: &str) -> Result<i64, String> {
    let value = value.trim();
    let (number, multiplier) = match value.chars().last() {
        Some('m') => (&value[..value.len() - 1], 60_000),
        Some('h') => (&value[..value.len() - 1], 60 * 60_000),
        Some('d') => (&value[..value.len() - 1], 24 * 60 * 60_000),
        _ => (value, 1),
    };
    let number = number
        .parse::<i64>()
        .map_err(|_| format!("invalid duration {value:?}; use forms like 30m, 24h, or 7d"))?;
    if number < 0 {
        return Err("duration must not be negative".to_string());
    }
    Ok(number.saturating_mul(multiplier))
}

fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    value
        .chars()
        .take(width.saturating_sub(3))
        .collect::<String>()
        + "..."
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn gateway_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "chisei-gateway".parse().unwrap());
    request
}

pub fn report_usage() -> String {
    "Usage: chisei-gateway report [--target <grpc-url>] [--by <project|agent|model>] [--since <30m|24h|7d>] [--limit <rows>] [--html <path>]".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parses_report_args() {
        let config = GatewayReportConfig::from_env_and_args([
            "--target".to_string(),
            "http://127.0.0.1:50051".to_string(),
            "--by".to_string(),
            "project".to_string(),
            "--since".to_string(),
            "7d".to_string(),
            "--limit".to_string(),
            "25".to_string(),
        ])
        .unwrap();

        assert_eq!(config.chisei_grpc_target, "http://127.0.0.1:50051");
        assert_eq!(config.group_by, ReportGroupBy::Project);
        assert_eq!(config.limit, 25);
        assert_eq!(config.html_output, None);
        assert!(config.since_ms <= Utc::now().timestamp_millis());
    }

    #[test]
    fn parses_html_output_arg() {
        let config = GatewayReportConfig::from_env_and_args([
            "--html".to_string(),
            "dashboard.html".to_string(),
        ])
        .unwrap();

        assert_eq!(config.html_output, Some(PathBuf::from("dashboard.html")));
    }

    #[test]
    fn summarizes_rows_by_resolved_model() {
        let rows = vec![
            row([
                ("model", "gpt-5.5"),
                ("resolved_model", "gpt-5.5-mini"),
                ("input_tokens", "10"),
                ("output_tokens", "3"),
                ("total_tokens", "13"),
                ("cost_usd_micros", "16"),
            ]),
            row([
                ("model", "gpt-5.5"),
                ("resolved_model", "gpt-5.5-mini"),
                ("input_tokens", "7"),
                ("output_tokens", "4"),
                ("total_tokens", "11"),
                ("cost_usd_micros", "15"),
            ]),
            row([
                ("model", "claude-opus-4-8"),
                ("input_tokens", "5"),
                ("output_tokens", "2"),
                ("total_tokens", "7"),
                ("cost_usd_micros", "21"),
            ]),
        ];

        let report = summarize_rows(rows, ReportGroupBy::Model);
        assert_eq!(
            report,
            vec![
                GatewayReportRow {
                    group: "gpt-5.5-mini".to_string(),
                    calls: 2,
                    input_tokens: 17,
                    output_tokens: 7,
                    total_tokens: 24,
                    cost_usd_micros: 31,
                },
                GatewayReportRow {
                    group: "claude-opus-4-8".to_string(),
                    calls: 1,
                    input_tokens: 5,
                    output_tokens: 2,
                    total_tokens: 7,
                    cost_usd_micros: 21,
                },
            ]
        );
    }

    fn row(values: impl IntoIterator<Item = (&'static str, &'static str)>) -> Row {
        Row {
            values: HashMap::from_iter(
                values
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            ),
        }
    }

    #[test]
    fn dashboard_renders_all_groupings_and_escapes_values() {
        let html = render_dashboard(
            &[
                row([
                    ("project", "sekai-chisei"),
                    ("agent", "codex-app"),
                    ("model", "gpt-5.5"),
                    ("input_tokens", "10"),
                    ("output_tokens", "5"),
                    ("total_tokens", "15"),
                    ("cost_usd_micros", "25"),
                ]),
                row([
                    ("project", "danger<&>"),
                    ("agent", "claude-code"),
                    ("model", "claude-sonnet-4-8"),
                    ("input_tokens", "7"),
                    ("output_tokens", "3"),
                    ("total_tokens", "10"),
                    ("cost_usd_micros", "15"),
                ]),
            ],
            123,
        );

        assert!(html.contains("Chisei Gateway Usage"));
        assert!(html.contains("By Project"));
        assert!(html.contains("By Agent"));
        assert!(html.contains("By Model"));
        assert!(html.contains("Estimated cost"));
        assert!(html.contains("$0.000040"));
        assert!(html.contains("codex-app"));
        assert!(html.contains("danger&lt;&amp;&gt;"));
        assert!(!html.contains("danger<&>"));
    }
}
