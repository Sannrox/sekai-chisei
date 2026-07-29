//! Shared gateway report queries, aggregation, and rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chrono::Utc;
use futures_util::{StreamExt, stream};
use tonic::Request as GrpcRequest;

use crate::client::{GatewayClient, connect_sekai};
use sekai_proto::chisei::CheckBudgetRequest;
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{QueryRowsRequest, Row, RowFilter, RowQuery};

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
    Provider,
    ProviderModel,
    Model,
    WorkUnit,
    AgentWithinProject,
}

impl ReportGroupBy {
    fn label(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Provider => "provider",
            Self::ProviderModel => "provider/model",
            Self::Model => "model",
            Self::WorkUnit => "work_unit",
            Self::AgentWithinProject => "agent/project",
        }
    }
}

impl std::str::FromStr for ReportGroupBy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "project" => Ok(Self::Project),
            "agent" => Ok(Self::Agent),
            "provider" => Ok(Self::Provider),
            "provider-model" | "provider_model" => Ok(Self::ProviderModel),
            "model" => Ok(Self::Model),
            "work-unit" | "work_unit" => Ok(Self::WorkUnit),
            "agent-within-project" | "agent_within_project" => Ok(Self::AgentWithinProject),
            other => Err(format!(
                "unsupported report group {other:?}; expected project, agent, provider, provider-model, model, work-unit, or agent-within-project"
            )),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayReportRow {
    pub group: String,
    pub calls: i64,
    pub operations: i64,
    pub successful_outcomes: i64,
    pub input_tokens: i64,
    pub uncached_input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub cost_usd_micros: i64,
    pub cache_read_input_tokens: i64,
    pub cache_creation_input_tokens: i64,
    pub cache_warm_reads: i64,
    pub cache_cold_writes: i64,
    pub cache_misses: i64,
    pub cache_accounted_calls: i64,
    pub cache_unaccounted_attempts: i64,
    pub cache_savings_usd_micros: i64,
    pub refusals: i64,
    pub terminal_failures: i64,
    pub models: BTreeMap<String, i64>,
    pub profile_versions: BTreeMap<String, i64>,
    pub capability_snapshots: BTreeMap<String, i64>,
    pub budget_used: i64,
    pub budget_limit: i64,
}

pub async fn run_report(
    config: GatewayReportConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.chisei_grpc_target).await?;
    let mut sekai = SekaiServiceClient::new(channel.clone());
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
                    "operation_id".to_string(),
                    "provider".to_string(),
                    "model".to_string(),
                    "resolved_model".to_string(),
                    "profile_version".to_string(),
                    "capability_snapshot_version".to_string(),
                    "work_unit_id".to_string(),
                    "pipeline_sampled".to_string(),
                    "sample_reason".to_string(),
                    "sample_rate".to_string(),
                    "status".to_string(),
                    "terminal_outcome".to_string(),
                    "refusal_reason".to_string(),
                    "input_tokens".to_string(),
                    "uncached_input_tokens".to_string(),
                    "output_tokens".to_string(),
                    "total_tokens".to_string(),
                    "provider_total_tokens".to_string(),
                    "cost_usd_micros".to_string(),
                    "cost_usd".to_string(),
                    "cache_read_input_tokens".to_string(),
                    "cache_creation_input_tokens".to_string(),
                    "cache_creation_5m_input_tokens".to_string(),
                    "cache_creation_1h_input_tokens".to_string(),
                    "cache_requested".to_string(),
                    "pricing_snapshot_version".to_string(),
                    "cache_savings_usd_micros".to_string(),
                    "cache_savings_usd".to_string(),
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
        let mut rows = summarize_rows(resp.rows.clone(), config.group_by);
        if config.group_by == ReportGroupBy::WorkUnit {
            attach_work_unit_budgets(&mut rows, &resp.rows, channel).await;
        }
        print_report(config.group_by, &rows);
    }
    Ok(())
}

pub fn render_egress_html(rows: &[Row]) -> String {
    let since = rows
        .iter()
        .filter_map(|row| row.values.get("timestamp_ms"))
        .filter_map(|value| value.parse::<i64>().ok())
        .min()
        .unwrap_or(0);
    render_dashboard(rows, since)
}

pub fn render_egress_csv(rows: &[Row]) -> String {
    let mut columns = std::collections::BTreeSet::new();
    for row in rows {
        for key in row.values.keys() {
            columns.insert(key.clone());
        }
    }
    let ordered: Vec<_> = columns
        .into_iter()
        .filter(|name| !name.is_empty())
        .collect();

    let mut out = String::new();
    out.push_str(&ordered.join(","));
    if !ordered.is_empty() {
        out.push('\n');
    }

    for row in rows {
        for (index, column) in ordered.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let value = row
                .values
                .get(column)
                .map(|value| value.as_str())
                .unwrap_or("");
            /*
            let escaped = value.replace('"', "\\"\"");
            */
            let escaped = value.replace('"', "\"\"");
            out.push('"');
            out.push_str(&escaped);
            out.push('"');
        }
        out.push('\n');
    }
    out
}

pub fn summarize_rows(rows: Vec<Row>, group_by: ReportGroupBy) -> Vec<GatewayReportRow> {
    let mut groups: BTreeMap<String, GatewayReportRow> = BTreeMap::new();
    let mut operations: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (row_index, row) in rows.into_iter().enumerate() {
        let group = report_group(&row, group_by);
        let summary = groups.entry(group.clone()).or_insert(GatewayReportRow {
            group: group.clone(),
            ..Default::default()
        });
        summary.calls += 1;
        let operation_key = row
            .values
            .get("operation_id")
            .filter(|operation_id| !operation_id.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("legacy-row-{row_index}"));
        operations
            .entry(group.clone())
            .or_default()
            .insert(operation_key);
        if row_is_successful(&row) {
            summary.successful_outcomes += 1;
        }
        summary.input_tokens += parse_i64(row.values.get("input_tokens"));
        let cache_reads = parse_i64(row.values.get("cache_read_input_tokens"));
        summary.uncached_input_tokens += row
            .values
            .get("uncached_input_tokens")
            .map(|value| parse_i64(Some(value)))
            .unwrap_or_else(|| legacy_uncached_input(&row, cache_reads));
        summary.output_tokens += parse_i64(row.values.get("output_tokens"));
        summary.total_tokens += parse_i64(row.values.get("total_tokens"));
        summary.cost_usd_micros += parse_i64(row.values.get("cost_usd_micros"));
        summary.cache_read_input_tokens += parse_i64(row.values.get("cache_read_input_tokens"));
        let cache_writes = parse_i64(row.values.get("cache_creation_input_tokens"));
        summary.cache_creation_input_tokens += cache_writes;
        summary.cache_warm_reads += i64::from(cache_reads > 0);
        summary.cache_cold_writes += i64::from(cache_writes > 0);
        let cache_requested = row
            .values
            .get("cache_requested")
            .is_some_and(|value| value == "true");
        let accounting_reported = row.values.contains_key("cache_read_input_tokens")
            || row.values.contains_key("cache_creation_input_tokens");
        let cache_accounted =
            cache_reads > 0 || cache_writes > 0 || (cache_requested && accounting_reported);
        summary.cache_accounted_calls += i64::from(cache_accounted);
        summary.cache_misses += i64::from(
            cache_requested && accounting_reported && cache_reads == 0 && cache_writes == 0,
        );
        summary.cache_unaccounted_attempts += i64::from(cache_requested && !accounting_reported);
        summary.cache_savings_usd_micros += parse_i64(row.values.get("cache_savings_usd_micros"));
        if row
            .values
            .get("status")
            .is_some_and(|status| status == "refused")
            || row
                .values
                .get("refusal_reason")
                .is_some_and(|reason| !reason.is_empty())
        {
            summary.refusals += 1;
        }
        if row
            .values
            .get("terminal_outcome")
            .is_some_and(|outcome| !outcome.is_empty() && outcome != "completed")
        {
            summary.terminal_failures += 1;
        }
        if group_by == ReportGroupBy::WorkUnit {
            let model = row
                .values
                .get("resolved_model")
                .filter(|model| !model.is_empty())
                .or_else(|| row.values.get("model").filter(|model| !model.is_empty()))
                .cloned();
            if let Some(model) = model {
                *summary.models.entry(model).or_default() += 1;
            }
        }
        if let Some(version) = row
            .values
            .get("profile_version")
            .filter(|version| !version.is_empty())
        {
            *summary.profile_versions.entry(version.clone()).or_default() += 1;
        }
        if let Some(snapshot) = row
            .values
            .get("capability_snapshot_version")
            .filter(|snapshot| !snapshot.is_empty())
        {
            *summary
                .capability_snapshots
                .entry(snapshot.clone())
                .or_default() += 1;
        }
    }
    let mut summaries = groups
        .into_iter()
        .map(|(group, mut summary)| {
            summary.operations = operations.get(&group).map_or(0, BTreeSet::len) as i64;
            summary
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|a, b| {
        b.total_tokens
            .cmp(&a.total_tokens)
            .then_with(|| b.calls.cmp(&a.calls))
            .then_with(|| a.group.cmp(&b.group))
    });
    summaries
}

async fn attach_work_unit_budgets(
    summaries: &mut [GatewayReportRow],
    source_rows: &[Row],
    channel: GatewayClient,
) {
    let mut contexts = BTreeMap::new();
    for row in source_rows {
        let Some(work_unit) = row
            .values
            .get("work_unit_id")
            .filter(|work_unit| !work_unit.is_empty())
        else {
            continue;
        };
        contexts.entry(work_unit.clone()).or_insert_with(|| {
            (
                row.values.get("project").cloned().unwrap_or_default(),
                row.values.get("agent").cloned().unwrap_or_default(),
            )
        });
    }
    let requests = summaries
        .iter()
        .filter(|row| row.group != "(unknown)")
        .map(|summary| {
            let (project, agent) = contexts.get(&summary.group).cloned().unwrap_or_default();
            (summary.group.clone(), project, agent)
        })
        .collect::<Vec<_>>();
    let usages = stream::iter(requests)
        .map(|(work_unit, project, agent)| {
            let mut chisei = ChiseiServiceClient::new(channel.clone());
            async move {
                let result = chisei
                    .check_budget(gateway_request(CheckBudgetRequest {
                        subject: String::new(),
                        estimated_tokens: 0,
                        project,
                        agent,
                        key_id: String::new(),
                        work_unit: work_unit.clone(),
                        user_id: String::new(),
                        metric: "tokens".to_string(),
                        task_class: String::new(),
                        mid_task: false,
                        local_free_available: false,
                    }))
                    .await
                    .map(|response| response.into_inner().usage);
                (work_unit, result)
            }
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;
    let mut by_work_unit = summaries
        .iter_mut()
        .map(|summary| (summary.group.clone(), summary))
        .collect::<BTreeMap<_, _>>();
    for (work_unit, result) in usages {
        match result {
            Ok(Some(usage)) => {
                if let Some(summary) = by_work_unit.get_mut(&work_unit) {
                    summary.budget_used = i64::from(usage.tokens_used);
                    summary.budget_limit = i64::from(usage.max_tokens);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%work_unit, %error, "could not load work-unit budget usage");
            }
        }
    }
}

fn report_group(row: &Row, group_by: ReportGroupBy) -> String {
    let value = match group_by {
        ReportGroupBy::Project => row.values.get("project"),
        ReportGroupBy::Agent => row.values.get("agent"),
        ReportGroupBy::Provider => row.values.get("provider"),
        ReportGroupBy::ProviderModel => {
            let provider = row.values.get("provider").filter(|value| !value.is_empty());
            let model = row
                .values
                .get("resolved_model")
                .filter(|value| !value.is_empty())
                .or_else(|| row.values.get("model").filter(|value| !value.is_empty()));
            return match (provider, model) {
                (Some(provider), Some(model)) if model.starts_with(&format!("{provider}/")) => {
                    model.clone()
                }
                (Some(provider), Some(model)) => format!("{provider}/{model}"),
                (Some(provider), None) => provider.clone(),
                (None, Some(model)) => model.clone(),
                (None, None) => "(unknown)".to_string(),
            };
        }
        ReportGroupBy::Model => row
            .values
            .get("resolved_model")
            .filter(|model| !model.is_empty())
            .or_else(|| row.values.get("model")),
        ReportGroupBy::WorkUnit => row.values.get("work_unit_id"),
        ReportGroupBy::AgentWithinProject => {
            let project = row.values.get("project").filter(|value| !value.is_empty());
            let agent = row.values.get("agent").filter(|value| !value.is_empty());
            return match (project, agent) {
                (Some(project), Some(agent)) => format!("{project}/{agent}"),
                (Some(project), None) => project.clone(),
                (None, Some(agent)) => agent.clone(),
                (None, None) => "(unknown)".to_string(),
            };
        }
    };
    value
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn row_is_successful(row: &Row) -> bool {
    let status_success = row
        .values
        .get("status")
        .and_then(|status| status.parse::<u16>().ok())
        .is_some_and(|status| (200..300).contains(&status));
    let terminal_success = row
        .values
        .get("terminal_outcome")
        .is_none_or(|outcome| outcome.is_empty() || outcome == "completed");
    let refused = row
        .values
        .get("refusal_reason")
        .is_some_and(|reason| !reason.is_empty());
    status_success && terminal_success && !refused
}

fn cache_hit_rate(row: &GatewayReportRow) -> i64 {
    let observed = row.cache_accounted_calls;
    if observed == 0 {
        0
    } else {
        (row.cache_warm_reads.saturating_mul(100) / observed).clamp(0, 100)
    }
}

fn effective_cached_share(row: &GatewayReportRow) -> i64 {
    let eligible_input = row
        .uncached_input_tokens
        .saturating_add(row.cache_read_input_tokens)
        .saturating_add(row.cache_creation_input_tokens);
    if eligible_input == 0 {
        0
    } else {
        (row.cache_read_input_tokens.saturating_mul(100) / eligible_input).clamp(0, 100)
    }
}

fn print_report(group_by: ReportGroupBy, rows: &[GatewayReportRow]) {
    if group_by == ReportGroupBy::WorkUnit {
        print_work_unit_report(rows);
        return;
    }
    println!(
        "{:<24} {:>8} {:>10} {:>9} {:>9} {:>8} {:>9} {:>14} {:>14} {:>14} {:>14} {:>10} {:>10} {:>9} {:>10} {:>10} {:>14}",
        group_by.label(),
        "calls",
        "operations",
        "successes",
        "failures",
        "profiles",
        "capability",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "est_cost_usd",
        "cold_write",
        "warm_read",
        "misses",
        "hit_rate",
        "cached_share",
        "cache_saved_usd"
    );
    println!("{}", "-".repeat(126));
    for row in rows {
        println!(
            "{:<24} {:>8} {:>10} {:>9} {:>9} {:>8} {:>9} {:>14} {:>14} {:>14} {:>14} {:>10} {:>10} {:>9} {:>9}% {:>9}% {:>14}",
            truncate(&row.group, 24),
            row.calls,
            row.operations,
            row.successful_outcomes,
            row.terminal_failures,
            row.profile_versions.len(),
            row.capability_snapshots.len(),
            row.input_tokens,
            row.output_tokens,
            row.total_tokens,
            format_usd_micros(row.cost_usd_micros),
            row.cache_cold_writes,
            row.cache_warm_reads,
            row.cache_misses,
            cache_hit_rate(row),
            effective_cached_share(row),
            format_usd_micros(row.cache_savings_usd_micros)
        );
    }
}

fn print_work_unit_report(rows: &[GatewayReportRow]) {
    println!(
        "{:<24} {:>7} {:>9} {:>9} {:>12} {:>8} {:>8} {:>7} {:>8} {:>8} {:>9}  models",
        "work_unit",
        "calls",
        "refusals",
        "failures",
        "cost_usd",
        "cold",
        "warm",
        "misses",
        "hit_rate",
        "cached",
        "budget"
    );
    println!("{}", "-".repeat(144));
    for row in rows {
        let budget = if row.budget_limit > 0 {
            format!(
                "{}%",
                (row.budget_used.saturating_mul(100) / row.budget_limit).clamp(0, 999)
            )
        } else {
            "unlimited".to_string()
        };
        let models = row
            .models
            .iter()
            .map(|(model, calls)| format!("{model}({calls})"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<24} {:>7} {:>9} {:>9} {:>12} {:>8} {:>8} {:>7} {:>7}% {:>7}% {:>9}  {}",
            truncate(&row.group, 24),
            row.calls,
            row.refusals,
            row.terminal_failures,
            format_usd_micros(row.cost_usd_micros),
            row.cache_cold_writes,
            row.cache_warm_reads,
            row.cache_misses,
            cache_hit_rate(row),
            effective_cached_share(row),
            budget,
            models
        );
    }
}

pub fn render_dashboard(rows: &[Row], since_ms: i64) -> String {
    let by_project = summarize_rows(rows.to_vec(), ReportGroupBy::Project);
    let by_agent = summarize_rows(rows.to_vec(), ReportGroupBy::Agent);
    let by_provider = summarize_rows(rows.to_vec(), ReportGroupBy::Provider);
    let by_provider_model = summarize_rows(rows.to_vec(), ReportGroupBy::ProviderModel);
    let by_model = summarize_rows(rows.to_vec(), ReportGroupBy::Model);
    let by_work_unit = summarize_rows(rows.to_vec(), ReportGroupBy::WorkUnit);
    let by_agent_within_project = summarize_rows(rows.to_vec(), ReportGroupBy::AgentWithinProject);
    let totals = rows
        .iter()
        .fold(GatewayReportRow::default(), |mut total, row| {
            total.calls += 1;
            if row_is_successful(row) {
                total.successful_outcomes += 1;
            }
            total.input_tokens += parse_i64(row.values.get("input_tokens"));
            let cache_reads = parse_i64(row.values.get("cache_read_input_tokens"));
            total.uncached_input_tokens += row
                .values
                .get("uncached_input_tokens")
                .map(|value| parse_i64(Some(value)))
                .unwrap_or_else(|| legacy_uncached_input(row, cache_reads));
            total.output_tokens += parse_i64(row.values.get("output_tokens"));
            total.total_tokens += parse_i64(row.values.get("total_tokens"));
            total.cost_usd_micros += parse_i64(row.values.get("cost_usd_micros"));
            total.cache_read_input_tokens += parse_i64(row.values.get("cache_read_input_tokens"));
            let cache_writes = parse_i64(row.values.get("cache_creation_input_tokens"));
            total.cache_creation_input_tokens += cache_writes;
            total.cache_warm_reads += i64::from(cache_reads > 0);
            total.cache_cold_writes += i64::from(cache_writes > 0);
            let cache_requested = row
                .values
                .get("cache_requested")
                .is_some_and(|value| value == "true");
            let accounting_reported = row.values.contains_key("cache_read_input_tokens")
                || row.values.contains_key("cache_creation_input_tokens");
            let cache_accounted =
                cache_reads > 0 || cache_writes > 0 || (cache_requested && accounting_reported);
            total.cache_accounted_calls += i64::from(cache_accounted);
            total.cache_misses += i64::from(
                cache_requested && accounting_reported && cache_reads == 0 && cache_writes == 0,
            );
            total.cache_unaccounted_attempts += i64::from(cache_requested && !accounting_reported);
            total.cache_savings_usd_micros += parse_i64(row.values.get("cache_savings_usd_micros"));
            if row
                .values
                .get("terminal_outcome")
                .is_some_and(|outcome| !outcome.is_empty() && outcome != "completed")
            {
                total.terminal_failures += 1;
            }
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
{provider}
{provider_model}
{model}
{work_unit}
{agent_within_project}
</main>
</body>
</html>
"#,
        since = html_escape(&since_ms.to_string()),
        metrics = render_metric_cards(&totals),
        project = render_section("By Project", "project", &by_project),
        agent = render_section("By Agent", "agent", &by_agent),
        provider = render_section("By Provider", "provider", &by_provider),
        provider_model = render_section(
            "By Provider and Model",
            "provider/model",
            &by_provider_model
        ),
        model = render_section("By Model", "model", &by_model),
        work_unit = render_section("By Work Unit", "work_unit", &by_work_unit),
        agent_within_project = render_section(
            "By Agent (within project)",
            "agent/project",
            &by_agent_within_project
        ),
    )
}

fn render_metric_cards(total: &GatewayReportRow) -> String {
    [
        ("Calls", total.calls.to_string()),
        ("Successful outcomes", total.successful_outcomes.to_string()),
        ("Terminal failures", total.terminal_failures.to_string()),
        ("Input tokens", total.input_tokens.to_string()),
        ("Output tokens", total.output_tokens.to_string()),
        ("Total tokens", total.total_tokens.to_string()),
        (
            "Estimated cost",
            format!("${}", format_usd_micros(total.cost_usd_micros)),
        ),
        ("Cache reads", total.cache_read_input_tokens.to_string()),
        ("Cold writes", total.cache_cold_writes.to_string()),
        ("Warm reads", total.cache_warm_reads.to_string()),
        ("Cache misses", total.cache_misses.to_string()),
        (
            "Unaccounted cache attempts",
            total.cache_unaccounted_attempts.to_string(),
        ),
        ("Cache hit rate", format!("{}%", cache_hit_rate(total))),
        (
            "Effective cached share",
            format!("{}%", effective_cached_share(total)),
        ),
        (
            "Cache savings",
            format!("${}", format_usd_micros(total.cache_savings_usd_micros)),
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
                r#"<tr><td>{group}<span class="bar" style="width:{width}%"></span></td><td>{calls}</td><td>{operations}</td><td>{successes}</td><td>{failures}</td><td>{profiles}</td><td>{capability_snapshots}</td><td>{input}</td><td>{output}</td><td>{total}</td><td>${cost}</td><td>{cold_writes}</td><td>{warm_reads}</td><td>{misses}</td><td>{hit_rate}%</td><td>{cached_share}%</td><td>${cache_saved}</td></tr>"#,
                group = html_escape(&row.group),
                width = width,
                calls = row.calls,
                operations = row.operations,
                successes = row.successful_outcomes,
                failures = row.terminal_failures,
                profiles = row.profile_versions.len(),
                capability_snapshots = row.capability_snapshots.len(),
                input = row.input_tokens,
                output = row.output_tokens,
                total = row.total_tokens,
                cost = format_usd_micros(row.cost_usd_micros),
                cold_writes = row.cache_cold_writes,
                warm_reads = row.cache_warm_reads,
                misses = row.cache_misses,
                hit_rate = cache_hit_rate(row),
                cached_share = effective_cached_share(row),
                cache_saved = format_usd_micros(row.cache_savings_usd_micros)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<section>
<h2>{title}</h2>
<table>
<thead><tr><th>{first_column}</th><th>calls</th><th>operations</th><th>successful outcomes</th><th>terminal failures</th><th>profiles</th><th>capability snapshots</th><th>input tokens</th><th>output tokens</th><th>total tokens</th><th>est. cost</th><th>cold writes</th><th>warm reads</th><th>misses</th><th>hit rate</th><th>cached share</th><th>cache savings</th></tr></thead>
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

fn legacy_uncached_input(row: &Row, cache_reads: i64) -> i64 {
    let input = parse_i64(row.values.get("input_tokens"));
    let provider = row.values.get("provider").map(String::as_str);
    let separate_anthropic_shape = provider == Some("anthropic")
        || row.values.contains_key("cache_creation_input_tokens")
        || row.values.contains_key("cache_creation_5m_input_tokens")
        || row.values.contains_key("cache_creation_1h_input_tokens");
    if separate_anthropic_shape {
        input
    } else {
        input.saturating_sub(cache_reads)
    }
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
    "Usage: chisei-gateway report [--target <grpc-url>] [--by <project|agent|provider|provider-model|model|work-unit|agent-within-project>] [--since <30m|24h|7d>] [--limit <rows>] [--html <path>]".to_string()
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
    fn parses_work_unit_report_args() {
        let config =
            GatewayReportConfig::from_env_and_args(["--by".to_string(), "work-unit".to_string()])
                .unwrap();

        assert_eq!(config.group_by, ReportGroupBy::WorkUnit);
    }

    #[test]
    fn parses_agent_within_project_report_args() {
        let config = GatewayReportConfig::from_env_and_args([
            "--by".to_string(),
            "agent-within-project".to_string(),
        ])
        .unwrap();

        assert_eq!(config.group_by, ReportGroupBy::AgentWithinProject);
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
                    operations: 2,
                    input_tokens: 17,
                    uncached_input_tokens: 17,
                    output_tokens: 7,
                    total_tokens: 24,
                    cost_usd_micros: 31,
                    ..Default::default()
                },
                GatewayReportRow {
                    group: "claude-opus-4-8".to_string(),
                    calls: 1,
                    operations: 1,
                    input_tokens: 5,
                    uncached_input_tokens: 5,
                    output_tokens: 2,
                    total_tokens: 7,
                    cost_usd_micros: 21,
                    ..Default::default()
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
    fn summarize_rows_aggregates_cache_reads_and_savings() {
        let rows = vec![
            row([
                ("agent", "claude-code"),
                ("input_tokens", "10"),
                ("uncached_input_tokens", "10"),
                ("output_tokens", "5"),
                ("total_tokens", "15"),
                ("cost_usd_micros", "40"),
                ("cache_read_input_tokens", "100"),
                ("cache_creation_input_tokens", "0"),
                ("cache_savings_usd_micros", "270"),
            ]),
            row([
                ("agent", "claude-code"),
                ("input_tokens", "8"),
                ("uncached_input_tokens", "8"),
                ("output_tokens", "2"),
                ("total_tokens", "10"),
                ("cost_usd_micros", "20"),
                ("cache_read_input_tokens", "50"),
                ("cache_creation_input_tokens", "0"),
                ("cache_savings_usd_micros", "130"),
            ]),
            // A row without cache tokens contributes zero to the cache columns.
            row([
                ("agent", "claude-code"),
                ("input_tokens", "4"),
                ("output_tokens", "1"),
                ("total_tokens", "5"),
                ("cost_usd_micros", "12"),
            ]),
        ];
        let report = summarize_rows(rows, ReportGroupBy::Agent);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].cache_warm_reads, 2);
        assert_eq!(report[0].cache_cold_writes, 0);
        assert_eq!(report[0].cache_misses, 0);
        assert_eq!(report[0].cache_accounted_calls, 2);
        assert_eq!(cache_hit_rate(&report[0]), 100);
        assert_eq!(effective_cached_share(&report[0]), 87);
        assert_eq!(report[0].calls, 3);
        assert_eq!(report[0].cache_read_input_tokens, 150);
        assert_eq!(report[0].cache_savings_usd_micros, 400);
    }

    #[test]
    fn zero_accounting_is_a_miss_only_for_an_explicit_cache_attempt() {
        let report = summarize_rows(
            vec![
                row([
                    ("agent", "attempted"),
                    ("cache_requested", "true"),
                    ("cache_read_input_tokens", "0"),
                    ("cache_creation_input_tokens", "0"),
                ]),
                row([
                    ("agent", "ordinary"),
                    ("cache_read_input_tokens", "0"),
                    ("cache_creation_input_tokens", "0"),
                ]),
                row([("agent", "unaccounted"), ("cache_requested", "true")]),
            ],
            ReportGroupBy::Agent,
        );
        let attempted = report.iter().find(|row| row.group == "attempted").unwrap();
        let ordinary = report.iter().find(|row| row.group == "ordinary").unwrap();
        let unaccounted = report
            .iter()
            .find(|row| row.group == "unaccounted")
            .unwrap();
        assert_eq!(attempted.cache_misses, 1);
        assert_eq!(attempted.cache_accounted_calls, 1);
        assert_eq!(ordinary.cache_misses, 0);
        assert_eq!(ordinary.cache_accounted_calls, 0);
        assert_eq!(unaccounted.cache_misses, 0);
        assert_eq!(unaccounted.cache_accounted_calls, 0);
        assert_eq!(unaccounted.cache_unaccounted_attempts, 1);
    }

    #[test]
    fn legacy_uncached_input_respects_provider_usage_shapes() {
        let anthropic = row([
            ("provider", "anthropic"),
            ("input_tokens", "10"),
            ("cache_read_input_tokens", "100"),
        ]);
        let openai = row([
            ("provider", "openai"),
            ("input_tokens", "100"),
            ("cache_read_input_tokens", "80"),
        ]);
        assert_eq!(legacy_uncached_input(&anthropic, 100), 10);
        assert_eq!(legacy_uncached_input(&openai, 80), 20);
    }

    #[test]
    fn summarize_rows_by_work_unit() {
        let rows = vec![
            row([
                ("work_unit_id", "wu-a"),
                ("input_tokens", "10"),
                ("output_tokens", "5"),
                ("total_tokens", "15"),
                ("cost_usd_micros", "25"),
            ]),
            row([
                ("work_unit_id", "wu-b"),
                ("input_tokens", "7"),
                ("output_tokens", "3"),
                ("total_tokens", "10"),
                ("cost_usd_micros", "15"),
            ]),
            row([
                ("work_unit_id", "wu-a"),
                ("input_tokens", "8"),
                ("output_tokens", "3"),
                ("total_tokens", "11"),
                ("cost_usd_micros", "12"),
            ]),
        ];

        let report = summarize_rows(rows, ReportGroupBy::WorkUnit);
        assert_eq!(
            report,
            vec![
                GatewayReportRow {
                    group: "wu-a".to_string(),
                    calls: 2,
                    operations: 2,
                    input_tokens: 18,
                    uncached_input_tokens: 18,
                    output_tokens: 8,
                    total_tokens: 26,
                    cost_usd_micros: 37,
                    ..Default::default()
                },
                GatewayReportRow {
                    group: "wu-b".to_string(),
                    calls: 1,
                    operations: 1,
                    input_tokens: 7,
                    uncached_input_tokens: 7,
                    output_tokens: 3,
                    total_tokens: 10,
                    cost_usd_micros: 15,
                    ..Default::default()
                }
            ]
        );
    }

    #[test]
    fn work_unit_summary_includes_refusals_and_model_mix() {
        let rows = vec![
            row([
                ("work_unit_id", "feature-x"),
                ("resolved_model", "claude-sonnet"),
                ("status", "ok"),
            ]),
            row([
                ("work_unit_id", "feature-x"),
                ("model", "claude-haiku"),
                ("status", "refused"),
                ("refusal_reason", "budget"),
            ]),
            row([
                ("work_unit_id", "feature-x"),
                ("model", "gpt-5.5"),
                ("status", "200"),
                ("terminal_outcome", "interrupted"),
            ]),
        ];

        let report = summarize_rows(rows, ReportGroupBy::WorkUnit);
        assert_eq!(report[0].calls, 3);
        assert_eq!(report[0].refusals, 1);
        assert_eq!(report[0].terminal_failures, 1);
        assert_eq!(report[0].models["claude-sonnet"], 1);
        assert_eq!(report[0].models["claude-haiku"], 1);
        assert_eq!(report[0].models["gpt-5.5"], 1);
    }

    #[test]
    fn provider_concentration_tracks_success_cost_and_governed_dependencies() {
        let rows = vec![
            row([
                ("provider", "xai"),
                ("operation_id", "operation-1"),
                ("resolved_model", "xai/grok-4.5"),
                ("profile_version", "xai.grok-4.5/v1"),
                ("capability_snapshot_version", "registry-v3:state-7"),
                ("status", "200"),
                ("cost_usd_micros", "30"),
            ]),
            row([
                ("provider", "xai"),
                ("operation_id", "operation-1"),
                ("resolved_model", "xai/grok-4.5"),
                ("profile_version", "xai.grok-4.5/v1"),
                ("capability_snapshot_version", "registry-v3:state-8"),
                ("status", "200"),
                ("terminal_outcome", "failed"),
                ("cost_usd_micros", "20"),
            ]),
        ];

        let by_provider = summarize_rows(rows.clone(), ReportGroupBy::Provider);
        assert_eq!(by_provider[0].group, "xai");
        assert_eq!(by_provider[0].calls, 2);
        assert_eq!(by_provider[0].operations, 1);
        assert_eq!(by_provider[0].successful_outcomes, 1);
        assert_eq!(by_provider[0].terminal_failures, 1);
        assert_eq!(by_provider[0].cost_usd_micros, 50);
        assert_eq!(by_provider[0].profile_versions["xai.grok-4.5/v1"], 2);
        assert_eq!(by_provider[0].capability_snapshots.len(), 2);

        let by_model = summarize_rows(rows, ReportGroupBy::ProviderModel);
        assert_eq!(by_model[0].group, "xai/grok-4.5");
    }

    #[test]
    fn summarize_rows_by_agent_within_project() {
        let rows = vec![
            row([
                ("project", "sekai-chisei"),
                ("agent", "claude-code"),
                ("input_tokens", "9"),
                ("output_tokens", "2"),
                ("total_tokens", "11"),
                ("cost_usd_micros", "8"),
            ]),
            row([
                ("project", "sekai-chisei"),
                ("agent", "claude-code"),
                ("input_tokens", "7"),
                ("output_tokens", "1"),
                ("total_tokens", "8"),
                ("cost_usd_micros", "5"),
            ]),
            row([
                ("project", "sekai-chisei"),
                ("agent", "codex-app"),
                ("input_tokens", "5"),
                ("output_tokens", "2"),
                ("total_tokens", "7"),
                ("cost_usd_micros", "14"),
            ]),
        ];

        let report = summarize_rows(rows, ReportGroupBy::AgentWithinProject);
        assert_eq!(
            report,
            vec![
                GatewayReportRow {
                    group: "sekai-chisei/claude-code".to_string(),
                    calls: 2,
                    operations: 2,
                    input_tokens: 16,
                    uncached_input_tokens: 16,
                    output_tokens: 3,
                    total_tokens: 19,
                    cost_usd_micros: 13,
                    ..Default::default()
                },
                GatewayReportRow {
                    group: "sekai-chisei/codex-app".to_string(),
                    calls: 1,
                    operations: 1,
                    input_tokens: 5,
                    uncached_input_tokens: 5,
                    output_tokens: 2,
                    total_tokens: 7,
                    cost_usd_micros: 14,
                    ..Default::default()
                },
            ]
        );
    }

    #[test]
    fn dashboard_renders_all_groupings_and_escapes_values() {
        let html = render_dashboard(
            &[
                row([
                    ("project", "sekai-chisei"),
                    ("agent", "codex-app"),
                    ("work_unit_id", "wu-main"),
                    ("model", "gpt-5.5"),
                    ("input_tokens", "10"),
                    ("output_tokens", "5"),
                    ("total_tokens", "15"),
                    ("cost_usd_micros", "25"),
                    ("cache_read_input_tokens", "100"),
                    ("cache_creation_input_tokens", "25"),
                    ("cache_savings_usd_micros", "270"),
                ]),
                row([
                    ("project", "danger<&>"),
                    ("agent", "claude-code"),
                    ("work_unit_id", "wu-main"),
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
        assert!(html.contains("By Work Unit"));
        assert!(html.contains("By Agent (within project)"));
        assert!(html.contains("Estimated cost"));
        assert!(html.contains("$0.000040"));
        assert!(html.contains("codex-app"));
        assert!(html.contains("danger&lt;&amp;&gt;"));
        assert!(!html.contains("danger<&>"));
        // Cache reporting is surfaced.
        assert!(html.contains("Cache reads"));
        assert!(html.contains("Cold writes"));
        assert!(html.contains("Warm reads"));
        assert!(html.contains("Cache misses"));
        assert!(html.contains("Unaccounted cache attempts"));
        assert!(html.contains("Cache hit rate"));
        assert!(html.contains("Effective cached share"));
        assert!(html.contains("Cache savings"));
        assert!(html.contains("cold writes"));
        assert!(html.contains("warm reads"));
        // A partially cached call counts once in the denominator, so its
        // call-level hit rate is 100%, not 50%.
        assert!(html.contains("100%"));
        // Total cache savings across rows: $0.000270.
        assert!(html.contains("$0.000270"));
    }
}
