//! `sekaictl admin governance budget` CLI: read budget usage and remaining
//! limit for a scope through `GetBudgetUsage`, and set or clear a scope's
//! work-unit default through `SetBudgetWorkUnitDefault`.
//!
//! Connects to the sekai control plane (via `CHISEI_GRPC_URL` or `SEKAI_SOCKET`,
//! defaulting to the local UDS). The scope flags mirror `SetBudgetLimit`.

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    GetBudgetUsageRequest, GetBudgetUsageResponse, SetBudgetWorkUnitDefaultRequest,
};
use serde_json::json;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin governance budget usage [--subject <scope>] [--project <p>] [--agent <a>] [--work-unit <w>] [--key-id <k>] [--user <u>] [--json]
sekaictl admin governance budget work-unit-default [--subject <scope>] [--project <p>] [--agent <a>] [--key-id <k>] [--user <u>] [--metric tokens|requests] (--max <n> [--period daily|weekly|monthly] | --clear)"
}

fn target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string())
}

pub async fn run_budget_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("usage") => {
            let (request, as_json) = parse_usage(&args[1..]).map_err(std::io::Error::other)?;
            let response = ChiseiServiceClient::new(connect_sekai(&target()).await?)
                .get_budget_usage(request)
                .await?
                .into_inner();
            print!("{}", render_usage(&response, as_json));
            Ok(())
        }
        Some("work-unit-default") => {
            let request = parse_work_unit_default(&args[1..]).map_err(std::io::Error::other)?;
            let clear = request.clear;
            ChiseiServiceClient::new(connect_sekai(&target()).await?)
                .set_budget_work_unit_default(request)
                .await?;
            println!(
                "{}",
                if clear {
                    "work-unit default cleared"
                } else {
                    "work-unit default set"
                }
            );
            Ok(())
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn parse_usage(args: &[String]) -> Result<(GetBudgetUsageRequest, bool), String> {
    let mut request = GetBudgetUsageRequest::default();
    let mut as_json = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let field = match arg.as_str() {
            "--json" => {
                as_json = true;
                continue;
            }
            "--subject" => &mut request.subject,
            "--project" => &mut request.project,
            "--agent" => &mut request.agent,
            "--work-unit" => &mut request.work_unit,
            "--key-id" => &mut request.key_id,
            "--user" => &mut request.user_id,
            _ => return Err(format!("unknown budget option {arg:?}\n{}", usage())),
        };
        *field = args
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{arg} requires a value"))?
            .clone();
    }
    Ok((request, as_json))
}

/// Parses `work-unit-default`: the scope flags of `usage` without
/// `--work-unit`, and either `--max` or `--clear`.
fn parse_work_unit_default(args: &[String]) -> Result<SetBudgetWorkUnitDefaultRequest, String> {
    let mut request = SetBudgetWorkUnitDefaultRequest::default();
    let mut max = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--clear" {
            request.clear = true;
            continue;
        }
        let value = args
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{arg} requires a value"))?
            .clone();
        match arg.as_str() {
            "--subject" => request.subject = value,
            "--project" => request.project = value,
            "--agent" => request.agent = value,
            "--key-id" => request.key_id = value,
            "--user" => request.user_id = value,
            "--metric" => request.metric = value,
            "--period" => request.period_type = value,
            "--max" => {
                max = Some(
                    value
                        .parse::<i32>()
                        .ok()
                        .filter(|max| *max >= 0)
                        .ok_or_else(|| format!("--max must be a non-negative integer: {value}"))?,
                )
            }
            _ => return Err(format!("unknown budget option {arg:?}\n{}", usage())),
        }
    }
    match (max, request.clear) {
        (Some(max), false) => request.max_amount = max,
        (None, true) => {}
        _ => return Err(format!("set exactly one of --max and --clear\n{}", usage())),
    }
    Ok(request)
}

/// Renders one row per scope level and metric. An unlimited level shows
/// `unlimited` for its limit and remainder.
pub fn render_usage(response: &GetBudgetUsageResponse, as_json: bool) -> String {
    if as_json {
        let levels = response
            .levels
            .iter()
            .map(|level| {
                json!({
                    "scope_id": level.scope_id,
                    "metric": level.metric,
                    "period_type": level.period_type,
                    "period_start": level.period_start,
                    "used": level.used,
                    "limit": (!level.unlimited).then_some(level.limit),
                    "remaining": (!level.unlimited).then_some(level.remaining),
                    "from_work_unit_default": level.from_work_unit_default,
                })
            })
            .collect::<Vec<_>>();
        let mut output = serde_json::to_string_pretty(&json!({
            "scope_id": response.scope_id,
            "levels": levels,
        }))
        .expect("budget usage is serializable");
        output.push('\n');
        return output;
    }
    let mut output = "SCOPE\tMETRIC\tPERIOD\tUSED\tLIMIT\tREMAINING\n".to_string();
    for level in &response.levels {
        let (limit, remaining) = if level.unlimited {
            ("unlimited".to_string(), "unlimited".to_string())
        } else {
            (level.limit.to_string(), level.remaining.to_string())
        };
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{limit}\t{remaining}\n",
            level.scope_id, level.metric, level.period_type, level.used
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::chisei::BudgetScopeUsage;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_scope_flags_like_set_budget_limit() {
        let (request, as_json) = parse_usage(&args(&[
            "--project",
            "p",
            "--agent",
            "a",
            "--work-unit",
            "w",
            "--json",
        ]))
        .unwrap();
        assert!(as_json);
        assert_eq!(
            (
                request.project.as_str(),
                request.agent.as_str(),
                request.work_unit.as_str()
            ),
            ("p", "a", "w")
        );
        assert!(parse_usage(&args(&["--subject"])).is_err());
        assert!(parse_usage(&args(&["--period", "daily"])).is_err());
    }

    #[test]
    fn work_unit_default_takes_either_a_max_or_clear() {
        let request = parse_work_unit_default(&args(&[
            "--project",
            "p",
            "--agent",
            "a",
            "--metric",
            "requests",
            "--max",
            "6",
        ]))
        .unwrap();
        assert_eq!(
            (
                request.agent.as_str(),
                request.metric.as_str(),
                request.max_amount,
                request.clear
            ),
            ("a", "requests", 6, false)
        );
        assert!(
            parse_work_unit_default(&args(&["--agent", "a", "--clear"]))
                .unwrap()
                .clear
        );
        for invalid in [
            &["--agent", "a"][..],
            &["--agent", "a", "--max", "6", "--clear"],
            &["--agent", "a", "--max", "-1"],
            &["--work-unit", "w", "--max", "6"],
        ] {
            assert!(
                parse_work_unit_default(&args(invalid)).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn renders_unlimited_levels_as_unlimited_and_null() {
        let response = GetBudgetUsageResponse {
            scope_id: "agent:a".into(),
            levels: vec![
                BudgetScopeUsage {
                    scope_id: "global".into(),
                    metric: "tokens".into(),
                    period_type: "daily".into(),
                    used: 3,
                    unlimited: true,
                    ..Default::default()
                },
                BudgetScopeUsage {
                    scope_id: "agent:a".into(),
                    metric: "tokens".into(),
                    period_type: "weekly".into(),
                    used: 3,
                    limit: 10,
                    remaining: 7,
                    ..Default::default()
                },
            ],
        };
        let table = render_usage(&response, false);
        assert!(table.contains("global\ttokens\tdaily\t3\tunlimited\tunlimited\n"));
        assert!(table.contains("agent:a\ttokens\tweekly\t3\t10\t7\n"));
        let parsed: serde_json::Value =
            serde_json::from_str(&render_usage(&response, true)).unwrap();
        assert_eq!(parsed["levels"][0]["limit"], serde_json::Value::Null);
        assert_eq!(parsed["levels"][1]["remaining"], 7);
    }
}
