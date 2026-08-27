//! sekaictl admin quality rule commands (#681).

use crate::chisei::data_quality::{self, PublishDataQualityRule};
use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin quality publish --namespace <ns> --rule-id <id> --dataset-id <id> --evaluator <digest_pin|completeness|row_count_bound> [--expected-digest <digest>] [--required-field <name> ...] [--min-rows <n>] [--max-rows <n>] [--baseline-digest <digest>] [--actor <principal>]\n  sekaictl admin quality evaluate --namespace <ns> --rule-id <id> [--rule-digest <digest>] [--actor <principal>]\n  sekaictl admin quality show --namespace <ns> --rule-id <id>\n  sekaictl admin quality list [--namespace <ns>]\n  sekaictl admin quality show-result --result-id <id>\n  sekaictl admin quality cancel --result-id <id> [--actor <principal>]\n  sekaictl admin quality restart --result-id <id> [--actor <principal>]"
}

pub async fn run_quality_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("publish") => publish(parse_publish(&args[1..])?).await,
        Some("evaluate") => evaluate(parse_evaluate(&args[1..])?).await,
        Some("show") => show_rule(parse_show(&args[1..])?).await,
        Some("list") => list_rules(parse_list(&args[1..])?).await,
        Some("show-result") => show_result(parse_result(&args[1..], "show-result")?).await,
        Some("cancel") => {
            mutate_result(parse_result(&args[1..], "cancel")?, MutateOp::Cancel).await
        }
        Some("restart") => {
            mutate_result(parse_result(&args[1..], "restart")?, MutateOp::Restart).await
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct PublishConfig {
    request: PublishDataQualityRule,
    actor: String,
}

struct EvaluateConfig {
    namespace: String,
    rule_id: String,
    rule_digest: Option<String>,
    actor: String,
}

struct ShowConfig {
    namespace: String,
    rule_id: String,
}

struct ResultConfig {
    result_id: String,
    actor: String,
}

enum MutateOp {
    Cancel,
    Restart,
}

async fn publish(config: PublishConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = data_quality::publish_rule(
        db.as_ref(),
        &config.actor,
        &config.request,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn evaluate(config: EvaluateConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = data_quality::evaluate_rule(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.rule_id,
        config.rule_digest.as_deref(),
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn show_rule(config: ShowConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = data_quality::show_rule(db.as_ref(), &config.namespace, &config.rule_id)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn list_rules(namespace: Option<String>) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let records = data_quality::list_rules(db.as_ref(), namespace.as_deref())
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

async fn show_result(config: ResultConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record =
        data_quality::show_result(db.as_ref(), &config.result_id).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn mutate_result(config: ResultConfig, op: MutateOp) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let now = Utc::now().timestamp_millis();
    let record = match op {
        MutateOp::Cancel => {
            data_quality::cancel_evaluation(db.as_ref(), &config.actor, &config.result_id, now)
        }
        MutateOp::Restart => {
            data_quality::restart_evaluation(db.as_ref(), &config.actor, &config.result_id, now)
        }
    }
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_publish(args: &[String]) -> Result<PublishConfig, String> {
    let mut namespace = None;
    let mut rule_id = None;
    let mut dataset_id = None;
    let mut evaluator = None;
    let mut expected_digest = None;
    let mut required_fields = Vec::new();
    let mut min_rows = None;
    let mut max_rows = None;
    let mut baseline_digest = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--rule-id" => {
                rule_id = Some(require_value(args, i, "--rule-id")?);
                i += 2;
            }
            "--dataset-id" => {
                dataset_id = Some(require_value(args, i, "--dataset-id")?);
                i += 2;
            }
            "--evaluator" => {
                evaluator = Some(require_value(args, i, "--evaluator")?);
                i += 2;
            }
            "--expected-digest" => {
                expected_digest = Some(require_value(args, i, "--expected-digest")?);
                i += 2;
            }
            "--required-field" => {
                required_fields.push(require_value(args, i, "--required-field")?);
                i += 2;
            }
            "--min-rows" => {
                min_rows = Some(
                    require_value(args, i, "--min-rows")?
                        .parse()
                        .map_err(|_| "--min-rows must be an integer".to_string())?,
                );
                i += 2;
            }
            "--max-rows" => {
                max_rows = Some(
                    require_value(args, i, "--max-rows")?
                        .parse()
                        .map_err(|_| "--max-rows must be an integer".to_string())?,
                );
                i += 2;
            }
            "--baseline-digest" => {
                baseline_digest = Some(require_value(args, i, "--baseline-digest")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown publish option {other}")),
        }
    }
    Ok(PublishConfig {
        request: PublishDataQualityRule {
            namespace: namespace.ok_or("--namespace is required")?,
            rule_id: rule_id.ok_or("--rule-id is required")?,
            dataset_id: dataset_id.ok_or("--dataset-id is required")?,
            evaluator: evaluator.ok_or("--evaluator is required")?,
            expected_digest,
            required_fields,
            min_rows,
            max_rows,
            baseline_digest,
        },
        actor,
    })
}

fn parse_evaluate(args: &[String]) -> Result<EvaluateConfig, String> {
    let mut namespace = None;
    let mut rule_id = None;
    let mut rule_digest = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--rule-id" => {
                rule_id = Some(require_value(args, i, "--rule-id")?);
                i += 2;
            }
            "--rule-digest" => {
                rule_digest = Some(require_value(args, i, "--rule-digest")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown evaluate option {other}")),
        }
    }
    Ok(EvaluateConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        rule_id: rule_id.ok_or("--rule-id is required")?,
        rule_digest,
        actor,
    })
}

fn parse_show(args: &[String]) -> Result<ShowConfig, String> {
    let mut namespace = None;
    let mut rule_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--rule-id" => {
                rule_id = Some(require_value(args, i, "--rule-id")?);
                i += 2;
            }
            other => return Err(format!("unknown show option {other}")),
        }
    }
    Ok(ShowConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        rule_id: rule_id.ok_or("--rule-id is required")?,
    })
}

fn parse_list(args: &[String]) -> Result<Option<String>, String> {
    let mut namespace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            other => return Err(format!("unknown list option {other}")),
        }
    }
    Ok(namespace)
}

fn parse_result(args: &[String], command: &str) -> Result<ResultConfig, String> {
    let mut result_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--result-id" => {
                result_id = Some(require_value(args, i, "--result-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown {command} option {other}")),
        }
    }
    Ok(ResultConfig {
        result_id: result_id.ok_or("--result-id is required")?,
        actor,
    })
}
