use crate::chisei::receipt::OperationReceipt;
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::operation_report::OperationReport;
use crate::weekly_report::TeamWeeklyReport;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl team weekly-report <report.json>... --namespace <name> --since-ms <time> --until-ms <time> --output <file>"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyReportConfig {
    pub namespace: String,
    pub since_ms: i64,
    pub until_ms: i64,
    pub output: PathBuf,
    pub inputs: Vec<PathBuf>,
}

impl WeeklyReportConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut namespace = None;
        let mut since_ms = None;
        let mut until_ms = None;
        let mut output = None;
        let mut inputs = Vec::new();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--namespace" => namespace = Some(value(&args, &mut index, "--namespace")?),
                "--since-ms" => {
                    since_ms = Some(
                        value(&args, &mut index, "--since-ms")?
                            .parse::<i64>()
                            .map_err(|_| "--since-ms must be an integer".to_string())?,
                    )
                }
                "--until-ms" => {
                    until_ms = Some(
                        value(&args, &mut index, "--until-ms")?
                            .parse::<i64>()
                            .map_err(|_| "--until-ms must be an integer".to_string())?,
                    )
                }
                "--output" => output = Some(PathBuf::from(value(&args, &mut index, "--output")?)),
                flag if flag.starts_with('-') => return Err(format!("unknown option {flag:?}")),
                path => inputs.push(PathBuf::from(path)),
            }
            index += 1;
        }
        if inputs.is_empty() {
            return Err("at least one authorized operation report is required".into());
        }
        let config = Self {
            namespace: namespace.ok_or_else(|| "--namespace is required".to_string())?,
            since_ms: since_ms.ok_or_else(|| "--since-ms is required".to_string())?,
            until_ms: until_ms.ok_or_else(|| "--until-ms is required".to_string())?,
            output: output.ok_or_else(|| "--output is required".to_string())?,
            inputs,
        };
        if config.namespace.trim().is_empty() || config.namespace.trim() != config.namespace {
            return Err(
                "--namespace must be canonical and must not contain surrounding whitespace".into(),
            );
        }
        if config.since_ms >= config.until_ms {
            return Err("--since-ms must be earlier than --until-ms".into());
        }
        Ok(config)
    }
}

fn value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .filter(|value| !value.starts_with('-'))
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

pub async fn run_weekly_report(config: WeeklyReportConfig) -> Result<TeamWeeklyReport, BoxErr> {
    let selectors = config
        .inputs
        .iter()
        .map(|path| -> Result<OperationReport, BoxErr> {
            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|report| {
            report_matches_scope(report, &config.namespace, config.since_ms, config.until_ms)
        })
        .collect::<Vec<_>>();
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let mut client = ChiseiServiceClient::new(connect_sekai(&target).await?);
    let mut reports = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let receipt_json = client
            .get_operation_receipt(GetOperationReceiptRequest {
                operation_id: selector.operation_id.clone(),
                request_id: String::new(),
                caller_scope: String::new(),
                attempt: 0,
            })
            .await?
            .into_inner()
            .receipt_json;
        let receipt: OperationReceipt = serde_json::from_str(&receipt_json)?;
        let canonical = OperationReport::from_authorized_receipt(&receipt);
        if selector != canonical {
            return Err(std::io::Error::other(format!(
                "operation report {:?} does not match its authorized control-plane projection",
                canonical.operation_id
            ))
            .into());
        }
        reports.push(selector);
    }
    let weekly = TeamWeeklyReport::from_reports(
        &reports,
        &config.namespace,
        config.since_ms,
        config.until_ms,
        chrono::Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    let json = serde_json::to_string_pretty(&weekly)?;
    write_atomically(&config.output, format!("{json}\n").as_bytes())?;
    Ok(weekly)
}

fn report_matches_scope(
    report: &OperationReport,
    namespace: &str,
    since_ms: i64,
    until_ms: i64,
) -> bool {
    scope_matches(
        &report.namespace,
        report.started_at_ms,
        namespace,
        since_ms,
        until_ms,
    )
}

fn scope_matches(
    report_namespace: &str,
    started_at_ms: i64,
    namespace: &str,
    since_ms: i64,
    until_ms: i64,
) -> bool {
    report_namespace == namespace && started_at_ms >= since_ms && started_at_ms < until_ms
}

fn write_atomically(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(not(unix))]
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic weekly report replacement is unsupported on this platform",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("weekly-report");
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_scheduled_report_inputs() {
        let config = WeeklyReportConfig::from_args([
            "one.json".into(),
            "two.json".into(),
            "--namespace".into(),
            "acme".into(),
            "--since-ms".into(),
            "100".into(),
            "--until-ms".into(),
            "200".into(),
            "--output".into(),
            "weekly.json".into(),
        ])
        .unwrap();
        assert_eq!(config.inputs.len(), 2);
        assert_eq!(config.namespace, "acme");
        assert_eq!(config.output, PathBuf::from("weekly.json"));
    }

    #[test]
    fn parser_rejects_ambiguous_or_incomplete_windows() {
        for args in [
            vec!["input.json", "--namespace", "acme"],
            vec![
                "input.json",
                "--namespace",
                " acme ",
                "--since-ms",
                "1",
                "--until-ms",
                "2",
                "--output",
                "out.json",
            ],
            vec![
                "input.json",
                "--namespace",
                "acme",
                "--since-ms",
                "2",
                "--until-ms",
                "1",
                "--output",
                "out.json",
            ],
            vec![
                "input.json",
                "--namespace",
                "acme",
                "--since-ms",
                "1",
                "--until-ms",
                "2",
                "--output",
                "out.json",
                "--unknown",
            ],
        ] {
            assert!(WeeklyReportConfig::from_args(args.into_iter().map(str::to_string)).is_err());
        }
    }

    #[test]
    fn report_scope_uses_namespace_and_a_half_open_window() {
        assert!(scope_matches("acme", 100, "acme", 100, 200));
        assert!(!scope_matches("other", 100, "acme", 100, 200));
        assert!(!scope_matches("acme", 200, "acme", 100, 200));
    }

    #[test]
    fn atomic_writer_replaces_a_complete_artifact() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-weekly-report-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("weekly.json");
        std::fs::write(&output, b"old").unwrap();
        let replacement = write_atomically(&output, br#"{"version":"new"}"#);
        #[cfg(unix)]
        replacement.unwrap();
        #[cfg(not(unix))]
        assert_eq!(
            replacement.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            r#"{"version":"new"}"#
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
