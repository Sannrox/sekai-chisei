//! `sekaictl admin assurance audit export` (#2638): page a namespace's audit
//! decisions into a JSON-lines file through `ExportNamespaceAudit`.
//!
//! Each page is appended as its record lines followed by one checkpoint line
//! holding the next cursor, written and synced together. Rerunning the same
//! command resumes from the last complete checkpoint and drops any torn tail
//! after it, so a crash leaves no gap and no duplicate.

use sekai_admin_client::client::connect_sekai;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{ExportNamespaceAuditRequest, ExportNamespaceAuditResponse};
use serde_json::{Value, json};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin assurance audit export --namespace <ns> --output <file.jsonl> [--page-size <n>]\n  \
     Appends records and a checkpoint per page; rerun the same command to resume."
}

pub async fn run_audit_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => export(parse_export(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExportConfig {
    namespace: String,
    output: PathBuf,
    page_size: u32,
}

fn parse_export(args: &[String]) -> Result<ExportConfig, BoxErr> {
    let mut namespace = None;
    let mut output = None;
    let mut page_size = 0;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| std::io::Error::other(format!("{arg} needs a value")))
        };
        match arg.as_str() {
            "--namespace" => namespace = Some(value()?),
            "--output" => output = Some(PathBuf::from(value()?)),
            "--page-size" => page_size = value()?.parse()?,
            _ => return Err(std::io::Error::other(usage()).into()),
        }
    }
    match (namespace, output) {
        (Some(namespace), Some(output)) => Ok(ExportConfig {
            namespace,
            output,
            page_size,
        }),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn export(config: ExportConfig) -> Result<(), BoxErr> {
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let mut client = SekaiServiceClient::new(connect_sekai(&target).await?);
    let mut cursor = resume(&config.output, &config.namespace)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.output)?;
    let mut total = 0usize;
    loop {
        let page = client
            .export_namespace_audit(ExportNamespaceAuditRequest {
                namespace: config.namespace.clone(),
                cursor: cursor.clone(),
                page_size: config.page_size,
            })
            .await?
            .into_inner();
        if page.archived_through_seq > 0 {
            eprintln!(
                "decisions through seq {} were archived by retention before export",
                page.archived_through_seq
            );
        }
        file.write_all(page_lines(&config.namespace, &page)?.as_bytes())?;
        file.sync_data()?;
        total += page.records.len();
        cursor = page.next_cursor;
        if page.caught_up {
            break;
        }
    }
    println!(
        "exported {} records={total} cursor={cursor}",
        config.output.display()
    );
    Ok(())
}

/// One page as JSON lines: its records, then its checkpoint.
fn page_lines(namespace: &str, page: &ExportNamespaceAuditResponse) -> Result<String, BoxErr> {
    let mut lines = String::new();
    for record in &page.records {
        lines.push_str(&serde_json::to_string(&json!({
            "kind": "record",
            "seq": record.seq,
            "prev_hash": record.prev_hash,
            "entry_hash": record.entry_hash,
            "id": record.id,
            "timestamp": record.timestamp,
            "actor": record.actor,
            "action": record.action,
            "reason": record.reason,
            "evidence_json": record.evidence_json,
            "target_id": record.target_id,
            "outcome": record.outcome,
        }))?);
        lines.push('\n');
    }
    lines.push_str(&serde_json::to_string(&json!({
        "kind": "checkpoint",
        "namespace": namespace,
        "next_cursor": page.next_cursor,
        "archived_through_seq": page.archived_through_seq,
        "verified_from_seq": page.verified_from_seq,
        "verified_from_hash": page.verified_from_hash,
        "verified_through_seq": page.verified_through_seq,
        "verified_through_hash": page.verified_through_hash,
    }))?);
    lines.push('\n');
    Ok(lines)
}

/// The cursor of the last complete checkpoint in `path`, truncating any
/// record lines written after it. A missing or empty file starts fresh.
fn resume(path: &Path, namespace: &str) -> Result<String, BoxErr> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let mut kept = 0usize;
    let mut cursor = String::new();
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        offset += line.len();
        if !line.ends_with('\n') {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            break;
        };
        if value["kind"] == "checkpoint" {
            if value["namespace"] != namespace {
                return Err(std::io::Error::other(format!(
                    "{} holds an export of another namespace",
                    path.display()
                ))
                .into());
            }
            cursor = value["next_cursor"].as_str().unwrap_or_default().into();
            kept = offset;
        }
    }
    if kept < text.len() {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(kept as u64)?;
        file.seek(std::io::SeekFrom::End(0))?;
        file.sync_data()?;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "audit-export-{}-{}-{name}.jsonl",
            std::process::id(),
            uuid::Uuid::new_v4().as_simple()
        ))
    }

    #[test]
    fn resume_drops_a_torn_page_after_the_last_checkpoint() {
        let path = temp_path("resume");
        let checkpoint = r#"{"kind":"checkpoint","namespace":"acme","next_cursor":"a1.4."}"#;
        std::fs::write(
            &path,
            format!(
                "{{\"kind\":\"record\",\"seq\":4}}\n{checkpoint}\n{{\"kind\":\"record\",\"seq\":6}}\n{{\"kind\":\"rec"
            ),
        )
        .unwrap();
        assert_eq!(resume(&path, "acme").unwrap(), "a1.4.");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{{\"kind\":\"record\",\"seq\":4}}\n{checkpoint}\n")
        );
        assert!(resume(&path, "other").is_err());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(resume(&path, "acme").unwrap(), "");
    }

    #[test]
    fn parses_export_flags() {
        let args: Vec<String> = [
            "--namespace",
            "acme",
            "--output",
            "out.jsonl",
            "--page-size",
            "5",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            parse_export(&args).unwrap(),
            ExportConfig {
                namespace: "acme".into(),
                output: "out.jsonl".into(),
                page_size: 5,
            }
        );
        assert!(parse_export(&args[..2]).is_err());
    }
}
