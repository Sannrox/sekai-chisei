use crate::sdk::EvidenceDraft;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const EVIDENCE_TYPE: &str = "source_control.check_run";
pub const SCHEMA_ID: &str = "adapter.github.check_run";
pub const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Deserialize)]
pub struct CheckRunWebhook {
    pub action: String,
    pub check_run: CheckRun,
    pub repository: Repository,
}

#[derive(Debug, Deserialize)]
pub struct CheckRun {
    pub id: u64,
    pub status: String,
    pub conclusion: Option<String>,
    pub head_sha: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub updated_at: String,
    pub html_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub full_name: String,
}

pub fn translate(payload: CheckRunWebhook) -> Result<EvidenceDraft, String> {
    let observed_at_ms = parse_timestamp(
        payload
            .check_run
            .completed_at
            .as_deref()
            .unwrap_or(&payload.check_run.updated_at),
    )?;
    let updated_at_ms = parse_timestamp(&payload.check_run.updated_at)?;
    let outcome = payload
        .check_run
        .conclusion
        .clone()
        .unwrap_or_else(|| payload.check_run.status.clone());
    let content = json!({
        "action": payload.action,
        "status": payload.check_run.status,
        "outcome": outcome,
        "head_sha": payload.check_run.head_sha,
        "repository": payload.repository.full_name,
        "started_at": payload.check_run.started_at,
        "completed_at": payload.check_run.completed_at,
        "details_url": payload.check_run.html_url,
    });
    let content_fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&content).map_err(|error| error.to_string())?)
    );
    let check_run_id = payload.check_run.id.to_string();
    Ok(EvidenceDraft {
        source_type: "github_check_run".into(),
        // GitHub check_run timestamps are not a strict event sequence. Treat each
        // distinct payload as an immutable observation instead of claiming that
        // same-second updates are ordered versions of one record.
        source_record_id: format!("{check_run_id}:{content_fingerprint}"),
        source_version: payload.check_run.updated_at,
        source_sequence: updated_at_ms,
        evidence_type: EVIDENCE_TYPE.into(),
        signal: "verification".into(),
        schema_id: SCHEMA_ID.into(),
        schema_version: SCHEMA_VERSION.into(),
        observed_at_ms,
        expires_at_ms: None,
        content,
        relationships: vec![],
        confidence_bps: if payload.check_run.conclusion.is_some() {
            9_500
        } else {
            7_000
        },
        provenance: HashMap::from([
            ("adapter".into(), "github_check_webhook/v1".into()),
            ("delivery".into(), "webhook".into()),
            ("check_run_id".into(), check_run_id),
        ]),
        causality: None,
    })
}

pub fn parse(input: &[u8]) -> Result<CheckRunWebhook, String> {
    serde_json::from_slice::<Value>(input)
        .and_then(serde_json::from_value)
        .map_err(|error| format!("invalid GitHub check_run payload: {error}"))
}

fn parse_timestamp(value: &str) -> Result<i64, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.timestamp_millis())
        .map_err(|_| "GitHub check_run timestamp is invalid".into())
}
