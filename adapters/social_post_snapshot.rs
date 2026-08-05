//! Reference adapter: admit one fixed-window social post metric snapshot.
//!
//! Collection stays outside Sekai core (manual export, scheduled poll, webhook
//! fan-in, or an external CLI). This adapter only maps a bounded JSON document
//! into a `sekai.evidence/v1` draft for `social.post_snapshot`.

use crate::sdk::{ConformanceProfile, EvidenceDraft};
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

pub const EVIDENCE_TYPE: &str = "social.post_snapshot";
pub const SCHEMA_ID: &str = "adapter.social.post_snapshot";
pub const SCHEMA_VERSION: &str = "1.0.0";
pub const CONFORMANCE_PROFILE: ConformanceProfile = ConformanceProfile {
    source_type: "social_observation_document",
    evidence_type: EVIDENCE_TYPE,
    signal: "other",
    schema_id: SCHEMA_ID,
    schema_version: SCHEMA_VERSION,
    delivery: "document",
    requires_expiry: false,
};

const REQUIRED_METRICS: [&str; 5] = ["impressions", "likes", "replies", "reposts", "quotes"];

#[derive(Debug, Deserialize)]
pub struct PostSnapshotDocument {
    pub post_id: String,
    pub window: String,
    pub observed_at: String,
    pub metrics: HashMap<String, i64>,
    #[serde(default)]
    pub source_system: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

pub fn parse(input: &[u8]) -> Result<PostSnapshotDocument, String> {
    serde_json::from_slice(input)
        .map_err(|error| format!("invalid social post snapshot document: {error}"))
}

pub fn translate(document: PostSnapshotDocument) -> Result<EvidenceDraft, String> {
    let post_id = require_nonempty(&document.post_id, "post_id")?;
    let window = normalize_window(&document.window)?;
    let observed_at_ms = parse_timestamp(&document.observed_at, "observed_at")?;
    let metrics = require_metrics(&document.metrics)?;
    let source_system = document
        .source_system
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("manual")
        .to_string();
    if source_system.eq_ignore_ascii_case("birdclaw_digest")
        || source_system.eq_ignore_ascii_case("generated_digest")
    {
        return Err(
            "generated social digests are not admissible; submit raw window metrics only".into(),
        );
    }

    let content = json!({
        "post_id": post_id,
        "window": window,
        "metrics": metrics,
    });
    let source_sequence = match window {
        "24h" => 1,
        "7d" => 2,
        _ => unreachable!("normalize_window restricts windows"),
    };
    let mut provenance = HashMap::from([
        ("adapter".into(), "social_post_snapshot/v1".into()),
        ("delivery".into(), "document".into()),
        ("source_system".into(), source_system),
        ("window".into(), window.to_string()),
        ("post_id".into(), post_id.clone()),
    ]);
    if let Some(account) = document
        .account
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        provenance.insert("account".into(), account.to_string());
    }

    let draft = EvidenceDraft {
        source_type: "social_observation_document".into(),
        source_record_id: post_id,
        source_version: format!("{window}-complete-v1"),
        source_sequence,
        evidence_type: EVIDENCE_TYPE.into(),
        signal: "other".into(),
        schema_id: SCHEMA_ID.into(),
        schema_version: SCHEMA_VERSION.into(),
        observed_at_ms,
        expires_at_ms: None,
        content,
        relationships: vec![],
        confidence_bps: 10_000,
        provenance,
        causality: None,
    };
    CONFORMANCE_PROFILE.validate(&draft)?;
    Ok(draft)
}

fn normalize_window(window: &str) -> Result<&'static str, String> {
    match window.trim() {
        "24h" => Ok("24h"),
        "7d" => Ok("7d"),
        other => Err(format!("window must be 24h or 7d, got {other:?}")),
    }
}

fn require_metrics(metrics: &HashMap<String, i64>) -> Result<Value, String> {
    let mut normalized = serde_json::Map::new();
    for field in REQUIRED_METRICS {
        let value = metrics
            .get(field)
            .copied()
            .ok_or_else(|| format!("metrics.{field} is required"))?;
        if value < 0 {
            return Err(format!("metrics.{field} must be non-negative"));
        }
        normalized.insert(field.to_string(), json!(value));
    }
    for key in metrics.keys() {
        if !REQUIRED_METRICS.contains(&key.as_str()) {
            return Err(format!("unknown metrics field {key:?}"));
        }
    }
    Ok(Value::Object(normalized))
}

fn require_nonempty(value: &str, field: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} is required"));
    }
    Ok(trimmed.to_string())
}

fn parse_timestamp(value: &str, field: &str) -> Result<i64, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_millis())
        .map_err(|error| format!("invalid {field} timestamp: {error}"))
}
