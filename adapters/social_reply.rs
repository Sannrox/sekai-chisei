//! Reference adapter: admit one social reply observation.
//!
//! Collection stays outside Sekai core. This adapter maps a bounded JSON
//! document into a `sekai.evidence/v1` draft for `social.reply`. Reply text is
//! untrusted remote data and must never be treated as instructions.

use crate::sdk::{ConformanceProfile, EvidenceDraft};
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub const EVIDENCE_TYPE: &str = "social.reply";
pub const SCHEMA_ID: &str = "adapter.social.reply";
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

const MAX_TEXT_BYTES: usize = 8 * 1024;
const OPTIONAL_METRICS: [&str; 5] = ["impressions", "likes", "replies", "reposts", "quotes"];

#[derive(Debug, Deserialize)]
pub struct ReplyDocument {
    pub reply_id: String,
    pub parent_post_id: String,
    pub author_reference: String,
    pub text: String,
    pub created_at: String,
    #[serde(default)]
    pub collected_at: Option<String>,
    #[serde(default)]
    pub public_metrics: Option<HashMap<String, i64>>,
    #[serde(default)]
    pub source_system: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

pub fn parse(input: &[u8]) -> Result<ReplyDocument, String> {
    serde_json::from_slice(input).map_err(|error| format!("invalid social reply document: {error}"))
}

pub fn translate(document: ReplyDocument) -> Result<EvidenceDraft, String> {
    let reply_id = require_nonempty(&document.reply_id, "reply_id")?;
    let parent_post_id = require_nonempty(&document.parent_post_id, "parent_post_id")?;
    let author_reference = require_nonempty(&document.author_reference, "author_reference")?;
    let text = document.text.trim().to_string();
    if text.is_empty() {
        return Err("text is required".into());
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!("text exceeds {MAX_TEXT_BYTES} bytes"));
    }
    let observed_at_ms = parse_timestamp(&document.created_at, "created_at")?;
    let collected_at_ms = match document.collected_at.as_deref() {
        Some(value) => parse_timestamp(value, "collected_at")?,
        None => observed_at_ms,
    };
    if collected_at_ms < observed_at_ms {
        return Err("collected_at must not precede created_at".into());
    }
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
            "generated social digests are not admissible; submit raw reply observations only"
                .into(),
        );
    }
    let public_metrics = normalize_optional_metrics(document.public_metrics.as_ref())?;

    let content = json!({
        "reply_id": reply_id,
        "parent_post_id": parent_post_id,
        "author_reference": author_reference,
        "text": text,
        "public_metrics": public_metrics,
        "collected_at_ms": collected_at_ms,
    });
    let mut provenance = HashMap::from([
        ("adapter".into(), "social_reply/v1".into()),
        ("delivery".into(), "document".into()),
        ("source_system".into(), source_system),
        ("reply_id".into(), reply_id.clone()),
        ("parent_post_id".into(), parent_post_id),
        ("content_trust".into(), "untrusted_remote_text".into()),
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
        source_record_id: reply_id,
        source_version: "1".into(),
        source_sequence: 1,
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

fn normalize_optional_metrics(
    metrics: Option<&HashMap<String, i64>>,
) -> Result<Map<String, Value>, String> {
    let Some(metrics) = metrics else {
        return Ok(Map::new());
    };
    let mut normalized = Map::new();
    for (key, value) in metrics {
        if !OPTIONAL_METRICS.contains(&key.as_str()) {
            return Err(format!("unknown public_metrics field {key:?}"));
        }
        if *value < 0 {
            return Err(format!("public_metrics.{key} must be non-negative"));
        }
        normalized.insert(key.clone(), json!(value));
    }
    Ok(normalized)
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
