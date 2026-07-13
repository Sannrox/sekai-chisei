use crate::sdk::EvidenceDraft;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub const EVIDENCE_TYPE: &str = "operations.health_snapshot";
pub const SCHEMA_ID: &str = "adapter.http.health_snapshot";
pub const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Deserialize)]
pub struct HealthSnapshot {
    pub status: String,
    pub observed_at: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub checks: Map<String, Value>,
}

pub fn translate(
    payload: HealthSnapshot,
    source_record_id: &str,
    response_version: Option<&str>,
    ttl_ms: i64,
) -> Result<EvidenceDraft, String> {
    if source_record_id.trim().is_empty() {
        return Err("health source record id is required".into());
    }
    if payload.status.trim().is_empty() {
        return Err("health status is required".into());
    }
    if ttl_ms <= 0 {
        return Err("health evidence TTL must be positive".into());
    }
    let observed_at_ms = DateTime::parse_from_rfc3339(&payload.observed_at)
        .map(|value| value.timestamp_millis())
        .map_err(|_| "health observed_at is invalid".to_string())?;
    let source_version = response_version
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or(payload.version.clone())
        .unwrap_or_else(|| payload.observed_at.clone());
    Ok(EvidenceDraft {
        source_type: "http_health_endpoint".into(),
        source_record_id: source_record_id.trim().into(),
        source_version,
        source_sequence: observed_at_ms,
        evidence_type: EVIDENCE_TYPE.into(),
        signal: "operational_health".into(),
        schema_id: SCHEMA_ID.into(),
        schema_version: SCHEMA_VERSION.into(),
        observed_at_ms,
        expires_at_ms: Some(observed_at_ms.saturating_add(ttl_ms)),
        content: json!({
            "status": payload.status,
            "checks": payload.checks,
            "reported_version": payload.version,
        }),
        relationships: vec![],
        confidence_bps: 9_000,
        provenance: HashMap::from([
            ("adapter".into(), "http_health_poll/v1".into()),
            ("delivery".into(), "poll".into()),
        ]),
        causality: None,
    })
}

pub fn parse(input: &[u8]) -> Result<HealthSnapshot, String> {
    serde_json::from_slice(input).map_err(|error| format!("invalid health payload: {error}"))
}
