//! Durable, generation-fenced continuation records for parked runtime work.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RESOLVE_PARKED_WORK_ACTION: &str = "resolve_parked_work/v1";
pub const MAX_CONTINUATION_JSON_BYTES: usize = 64 * 1024;
pub const MAX_REASON_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionWorkPark {
    pub park_id: String,
    pub effect_id: String,
    pub namespace: String,
    pub operation_id: String,
    pub park_generation: u64,
    pub claim_generation: u64,
    pub checkpoint_ref: String,
    pub checkpoint_digest: String,
    pub reason: String,
    pub parked_by: String,
    pub parked_at_ms: i64,
    pub request_id: String,
    pub request_digest: String,
    pub checkpoint_store_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedWorkResolutionInput {
    pub resolution_input_id: String,
    pub effect_id: String,
    pub park_generation: u64,
    pub input_json: String,
    pub input_digest: String,
    pub reason: String,
    pub submitted_by: String,
    pub submitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedWorkResolutionAction {
    pub resolution_action_id: String,
    pub effect_id: String,
    pub namespace: String,
    pub expected_park_generation: u64,
    pub status: String,
    pub policy_version: String,
    pub approval_id: String,
    pub decided_by: String,
    pub created_at_ms: i64,
    pub invoked_at_ms: i64,
    pub resolution_input_id: String,
    pub request_id: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionWorkContinuation {
    pub resolution_id: String,
    pub effect_id: String,
    pub namespace: String,
    pub operation_id: String,
    pub park_generation: u64,
    pub input_json: String,
    pub input_digest: String,
    pub park_id: String,
    pub resolution_action_id: String,
    pub resolution_input_id: String,
    pub reason: String,
    pub decided_by: String,
    pub decided_at_ms: i64,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkResult {
    pub effect: crate::sekai::action_effect::ActionEffect,
    pub park: ActionWorkPark,
    pub replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionResult {
    pub effect: crate::sekai::action_effect::ActionEffect,
    pub action: ParkedWorkResolutionAction,
    pub continuation: Option<ActionWorkContinuation>,
    pub park: ActionWorkPark,
    pub replay: bool,
}

pub fn sha256_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn canonical_json(input: &str) -> Result<String, String> {
    if input.len() > MAX_CONTINUATION_JSON_BYTES {
        return Err("input_json exceeds 65536 bytes".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|error| format!("input_json must be JSON: {error}"))?;
    if !value.is_object() {
        return Err("input_json must be a JSON object".into());
    }
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

pub fn validate_reason(reason: &str) -> Result<(), String> {
    if reason.len() > MAX_REASON_BYTES {
        return Err("reason exceeds 2048 bytes".into());
    }
    Ok(())
}

pub fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.trim().is_empty() {
        return Err("request_id required".into());
    }
    if request_id.len() > 256 || request_id.chars().any(char::is_whitespace) {
        return Err("request_id must be at most 256 non-whitespace bytes".into());
    }
    Ok(())
}

pub fn validate_checkpoint_tuple(
    store_id: &str,
    checkpoint_ref: &str,
    digest: &str,
) -> Result<(), String> {
    let present = [
        !store_id.trim().is_empty(),
        !checkpoint_ref.trim().is_empty(),
        !digest.trim().is_empty(),
    ];
    if present.iter().any(|value| *value) && !present.iter().all(|value| *value) {
        return Err(
            "checkpoint store, reference, and digest must be all present or all absent".into(),
        );
    }
    if !present[0] {
        return Ok(());
    }
    if store_id.len() > 128 || checkpoint_ref.len() > 1024 {
        return Err("checkpoint handle exceeds bounds".into());
    }
    let suspicious = |value: &str| {
        value.contains("://")
            || value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
            || value.contains('\\')
    };
    if suspicious(store_id) || suspicious(checkpoint_ref) {
        return Err("checkpoint handles must be opaque identifiers, not URLs or paths".into());
    }
    let hex = digest.strip_prefix("sha256:").unwrap_or("");
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("checkpoint_digest must be sha256:<64 lowercase hex>".into());
    }
    Ok(())
}
