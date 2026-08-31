//! Domain-neutral approval-step workflow adapter (#709).
//!
//! Translates an approval-gate document into a workflow-action envelope.
//! Admission, policy, budget, and receipts stay in the control plane.

use sekai_chisei::sekai::workflow_action::{
    ACTION_TYPE_VERSION, APPROVAL_TYPE_ID, BRIDGE_CONTRACT, PROFILE_APPROVAL_STEP, PROFILE_VERSION,
    USAGE_APPROVAL, WorkflowStepEnvelope,
};
use serde::Deserialize;

pub const ADAPTER_ID: &str = PROFILE_APPROVAL_STEP;
pub const ADAPTER_VERSION: &str = PROFILE_VERSION;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStepDocument {
    pub request_id: String,
    pub gate_id: String,
    pub namespace: String,
    pub owner: String,
    pub source_instance: String,
    pub decision: String,
    pub cursor: u64,
    pub callback_id: String,
    pub callback_digest: String,
    #[serde(default)]
    pub artifact_digest: String,
    pub usage_units: u64,
}

pub fn parse(bytes: &[u8]) -> Result<ApprovalStepDocument, String> {
    serde_json::from_slice(bytes)
        .map_err(|error| format!("approval step document is invalid: {error}"))
}

pub fn translate(document: ApprovalStepDocument) -> Result<WorkflowStepEnvelope, String> {
    if document.request_id.trim().is_empty() || document.gate_id.trim().is_empty() {
        return Err("approval step identity is required".into());
    }
    if document.decision.trim().is_empty() {
        return Err("approval step decision is required".into());
    }
    Ok(WorkflowStepEnvelope {
        contract_version: BRIDGE_CONTRACT.into(),
        profile_id: PROFILE_APPROVAL_STEP.into(),
        profile_version: PROFILE_VERSION.into(),
        namespace: document.namespace,
        owner: document.owner,
        source_instance: document.source_instance,
        step_id: format!("{}/{}", document.request_id, document.gate_id),
        type_id: APPROVAL_TYPE_ID.into(),
        version: ACTION_TYPE_VERSION.into(),
        parameters_json: serde_json::to_string(&serde_json::json!({
            "decision": document.decision
        }))
        .map_err(|error| error.to_string())?,
        cursor: document.cursor,
        callback_id: document.callback_id,
        callback_digest: document.callback_digest,
        artifact_digest: document.artifact_digest,
        usage_kind: USAGE_APPROVAL.into(),
        usage_units: document.usage_units,
        idempotency_key: String::new(),
    })
}
