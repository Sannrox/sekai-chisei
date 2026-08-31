//! Domain-neutral job-step workflow adapter (#709).
//!
//! Translates a sequential job/step document into a workflow-action envelope.
//! Admission, policy, budget, and receipts stay in the control plane.

use sekai_chisei::sekai::workflow_action::{
    ACTION_TYPE_VERSION, BRIDGE_CONTRACT, JOB_TYPE_ID, PROFILE_JOB_STEP, PROFILE_VERSION,
    USAGE_STEP, WorkflowStepEnvelope,
};
use serde::Deserialize;

pub const ADAPTER_ID: &str = PROFILE_JOB_STEP;
pub const ADAPTER_VERSION: &str = PROFILE_VERSION;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStepDocument {
    pub job_id: String,
    pub step_id: String,
    pub namespace: String,
    pub owner: String,
    pub source_instance: String,
    pub runtime: String,
    pub cursor: u64,
    pub callback_id: String,
    pub callback_digest: String,
    #[serde(default)]
    pub artifact_digest: String,
    pub usage_units: u64,
}

pub fn parse(bytes: &[u8]) -> Result<JobStepDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("job step document is invalid: {error}"))
}

pub fn translate(document: JobStepDocument) -> Result<WorkflowStepEnvelope, String> {
    if document.job_id.trim().is_empty() || document.step_id.trim().is_empty() {
        return Err("job step identity is required".into());
    }
    if document.runtime.trim().is_empty() {
        return Err("job step runtime is required".into());
    }
    Ok(WorkflowStepEnvelope {
        contract_version: BRIDGE_CONTRACT.into(),
        profile_id: PROFILE_JOB_STEP.into(),
        profile_version: PROFILE_VERSION.into(),
        namespace: document.namespace,
        owner: document.owner,
        source_instance: document.source_instance,
        step_id: format!("{}/{}", document.job_id, document.step_id),
        type_id: JOB_TYPE_ID.into(),
        version: ACTION_TYPE_VERSION.into(),
        parameters_json: serde_json::to_string(&serde_json::json!({
            "runtime": document.runtime
        }))
        .map_err(|error| error.to_string())?,
        cursor: document.cursor,
        callback_id: document.callback_id,
        callback_digest: document.callback_digest,
        artifact_digest: document.artifact_digest,
        usage_kind: USAGE_STEP.into(),
        usage_units: document.usage_units,
        idempotency_key: String::new(),
    })
}
