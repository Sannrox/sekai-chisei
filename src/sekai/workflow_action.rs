//! Workflow-action bridge (#709).
//!
//! External workflow adapters project steps onto ActionInstance admission.
//! They never evaluate policy, budget, or receipts.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::chisei::budget::BudgetTracker;
use crate::chisei::receipt::OperationReceipt;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_instance::STATUS_ADMITTED;
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
};
use crate::shomei;

pub const BRIDGE_CONTRACT: &str = "sekai.workflow-action-bridge/v1";
pub const PROFILE_JOB_STEP: &str = "adapter.workflow.job_step";
pub const PROFILE_APPROVAL_STEP: &str = "adapter.workflow.approval_step";
pub const PROFILE_VERSION: &str = "1.0.0";
pub const JOB_TYPE_ID: &str = "workflow.job_step";
pub const APPROVAL_TYPE_ID: &str = "workflow.approval_step";
pub const ACTION_TYPE_VERSION: &str = "1";
pub const COMMAND_SUBMIT: &str = "submit";
pub const COMMAND_PARK: &str = "park";
pub const COMMAND_RESUME: &str = "resume";
pub const COMMAND_CANCEL: &str = "cancel";
pub const COMMAND_CALLBACK: &str = "callback";
pub const COMMAND_RECONCILE: &str = "reconcile";
pub const STATUS_SUBMITTED: &str = "submitted";
pub const STATUS_PARKED: &str = "parked";
pub const STATUS_RESUMED: &str = "resumed";
pub const STATUS_CANCELLED: &str = "cancelled";
pub use crate::sekai::action_instance::STATUS_DENIED;
pub const USAGE_STEP: &str = "step";
pub const USAGE_APPROVAL: &str = "approval";
pub const WORKFLOW_UNAVAILABLE: &str = "workflow action is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "workflow action revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "workflow actions are unavailable on the PostgreSQL community runtime";
pub const ADMISSION_RETAINED: &str = "workflow adapters cannot assume admission authority";

const MAX_JSON_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStepEnvelope {
    pub contract_version: String,
    pub profile_id: String,
    pub profile_version: String,
    pub namespace: String,
    pub owner: String,
    pub source_instance: String,
    pub step_id: String,
    pub type_id: String,
    pub version: String,
    pub parameters_json: String,
    pub cursor: u64,
    pub callback_id: String,
    pub callback_digest: String,
    #[serde(default)]
    pub artifact_digest: String,
    pub usage_kind: String,
    pub usage_units: u64,
    #[serde(default)]
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowActionBinding {
    pub contract_version: String,
    pub binding_id: String,
    pub namespace: String,
    pub owner: String,
    pub profile_id: String,
    pub profile_version: String,
    pub source_instance: String,
    pub step_id: String,
    pub type_id: String,
    pub version: String,
    pub parameters_digest: String,
    pub cursor: u64,
    pub callback_id: String,
    pub callback_digest: String,
    #[serde(default)]
    pub artifact_digest: String,
    pub usage_kind: String,
    pub usage_units: u64,
    pub idempotency_key: String,
    pub instance_id: String,
    pub operation_id: String,
    pub instance_status: String,
    pub status: String,
    pub last_command: String,
    pub last_command_digest: String,
    pub binding_digest: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCommandRecord {
    pub namespace: String,
    pub binding_id: String,
    pub command: String,
    pub expected_cursor: u64,
    pub command_digest: String,
    pub result: WorkflowActionBinding,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCallback {
    pub namespace: String,
    pub binding_id: String,
    pub callback_id: String,
    pub cursor: u64,
    pub payload_digest: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReceiptReconciliation {
    pub namespace: String,
    pub binding_id: String,
    pub instance_id: String,
    pub operation_id: String,
    pub instance_status: String,
    pub receipt_present: bool,
    pub receipt_operation_id: String,
    pub matched: bool,
}

#[derive(Serialize)]
struct IdentityPin<'a> {
    namespace: &'a str,
    profile_id: &'a str,
    source_instance: &'a str,
    step_id: &'a str,
}

#[derive(Serialize)]
struct BindingPin<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    owner: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    source_instance: &'a str,
    step_id: &'a str,
    type_id: &'a str,
    version: &'a str,
    parameters_digest: &'a str,
    callback_id: &'a str,
    callback_digest: &'a str,
    artifact_digest: &'a str,
    usage_kind: &'a str,
    usage_units: u64,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct CommandPin<'a> {
    command: &'a str,
    expected_cursor: u64,
    payload_digest: &'a str,
    parameters_digest: &'a str,
    callback_id: &'a str,
    callback_digest: &'a str,
    artifact_digest: &'a str,
    usage_kind: &'a str,
    usage_units: u64,
}

pub fn binding_id_for(
    namespace: &str,
    profile_id: &str,
    source_instance: &str,
    step_id: &str,
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&IdentityPin {
            namespace,
            profile_id,
            source_instance,
            step_id,
        })?
    ))
}

pub fn parameters_digest_for(parameters_json: &str) -> Result<String, String> {
    crate::sekai::action_instance::validate_parameters_json(parameters_json)?;
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
    Ok(format!("sha256:{}", shomei::digest_serializable(&params)?))
}

pub fn binding_digest_for(binding: &WorkflowActionBinding) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&BindingPin {
            contract_version: &binding.contract_version,
            namespace: &binding.namespace,
            owner: &binding.owner,
            profile_id: &binding.profile_id,
            profile_version: &binding.profile_version,
            source_instance: &binding.source_instance,
            step_id: &binding.step_id,
            type_id: &binding.type_id,
            version: &binding.version,
            parameters_digest: &binding.parameters_digest,
            callback_id: &binding.callback_id,
            callback_digest: &binding.callback_digest,
            artifact_digest: &binding.artifact_digest,
            usage_kind: &binding.usage_kind,
            usage_units: binding.usage_units,
            idempotency_key: &binding.idempotency_key,
        })?
    ))
}

pub fn submit_step(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    now_ms: i64,
) -> Result<WorkflowActionBinding, String> {
    required("actor", actor)?;
    require_positive_timestamp("submit", now_ms)?;
    let prepared = prepare_command(db, actor, envelope, COMMAND_SUBMIT, "")?;
    if let Some(replay) = prepared.replay {
        return Ok(replay);
    }
    if prepared.envelope.cursor != 0 {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let budget = BudgetTracker::new(Arc::new(db.clone()));
    let admitted = ActionInstanceAdmission::new(db, Some(&budget))
        .admit(
            ActionInstanceAdmissionRequest {
                namespace: prepared.envelope.namespace.clone(),
                type_id: prepared.envelope.type_id.clone(),
                version: prepared.envelope.version.clone(),
                parameters_json: prepared.envelope.parameters_json.clone(),
                idempotency_key: prepared.envelope.idempotency_key.clone(),
                evidence_submission_ids: Vec::new(),
                request_id: String::new(),
                ontology_digest: String::new(),
            },
            actor,
            now_ms,
        )
        .map_err(map_admission)?;
    if admitted.instance.principal != actor
        || admitted.instance.namespace != prepared.envelope.namespace
        || admitted.instance.idempotency_key != prepared.envelope.idempotency_key
    {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let status = if admitted.instance.status == STATUS_DENIED {
        STATUS_DENIED
    } else if admitted.instance.status == STATUS_ADMITTED {
        STATUS_SUBMITTED
    } else {
        return Err(WORKFLOW_UNAVAILABLE.into());
    };
    let mut binding = WorkflowActionBinding {
        contract_version: BRIDGE_CONTRACT.into(),
        binding_id: prepared.binding_id.clone(),
        namespace: prepared.envelope.namespace.clone(),
        owner: prepared.envelope.owner.clone(),
        profile_id: prepared.envelope.profile_id.clone(),
        profile_version: prepared.envelope.profile_version.clone(),
        source_instance: prepared.envelope.source_instance.clone(),
        step_id: prepared.envelope.step_id.clone(),
        type_id: prepared.envelope.type_id.clone(),
        version: prepared.envelope.version.clone(),
        parameters_digest: parameters_digest_for(&prepared.envelope.parameters_json)?,
        cursor: 0,
        callback_id: prepared.envelope.callback_id.clone(),
        callback_digest: prepared.envelope.callback_digest.clone(),
        artifact_digest: prepared.envelope.artifact_digest.clone(),
        usage_kind: prepared.envelope.usage_kind.clone(),
        usage_units: prepared.envelope.usage_units,
        idempotency_key: prepared.envelope.idempotency_key.clone(),
        instance_id: admitted.instance.instance_id.clone(),
        operation_id: admitted.instance.operation_id.clone(),
        instance_status: admitted.instance.status.clone(),
        status: status.into(),
        last_command: COMMAND_SUBMIT.into(),
        last_command_digest: prepared.digest.clone(),
        binding_digest: String::new(),
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    binding.binding_digest = binding_digest_for(&binding)?;
    match db.commit_workflow_transition(
        None,
        &binding,
        None,
        &prepared.record(&binding, actor, now_ms),
    ) {
        Ok(()) => Ok(binding),
        Err(error) if error == WORKFLOW_UNAVAILABLE => prepared.conflict_replay(db),
        Err(error) => Err(error),
    }
}

pub fn park_step(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    now_ms: i64,
) -> Result<WorkflowActionBinding, String> {
    transition(
        db,
        actor,
        envelope,
        now_ms,
        COMMAND_PARK,
        &[STATUS_SUBMITTED, STATUS_RESUMED],
        STATUS_PARKED,
        "",
    )
}

pub fn resume_step(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    now_ms: i64,
) -> Result<WorkflowActionBinding, String> {
    transition(
        db,
        actor,
        envelope,
        now_ms,
        COMMAND_RESUME,
        &[STATUS_PARKED],
        STATUS_RESUMED,
        "",
    )
}

pub fn cancel_step(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    now_ms: i64,
) -> Result<WorkflowActionBinding, String> {
    transition(
        db,
        actor,
        envelope,
        now_ms,
        COMMAND_CANCEL,
        &[STATUS_SUBMITTED, STATUS_PARKED, STATUS_RESUMED],
        STATUS_CANCELLED,
        "",
    )
}

pub fn callback_step(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    payload_digest: &str,
    now_ms: i64,
) -> Result<WorkflowActionBinding, String> {
    required("actor", actor)?;
    require_positive_timestamp("callback", now_ms)?;
    if !digest_token(payload_digest) {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let prepared = prepare_command(db, actor, envelope, COMMAND_CALLBACK, payload_digest)?;
    if let Some(replay) = prepared.replay {
        return Ok(replay);
    }
    let current = owned_binding(db, &prepared.envelope, actor)?;
    if current.cursor != prepared.envelope.cursor {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if current.callback_id != prepared.envelope.callback_id
        || current.callback_digest != prepared.envelope.callback_digest
        || current.status == STATUS_CANCELLED
        || current.status == STATUS_DENIED
    {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let next_status = if current.status == STATUS_PARKED {
        STATUS_RESUMED
    } else if current.status == STATUS_SUBMITTED || current.status == STATUS_RESUMED {
        current.status.as_str()
    } else {
        return Err(WORKFLOW_UNAVAILABLE.into());
    };
    let mut next = current.clone();
    next.cursor = current.cursor.checked_add(1).ok_or(WORKFLOW_UNAVAILABLE)?;
    next.status = next_status.into();
    next.last_command = COMMAND_CALLBACK.into();
    next.last_command_digest = prepared.digest.clone();
    next.updated_at_ms = now_ms;
    let callback = WorkflowCallback {
        namespace: current.namespace.clone(),
        binding_id: current.binding_id.clone(),
        callback_id: current.callback_id.clone(),
        cursor: prepared.envelope.cursor,
        payload_digest: payload_digest.into(),
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
    };
    match db.commit_workflow_transition(
        Some(&current),
        &next,
        Some(&callback),
        &prepared.record(&next, actor, now_ms),
    ) {
        Ok(()) => Ok(next),
        Err(error) if error == WORKFLOW_UNAVAILABLE => prepared.conflict_replay(db),
        Err(error) => Err(error),
    }
}

pub fn get_binding(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    binding_id: &str,
) -> Result<WorkflowActionBinding, String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    required("binding id", binding_id)?;
    let binding = db
        .get_workflow_binding(namespace, binding_id)?
        .ok_or(WORKFLOW_UNAVAILABLE)?;
    if binding.owner != actor {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if binding.contract_version != BRIDGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(binding)
}

pub fn reconcile_receipt(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    binding_id: &str,
) -> Result<WorkflowReceiptReconciliation, String> {
    let binding = get_binding(db, actor, namespace, binding_id)?;
    let instance = db
        .get_action_instance(&binding.instance_id)?
        .ok_or(WORKFLOW_UNAVAILABLE)?;
    if instance.namespace != binding.namespace
        || instance.operation_id != binding.operation_id
        || instance.principal != binding.owner
    {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let receipt = db.get_operation_receipt(&binding.operation_id)?;
    let (receipt_present, receipt_operation_id, matched) = match receipt {
        Some(OperationReceipt {
            operation_id,
            namespace,
            initiating_actor,
            ..
        }) => {
            let matched = operation_id == binding.operation_id
                && namespace == binding.namespace
                && initiating_actor == binding.owner
                && instance.status == binding.instance_status;
            (true, operation_id, matched)
        }
        None => (false, String::new(), false),
    };
    Ok(WorkflowReceiptReconciliation {
        namespace: binding.namespace,
        binding_id: binding.binding_id,
        instance_id: binding.instance_id,
        operation_id: binding.operation_id,
        instance_status: binding.instance_status,
        receipt_present,
        receipt_operation_id,
        matched,
    })
}

#[allow(clippy::too_many_arguments)]
fn transition(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    now_ms: i64,
    command: &str,
    allowed: &[&str],
    next_status: &str,
    payload_digest: &str,
) -> Result<WorkflowActionBinding, String> {
    required("actor", actor)?;
    require_positive_timestamp(command, now_ms)?;
    let prepared = prepare_command(db, actor, envelope, command, payload_digest)?;
    if let Some(replay) = prepared.replay {
        return Ok(replay);
    }
    let current = owned_binding(db, &prepared.envelope, actor)?;
    if current.cursor != prepared.envelope.cursor
        || !allowed.iter().any(|status| *status == current.status)
        || pins_diverge(&current, &prepared.envelope)
    {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.cursor = current.cursor.checked_add(1).ok_or(WORKFLOW_UNAVAILABLE)?;
    next.status = next_status.into();
    next.last_command = command.into();
    next.last_command_digest = prepared.digest.clone();
    next.updated_at_ms = now_ms;
    match db.commit_workflow_transition(
        Some(&current),
        &next,
        None,
        &prepared.record(&next, actor, now_ms),
    ) {
        Ok(()) => Ok(next),
        Err(error) if error == WORKFLOW_UNAVAILABLE => prepared.conflict_replay(db),
        Err(error) => Err(error),
    }
}

fn prepare_envelope(
    envelope: &WorkflowStepEnvelope,
    actor: &str,
    command: &str,
) -> Result<WorkflowStepEnvelope, String> {
    if envelope.contract_version != BRIDGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if envelope.profile_version != PROFILE_VERSION {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let (expected_usage, expected_type) = match envelope.profile_id.as_str() {
        PROFILE_JOB_STEP => (USAGE_STEP, JOB_TYPE_ID),
        PROFILE_APPROVAL_STEP => (USAGE_APPROVAL, APPROVAL_TYPE_ID),
        _ => return Err(WORKFLOW_UNAVAILABLE.into()),
    };
    if envelope.type_id != expected_type || envelope.version != ACTION_TYPE_VERSION {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    required("namespace", &envelope.namespace)?;
    required("owner", &envelope.owner)?;
    required("source instance", &envelope.source_instance)?;
    required("step id", &envelope.step_id)?;
    required("type id", &envelope.type_id)?;
    required("version", &envelope.version)?;
    required("callback id", &envelope.callback_id)?;
    if envelope.owner != actor {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if envelope.parameters_json.len() > MAX_JSON_BYTES {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    crate::sekai::action_instance::validate_parameters_json(&envelope.parameters_json)
        .map_err(|_| WORKFLOW_UNAVAILABLE.to_string())?;
    if envelope.usage_kind != expected_usage || envelope.usage_units != 1 {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if !digest_token(&envelope.callback_digest) {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if !envelope.artifact_digest.is_empty() && !digest_token(&envelope.artifact_digest) {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if has_whitespace(&envelope.namespace)
        || has_whitespace(&envelope.owner)
        || has_whitespace(&envelope.step_id)
        || has_whitespace(&envelope.source_instance)
        || has_whitespace(&envelope.callback_id)
        || has_whitespace(&envelope.type_id)
        || has_whitespace(&envelope.version)
    {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    if command == COMMAND_SUBMIT && envelope.cursor != 0 {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let binding_id = binding_id_for(
        &envelope.namespace,
        &envelope.profile_id,
        &envelope.source_instance,
        &envelope.step_id,
    )?;
    let derived_key = format!("workflow:{binding_id}");
    if !envelope.idempotency_key.is_empty() && envelope.idempotency_key != derived_key {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    let mut prepared = envelope.clone();
    prepared.idempotency_key = derived_key;
    Ok(prepared)
}

struct PreparedCommand {
    envelope: WorkflowStepEnvelope,
    binding_id: String,
    command: String,
    digest: String,
    replay: Option<WorkflowActionBinding>,
}

impl PreparedCommand {
    fn record(
        &self,
        result: &WorkflowActionBinding,
        actor: &str,
        now_ms: i64,
    ) -> WorkflowCommandRecord {
        WorkflowCommandRecord {
            namespace: self.envelope.namespace.clone(),
            binding_id: self.binding_id.clone(),
            command: self.command.clone(),
            expected_cursor: self.envelope.cursor,
            command_digest: self.digest.clone(),
            result: result.clone(),
            admitted_by: actor.into(),
            admitted_at_ms: now_ms,
        }
    }

    fn conflict_replay(&self, db: &RuntimeDb) -> Result<WorkflowActionBinding, String> {
        let record = db
            .get_workflow_command(
                &self.envelope.namespace,
                &self.binding_id,
                &self.command,
                self.envelope.cursor,
            )?
            .ok_or(WORKFLOW_UNAVAILABLE)?;
        if record.command_digest != self.digest || record.admitted_by != self.envelope.owner {
            return Err(WORKFLOW_UNAVAILABLE.into());
        }
        Ok(record.result)
    }
}

fn prepare_command(
    db: &RuntimeDb,
    actor: &str,
    envelope: &WorkflowStepEnvelope,
    command: &str,
    payload_digest: &str,
) -> Result<PreparedCommand, String> {
    let envelope = prepare_envelope(envelope, actor, command)?;
    let binding_id = binding_id_for(
        &envelope.namespace,
        &envelope.profile_id,
        &envelope.source_instance,
        &envelope.step_id,
    )?;
    let digest = command_digest(
        command,
        envelope.cursor,
        payload_digest,
        &parameters_digest_for(&envelope.parameters_json)?,
        &envelope,
    )?;
    let replay = match db.get_workflow_command(
        &envelope.namespace,
        &binding_id,
        command,
        envelope.cursor,
    )? {
        Some(record) if record.command_digest == digest && record.admitted_by == actor => {
            if pins_diverge(&record.result, &envelope) {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            Some(record.result)
        }
        Some(_) => return Err(WORKFLOW_UNAVAILABLE.into()),
        None => None,
    };
    Ok(PreparedCommand {
        envelope,
        binding_id,
        command: command.into(),
        digest,
        replay,
    })
}

fn owned_binding(
    db: &RuntimeDb,
    envelope: &WorkflowStepEnvelope,
    actor: &str,
) -> Result<WorkflowActionBinding, String> {
    let binding_id = binding_id_for(
        &envelope.namespace,
        &envelope.profile_id,
        &envelope.source_instance,
        &envelope.step_id,
    )?;
    let binding = get_binding(db, actor, &envelope.namespace, &binding_id)?;
    if pins_diverge(&binding, envelope) {
        return Err(WORKFLOW_UNAVAILABLE.into());
    }
    Ok(binding)
}

fn pins_diverge(binding: &WorkflowActionBinding, envelope: &WorkflowStepEnvelope) -> bool {
    binding.profile_id != envelope.profile_id
        || binding.profile_version != envelope.profile_version
        || binding.source_instance != envelope.source_instance
        || binding.step_id != envelope.step_id
        || binding.type_id != envelope.type_id
        || binding.version != envelope.version
        || binding.callback_id != envelope.callback_id
        || binding.callback_digest != envelope.callback_digest
        || binding.artifact_digest != envelope.artifact_digest
        || binding.usage_kind != envelope.usage_kind
        || binding.usage_units != envelope.usage_units
        || parameters_digest_for(&envelope.parameters_json)
            .ok()
            .is_none_or(|digest| digest != binding.parameters_digest)
}

fn command_digest(
    command: &str,
    expected_cursor: u64,
    payload_digest: &str,
    parameters_digest: &str,
    envelope: &WorkflowStepEnvelope,
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&CommandPin {
            command,
            expected_cursor,
            payload_digest,
            parameters_digest,
            callback_id: &envelope.callback_id,
            callback_digest: &envelope.callback_digest,
            artifact_digest: &envelope.artifact_digest,
            usage_kind: &envelope.usage_kind,
            usage_units: envelope.usage_units,
        })?
    ))
}

fn map_admission(error: ActionInstanceAdmissionError) -> String {
    match error {
        ActionInstanceAdmissionError::Internal(message)
            if message == POSTGRES_UNAVAILABLE || message.contains("unavailable") =>
        {
            if message == POSTGRES_UNAVAILABLE {
                POSTGRES_UNAVAILABLE.into()
            } else {
                WORKFLOW_UNAVAILABLE.into()
            }
        }
        _ => WORKFLOW_UNAVAILABLE.into(),
    }
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn has_whitespace(value: &str) -> bool {
    value.chars().any(char::is_whitespace)
}

fn require_positive_timestamp(action: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{action} timestamp must be positive"))
    } else {
        Ok(())
    }
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::memory();
        db.put_governed_action_type(job_type(), "operator", 1)
            .unwrap();
        db.put_governed_action_type(approval_type(), "operator", 1)
            .unwrap();
        db
    }

    fn job_type() -> GovernedActionType {
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "workflow.job_step".into(),
            version: "1".into(),
            description: "job step".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: String::new(),
            object_mutation: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        }
    }

    fn approval_type() -> GovernedActionType {
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "workflow.approval_step".into(),
            version: "1".into(),
            description: "approval step".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"decision":{"type":"string"}},"required":["decision"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: String::new(),
            object_mutation: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        }
    }

    fn job_envelope() -> WorkflowStepEnvelope {
        WorkflowStepEnvelope {
            contract_version: BRIDGE_CONTRACT.into(),
            profile_id: PROFILE_JOB_STEP.into(),
            profile_version: PROFILE_VERSION.into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            source_instance: "runner:ci".into(),
            step_id: "job:nightly/build".into(),
            type_id: "workflow.job_step".into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"job"}"#.into(),
            cursor: 0,
            callback_id: "cb:job:nightly:build".into(),
            callback_digest: digest(1),
            artifact_digest: String::new(),
            usage_kind: USAGE_STEP.into(),
            usage_units: 1,
            idempotency_key: String::new(),
        }
    }

    fn approval_envelope() -> WorkflowStepEnvelope {
        WorkflowStepEnvelope {
            contract_version: BRIDGE_CONTRACT.into(),
            profile_id: PROFILE_APPROVAL_STEP.into(),
            profile_version: PROFILE_VERSION.into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            source_instance: "gate:change".into(),
            step_id: "req:change-1/security".into(),
            type_id: "workflow.approval_step".into(),
            version: "1".into(),
            parameters_json: r#"{"decision":"open"}"#.into(),
            cursor: 0,
            callback_id: "cb:req:change-1:security".into(),
            callback_digest: digest(2),
            artifact_digest: String::new(),
            usage_kind: USAGE_APPROVAL.into(),
            usage_units: 1,
            idempotency_key: String::new(),
        }
    }

    fn lifecycle(runtime: &RuntimeDb, mut envelope: WorkflowStepEnvelope) {
        let submitted = submit_step(runtime, "integrator", &envelope, 1_000).unwrap();
        assert_eq!(submitted.status, STATUS_SUBMITTED);
        assert_eq!(submitted.instance_status, STATUS_ADMITTED);
        assert_eq!(
            submit_step(runtime, "integrator", &envelope, 1_100).unwrap(),
            submitted
        );
        let mut conflicting = envelope.clone();
        if envelope.profile_id == PROFILE_JOB_STEP {
            conflicting.parameters_json = r#"{"runtime":"other"}"#.into();
        } else {
            conflicting.parameters_json = r#"{"decision":"other"}"#.into();
        }
        assert_eq!(
            submit_step(runtime, "integrator", &conflicting, 1_200).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        envelope.cursor = 0;
        let parked = park_step(runtime, "integrator", &envelope, 2_000).unwrap();
        assert_eq!(parked.status, STATUS_PARKED);
        assert_eq!(parked.cursor, 1);
        assert_eq!(
            park_step(runtime, "integrator", &envelope, 2_100).unwrap(),
            parked
        );
        let mut stale = envelope.clone();
        stale.cursor = 9;
        assert_eq!(
            park_step(runtime, "integrator", &stale, 2_200).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        envelope.cursor = 1;
        let resumed = callback_step(runtime, "integrator", &envelope, &digest(9), 3_000).unwrap();
        assert_eq!(resumed.status, STATUS_RESUMED);
        assert_eq!(resumed.cursor, 2);
        assert_eq!(
            callback_step(runtime, "integrator", &envelope, &digest(9), 3_100).unwrap(),
            resumed
        );
        let mut wrong_callback = envelope.clone();
        wrong_callback.callback_digest = digest(7);
        assert_eq!(
            callback_step(runtime, "integrator", &wrong_callback, &digest(9), 3_200).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        envelope.cursor = 2;
        let cancelled = cancel_step(runtime, "integrator", &envelope, 4_000).unwrap();
        assert_eq!(cancelled.status, STATUS_CANCELLED);
        assert_eq!(
            cancel_step(runtime, "integrator", &envelope, 4_100).unwrap(),
            cancelled
        );
        envelope.cursor = 0;
        assert_eq!(
            park_step(runtime, "integrator", &envelope, 4_200).unwrap(),
            parked
        );
        envelope.cursor = 2;
        assert_eq!(
            park_step(runtime, "integrator", &envelope, 4_300).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let reconciled = reconcile_receipt(
            runtime,
            "integrator",
            &submitted.namespace,
            &submitted.binding_id,
        )
        .unwrap();
        assert!(reconciled.receipt_present);
        assert!(reconciled.matched);
        assert_eq!(reconciled.operation_id, submitted.operation_id);
        assert_eq!(
            get_binding(
                runtime,
                "intruder",
                &submitted.namespace,
                &submitted.binding_id
            )
            .unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
    }

    #[test]
    fn job_and_approval_adapters_share_the_governed_lifecycle() {
        let runtime = setup();
        lifecycle(&runtime, job_envelope());
        lifecycle(&runtime, approval_envelope());
    }

    #[test]
    fn hidden_fields_unknown_versions_and_ambiguous_usage_fail_closed() {
        let runtime = setup();
        let mut hidden = serde_json::to_value(job_envelope()).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("policy".into(), serde_json::json!("allow"));
        assert!(serde_json::from_value::<WorkflowStepEnvelope>(hidden).is_err());
        let mut unknown = job_envelope();
        unknown.contract_version = "sekai.workflow-action-bridge/v0".into();
        assert_eq!(
            submit_step(&runtime, "integrator", &unknown, 1_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        let mut usage = job_envelope();
        usage.usage_units = 0;
        assert_eq!(
            submit_step(&runtime, "integrator", &usage, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let mut mismatched = job_envelope();
        mismatched.usage_kind = USAGE_APPROVAL.into();
        assert_eq!(
            submit_step(&runtime, "integrator", &mismatched, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let mut padded = job_envelope();
        padded.namespace = " ops ".into();
        assert_eq!(
            submit_step(&runtime, "integrator", &padded, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let submitted = submit_step(&runtime, "integrator", &job_envelope(), 500).unwrap();
        let mut usage = job_envelope();
        usage.usage_units = 2;
        assert_eq!(
            submit_step(&runtime, "integrator", &usage, 600).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        assert_eq!(
            get_binding(
                &runtime,
                "integrator",
                &submitted.namespace,
                &submitted.binding_id
            )
            .unwrap()
            .usage_units,
            1
        );
        let mut hijack = job_envelope();
        hijack.idempotency_key = "workflow:foreign-key".into();
        hijack.step_id = "job:nightly/other".into();
        hijack.callback_id = "cb:job:nightly:other".into();
        assert_eq!(
            submit_step(&runtime, "integrator", &hijack, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let mut wrong_type = job_envelope();
        wrong_type.type_id = APPROVAL_TYPE_ID.into();
        assert_eq!(
            submit_step(&runtime, "integrator", &wrong_type, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        let mut first = job_envelope();
        first.source_instance = "a:b".into();
        first.step_id = "c".into();
        first.callback_id = "cb:a-b-c".into();
        let mut second = first.clone();
        second.source_instance = "a".into();
        second.step_id = "b:c".into();
        second.callback_id = "cb:a-bc".into();
        let left = submit_step(&runtime, "integrator", &first, 1_000).unwrap();
        let right = submit_step(&runtime, "integrator", &second, 1_100).unwrap();
        assert_ne!(left.binding_id, right.binding_id);
        assert_ne!(left.idempotency_key, right.idempotency_key);
        let mut foreign = job_envelope();
        foreign.owner = "intruder".into();
        assert_eq!(
            submit_step(&runtime, "integrator", &foreign, 1_000).unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        assert_eq!(
            ADMISSION_RETAINED,
            "workflow adapters cannot assume admission authority"
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "workflow actions are unavailable on the PostgreSQL community runtime"
        );
    }
}
