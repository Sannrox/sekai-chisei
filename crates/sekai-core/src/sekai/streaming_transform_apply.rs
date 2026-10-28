//! Exactly-once apply of streaming transform output onto Action-written objects.
//!
//! A claimed isolated-process worker commits a batch of object edits together
//! with its input checkpoint in one store transaction. Claim generation fences
//! stale workers. Replay of the same `(run_id, checkpoint)` returns the original
//! receipt and writes nothing. Action policy, freeze, and the bound object
//! mutation stay on the existing Action path.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::action::RiskClass;
use crate::sekai::action_instance::SUBMIT_POLICY_ACTION;
use crate::sekai::action_object_mutation::{self, PlannedObjectMutation};
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::action_type_criteria::{
    CRITERION_UNAVAILABLE, CriterionDecision, evaluate_submission_criteria, invoker_context,
};
use crate::sekai::governed_transform::{STALE_TRANSFORM_CLAIM, fold_live_output_marking};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use crate::sekai::object_security::PrincipalPolicyContext;
use crate::sekai::write_freeze;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingApplyError {
    InvalidArgument(String),
    FailedPrecondition(String),
    NotFound(String),
    PermissionDenied(String),
    Internal(String),
}

impl StreamingApplyError {
    pub fn message(self) -> String {
        match self {
            Self::InvalidArgument(message)
            | Self::FailedPrecondition(message)
            | Self::NotFound(message)
            | Self::PermissionDenied(message)
            | Self::Internal(message) => message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingInputPosition {
    pub source: String,
    pub position: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingObjectVersion {
    pub object_id: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingObjectEdit {
    pub object_id: String,
    pub name: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingTransformApplyRequest {
    pub run_id: String,
    pub runtime_id: String,
    pub claim_generation: i64,
    pub fencing_token: String,
    pub checkpoint: String,
    pub action_type_id: String,
    pub action_type_version: String,
    pub edits: Vec<StreamingObjectEdit>,
    pub input_positions: Vec<StreamingInputPosition>,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamingApplyAuth<'a> {
    pub actor: &'a str,
    pub tenant: &'a str,
    pub resource_tenant: &'a str,
    pub delegating_actor: Option<&'a str>,
    pub machine_credential: bool,
    pub policy_context: Option<&'a PrincipalPolicyContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingTransformApplyReceipt {
    pub run_id: String,
    pub claim_generation: i64,
    pub checkpoint: String,
    pub input_positions: Vec<StreamingInputPosition>,
    pub objects: Vec<StreamingObjectVersion>,
    pub transform_version: String,
    pub action_type_id: String,
    pub action_type_version: String,
    pub replay: bool,
}

#[derive(Debug, Clone)]
pub struct PlannedStreamingEdit {
    pub create: bool,
    pub object: Object,
    pub expected: Option<Object>,
}

#[derive(Debug, Clone)]
pub struct StreamingTransformApplyBatch {
    pub run_id: String,
    pub runtime_id: String,
    pub claim_generation: i64,
    pub fencing_token: String,
    pub checkpoint: String,
    pub input_positions: Vec<StreamingInputPosition>,
    pub edits: Vec<PlannedStreamingEdit>,
    pub transform_version: String,
    pub action_type_id: String,
    pub action_type_version: String,
    pub policy_generation: String,
}

/// Evaluate Action policy, plan bound object mutations, and commit them with
/// the checkpoint in one store transaction.
pub fn apply(
    db: &RuntimeDb,
    request: StreamingTransformApplyRequest,
    now_ms: i64,
    auth: StreamingApplyAuth<'_>,
    mut authorize: impl FnMut(Option<&Object>, &Object, bool) -> Result<(), StreamingApplyError>,
) -> Result<StreamingTransformApplyReceipt, StreamingApplyError> {
    let run_id = request.run_id.trim();
    let checkpoint = request.checkpoint.as_str();
    let action_type_id = request.action_type_id.trim();
    let action_type_version = request.action_type_version.trim();
    if run_id.is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "run_id required".into(),
        ));
    }
    if request.runtime_id.trim().is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "runtime_id required".into(),
        ));
    }
    if request.fencing_token.trim().is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "fencing_token required".into(),
        ));
    }
    if checkpoint.is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "checkpoint required".into(),
        ));
    }
    if action_type_id.is_empty() || action_type_version.is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "action_type_id and action_type_version required".into(),
        ));
    }
    let mut seen_object_ids = HashSet::new();
    for edit in &request.edits {
        let object_id = edit.object_id.trim();
        if object_id.is_empty() {
            return Err(StreamingApplyError::InvalidArgument(
                "object_id required".into(),
            ));
        }
        if !seen_object_ids.insert(object_id) {
            return Err(StreamingApplyError::InvalidArgument(format!(
                "duplicate object_id {object_id} in batch"
            )));
        }
    }

    let run = db
        .get_governed_transform_run(run_id)
        .map_err(StreamingApplyError::Internal)?
        .ok_or_else(|| StreamingApplyError::NotFound("transform run not found".into()))?;
    if let Some(receipt) = replay_committed(db, &request, checkpoint, now_ms, auth.actor)? {
        return Ok(receipt);
    }
    let type_def = db
        .require_enabled_governed_action_type(&run.namespace, action_type_id, action_type_version)
        .map_err(|error| {
            if error.contains("unknown") || error.contains("disabled") {
                StreamingApplyError::PermissionDenied(error)
            } else {
                StreamingApplyError::Internal(error)
            }
        })?;
    if type_def.object_kind.trim().is_empty() || type_def.object_mutation.trim().is_empty() {
        return Err(StreamingApplyError::InvalidArgument(
            "action type must bind object_kind and object_mutation".into(),
        ));
    }
    // This RPC has no envelope_id. Autonomous types require a live envelope on
    // SubmitActionInstance; refuse them here until that contract is on the wire.
    if type_def.type_id.starts_with("autonomous.") {
        return Err(StreamingApplyError::PermissionDenied(
            "streaming transform apply does not admit autonomous Action types".into(),
        ));
    }

    let agent = write_freeze::actor_is_agent(
        db,
        auth.actor,
        auth.delegating_actor,
        auth.machine_credential,
    )
    .map_err(StreamingApplyError::Internal)?;
    let acting = write_freeze::acting_or_registered_tenant(db, auth.tenant, auth.actor)
        .map_err(StreamingApplyError::Internal)?;
    let resource = auth.resource_tenant.trim();
    let mut freeze_checks = write_freeze::write_checks_for_actors(
        &run.namespace,
        acting.as_ref(),
        auth.actor,
        auth.delegating_actor,
        action_type_id,
        agent,
    );
    if !resource.is_empty() && resource != acting.as_ref() {
        freeze_checks.extend(write_freeze::write_checks_for_actors(
            &run.namespace,
            resource,
            auth.actor,
            auth.delegating_actor,
            action_type_id,
            agent,
        ));
    }
    if let Some(reason) = write_freeze::freeze_reason_any(db, &freeze_checks)
        .map_err(StreamingApplyError::Internal)?
    {
        return Err(StreamingApplyError::PermissionDenied(reason));
    }

    crate::sekai::parameter_schema::validate_parameter_schema(&type_def.parameter_schema_json)
        .map_err(|error| {
            StreamingApplyError::InvalidArgument(format!(
                "governed action type parameter schema invalid: {error}"
            ))
        })?;

    let policy_project = if type_def.policy_scope.trim().is_empty() {
        run.namespace.clone()
    } else {
        type_def.policy_scope.clone()
    };
    let resolved_policy = db
        .resolve_action_policy(auth.actor, &run.namespace, &policy_project)
        .map_err(StreamingApplyError::Internal)?;
    match resolved_policy.map(|policy| policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write)) {
        Some(ActionDecision::Deny) => {
            return Err(StreamingApplyError::PermissionDenied(
                "action policy denied streaming transform apply".into(),
            ));
        }
        Some(ActionDecision::RequireApproval) => {
            return Err(StreamingApplyError::PermissionDenied(
                "streaming transform apply requires allow; require_approval is refused".into(),
            ));
        }
        Some(ActionDecision::Allow) | None => {}
    }

    // Propose-only keys off the actor principal, not freeze's agent_action
    // (machine credentials / delegating actors). This RPC cannot park, so
    // refuse propose-only agent submissions.
    if crate::sekai::agent_autonomy::actor_is_agent(db, auth.actor) {
        match crate::sekai::agent_autonomy::evaluate_admission(
            db,
            auth.actor,
            &run.namespace,
            action_type_id,
            "",
            now_ms,
        ) {
            Ok(crate::sekai::agent_autonomy::AdmissionAutonomy::AutoApply { .. }) => {}
            Ok(crate::sekai::agent_autonomy::AdmissionAutonomy::ProposeOnly) => {
                return Err(StreamingApplyError::PermissionDenied(
                    "streaming transform apply refuses propose-only agent submissions".into(),
                ));
            }
            Err(error) => return Err(StreamingApplyError::Internal(error)),
        }
    }

    let mut planned = Vec::with_capacity(request.edits.len());
    for edit in &request.edits {
        let authorized_id = edit.object_id.trim();
        let expected = db
            .get_object(authorized_id)
            .map_err(StreamingApplyError::Internal)?;
        let parameters_json = edit_parameters_json(edit, &type_def.parameter_schema_json)?;
        crate::sekai::parameter_schema::validate_parameters(
            &type_def.parameter_schema_json,
            &parameters_json,
        )
        .map_err(|error| {
            StreamingApplyError::InvalidArgument(format!("action parameters invalid: {error}"))
        })?;
        let planned_mutation = match action_object_mutation::plan(
            db,
            &type_def,
            &run.namespace,
            &parameters_json,
            // No principal submits a streaming edit, so none may curate.
            None,
            // The run stamps its own admitted marking on the output below.
            None,
            now_ms,
        ) {
            Ok(Some(planned)) => planned,
            Ok(None) => {
                return Err(StreamingApplyError::InvalidArgument(
                    "action type must bind object_kind and object_mutation".into(),
                ));
            }
            Err(error) => {
                if let Some(receipt) =
                    replay_committed(db, &request, checkpoint, now_ms, auth.actor)?
                {
                    return Ok(receipt);
                }
                return Err(map_mutation_error(error));
            }
        };
        let (create, mut object) = match planned_mutation {
            PlannedObjectMutation::Create(object) => (true, object),
            PlannedObjectMutation::Update(object, _) => (false, object),
        };
        if object.id != authorized_id {
            return Err(StreamingApplyError::InvalidArgument(
                "planned object_id must match edit.object_id".into(),
            ));
        }
        if create {
            object.created = now_ms;
            object.updated = now_ms;
            stamp_admitted_output_marking(
                db,
                &run.namespace,
                &run.markings_out,
                None,
                &mut object,
            )?;
            revalidate_after_marking(db, &mut object, now_ms)?;
            planned.push(PlannedStreamingEdit {
                create: true,
                object,
                expected: None,
            });
            continue;
        }
        let expected = expected.ok_or_else(|| {
            StreamingApplyError::FailedPrecondition(format!("object {authorized_id} not found"))
        })?;
        object.updated = now_ms;
        stamp_admitted_output_marking(
            db,
            &run.namespace,
            &run.markings_out,
            Some(&expected),
            &mut object,
        )?;
        revalidate_after_marking(db, &mut object, now_ms)?;
        planned.push(PlannedStreamingEdit {
            create: false,
            object,
            expected: Some(expected),
        });
    }
    let policy_generation = db
        .get_object_security_activation(&run.namespace)
        .map_err(StreamingApplyError::Internal)?
        .map(|activation| activation.activation_id)
        .unwrap_or_else(|| "legacy".into());
    let invoker = invoker_context(auth.actor, auth.policy_context);
    for edit in &planned {
        let criterion_object = edit.expected.as_ref();
        let criterion_policy = match criterion_object {
            Some(object) => db
                .active_object_policy(&object.namespace, &object.kind)
                .map_err(StreamingApplyError::Internal)?,
            None => None,
        };
        match evaluate_submission_criteria(
            &type_def.submission_criteria,
            criterion_object,
            criterion_policy.as_ref(),
            &invoker,
        ) {
            CriterionDecision::Pass => {}
            CriterionDecision::Fail { criterion_id } => {
                return Err(StreamingApplyError::PermissionDenied(format!(
                    "submission criterion {criterion_id} failed"
                )));
            }
            CriterionDecision::Unavailable => {
                return Err(StreamingApplyError::PermissionDenied(
                    CRITERION_UNAVAILABLE.into(),
                ));
            }
        }
        authorize(edit.expected.as_ref(), &edit.object, edit.create)?;
    }

    let batch = StreamingTransformApplyBatch {
        run_id: run_id.to_string(),
        runtime_id: request.runtime_id,
        claim_generation: request.claim_generation,
        fencing_token: request.fencing_token,
        checkpoint: checkpoint.to_string(),
        input_positions: request.input_positions,
        edits: planned,
        transform_version: run.definition_digest,
        action_type_id: action_type_id.to_string(),
        action_type_version: action_type_version.to_string(),
        policy_generation,
    };
    // Action budget reservation is CrossStoreAdmission-only. Native
    // SubmitActionInstance on this service also constructs admission with
    // budget: None.
    let receipt = db.apply_streaming_transform_batch(batch, auth.actor, now_ms)?;
    complete_receipt_writes(db, &receipt, auth.actor, now_ms);
    Ok(receipt)
}

fn replay_committed(
    db: &RuntimeDb,
    request: &StreamingTransformApplyRequest,
    checkpoint: &str,
    now_ms: i64,
    actor: &str,
) -> Result<Option<StreamingTransformApplyReceipt>, StreamingApplyError> {
    let Some(receipt) = db.peek_streaming_transform_apply(
        request.run_id.trim(),
        &request.runtime_id,
        request.claim_generation,
        &request.fencing_token,
        checkpoint,
        now_ms,
    )?
    else {
        return Ok(None);
    };
    complete_receipt_writes(db, &receipt, actor, now_ms);
    Ok(Some(receipt))
}

/// Fold admitted `markings_out` with any stricter live stamp so a worker
/// cannot omit or lower classification on streaming output objects.
fn stamp_admitted_output_marking(
    db: &RuntimeDb,
    namespace: &str,
    admitted_out: &str,
    existing: Option<&Object>,
    object: &mut Object,
) -> Result<(), StreamingApplyError> {
    let lattice = db
        .get_classification_lattice(namespace)
        .map_err(StreamingApplyError::Internal)?;
    let existing_token = existing.and_then(crate::sekai::markings::object_marking_token);
    let planned_token = crate::sekai::markings::object_marking_token(object);
    let with_existing = fold_live_output_marking(lattice.as_ref(), admitted_out, existing_token)
        .map_err(StreamingApplyError::FailedPrecondition)?;
    let folded = fold_live_output_marking(lattice.as_ref(), &with_existing, planned_token)
        .map_err(StreamingApplyError::FailedPrecondition)?;
    if folded.trim().is_empty() {
        return Ok(());
    }
    object
        .properties
        .insert(OBJECT_CLASSIFICATION_PROPERTY.to_string(), folded);
    Ok(())
}

fn revalidate_after_marking(
    db: &RuntimeDb,
    object: &mut Object,
    now_ms: i64,
) -> Result<(), StreamingApplyError> {
    crate::sekai::feedback_package::validate_object_write(db, object, now_ms)
        .and_then(|()| crate::sekai::function_document::validate_lineage_write(db, object, now_ms))
        .map_err(StreamingApplyError::FailedPrecondition)
}

/// Best-effort Action follow-ups after the checkpoint is durable. Same
/// catch-up as Action admission replay: evidence projection and document
/// lineage stubs are idempotent, so a crash between persist and completion
/// is repaired on the next apply of this checkpoint.
fn complete_receipt_writes(
    db: &RuntimeDb,
    receipt: &StreamingTransformApplyReceipt,
    actor: &str,
    now_ms: i64,
) {
    for object in &receipt.objects {
        if let Ok(Some(current)) = db.get_object(&object.object_id) {
            action_object_mutation::complete_object_write(db, &current, actor, now_ms);
        }
    }
}

pub fn encode_receipt(receipt: &StreamingTransformApplyReceipt) -> Result<String, String> {
    serde_json::to_string(receipt).map_err(|error| error.to_string())
}

pub fn decode_receipt(raw: &str) -> Result<StreamingTransformApplyReceipt, String> {
    serde_json::from_str(raw).map_err(|error| format!("decode streaming apply receipt: {error}"))
}

pub fn receipt_from_batch(
    batch: &StreamingTransformApplyBatch,
    replay: bool,
) -> StreamingTransformApplyReceipt {
    StreamingTransformApplyReceipt {
        run_id: batch.run_id.clone(),
        claim_generation: batch.claim_generation,
        checkpoint: batch.checkpoint.clone(),
        input_positions: batch.input_positions.clone(),
        objects: batch
            .edits
            .iter()
            .map(|edit| StreamingObjectVersion {
                object_id: edit.object.id.clone(),
                version: edit.object.updated,
            })
            .collect(),
        transform_version: batch.transform_version.clone(),
        action_type_id: batch.action_type_id.clone(),
        action_type_version: batch.action_type_version.clone(),
        replay,
    }
}

fn edit_parameters_json(
    edit: &StreamingObjectEdit,
    schema_json: &str,
) -> Result<String, StreamingApplyError> {
    let schema: serde_json::Value = serde_json::from_str(schema_json).map_err(|error| {
        StreamingApplyError::FailedPrecondition(format!(
            "governed action type parameter schema invalid: {error}"
        ))
    })?;
    let declared = schema
        .get("properties")
        .and_then(serde_json::Value::as_object);
    let mut value = serde_json::Map::new();
    for (key, property) in &edit.properties {
        let key = key.trim();
        if key.is_empty() {
            return Err(StreamingApplyError::InvalidArgument(
                "property key required".into(),
            ));
        }
        if key == "object_id" || key == "name" {
            return Err(StreamingApplyError::InvalidArgument(format!(
                "properties must not include reserved key {key}"
            )));
        }
        let typed = match declared.and_then(|properties| properties.get(key)) {
            Some(schema) => coerce_parameter_value(key, property, schema)?,
            None => serde_json::Value::String(property.clone()),
        };
        value.insert(key.to_string(), typed);
    }
    value.insert(
        "object_id".into(),
        serde_json::Value::String(edit.object_id.clone()),
    );
    if !edit.name.trim().is_empty() {
        value.insert("name".into(), serde_json::Value::String(edit.name.clone()));
    }
    serde_json::to_string(&serde_json::Value::Object(value)).map_err(|error| {
        StreamingApplyError::InvalidArgument(format!("encode edit parameters: {error}"))
    })
}

fn coerce_parameter_value(
    name: &str,
    raw: &str,
    schema: &serde_json::Value,
) -> Result<serde_json::Value, StreamingApplyError> {
    let parameter_type = schema
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("string");
    match parameter_type {
        "boolean" => match raw.trim() {
            "true" => Ok(serde_json::Value::Bool(true)),
            "false" => Ok(serde_json::Value::Bool(false)),
            _ => Err(StreamingApplyError::InvalidArgument(format!(
                "parameter {name} must be a boolean"
            ))),
        },
        "integer" => {
            let raw = raw.trim();
            if let Ok(parsed) = raw.parse::<i64>() {
                Ok(serde_json::Value::Number(parsed.into()))
            } else if let Ok(parsed) = raw.parse::<u64>() {
                Ok(serde_json::Value::Number(parsed.into()))
            } else {
                Err(StreamingApplyError::InvalidArgument(format!(
                    "parameter {name} must be an integer"
                )))
            }
        }
        "number" => {
            let parsed: f64 = raw.trim().parse().map_err(|_| {
                StreamingApplyError::InvalidArgument(format!("parameter {name} must be a number"))
            })?;
            let number = serde_json::Number::from_f64(parsed).ok_or_else(|| {
                StreamingApplyError::InvalidArgument(format!("parameter {name} must be a number"))
            })?;
            Ok(serde_json::Value::Number(number))
        }
        _ => Ok(serde_json::Value::String(raw.to_string())),
    }
}

fn map_mutation_error(
    error: action_object_mutation::ActionObjectMutationError,
) -> StreamingApplyError {
    match error {
        action_object_mutation::ActionObjectMutationError::InvalidArgument(message) => {
            StreamingApplyError::InvalidArgument(message)
        }
        action_object_mutation::ActionObjectMutationError::FailedPrecondition(message) => {
            StreamingApplyError::FailedPrecondition(message)
        }
        action_object_mutation::ActionObjectMutationError::Internal(message) => {
            StreamingApplyError::Internal(message)
        }
    }
}

pub fn map_persist_error(error: String) -> StreamingApplyError {
    if error == STALE_TRANSFORM_CLAIM
        || error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION
    {
        StreamingApplyError::FailedPrecondition(error)
    } else if error.contains("not found") {
        StreamingApplyError::NotFound(error)
    } else if error.contains("required") || error.contains("checkpoint") {
        StreamingApplyError::InvalidArgument(error)
    } else {
        StreamingApplyError::Internal(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::sekai::action_policy::ActionPolicy;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_action_type::{
        EFFECT_KIND_NOTIFY, GovernedActionType, OBJECT_MUTATION_CREATE, OBJECT_MUTATION_UPDATE,
    };
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, TRANSFORM_WORK_CLAIMED,
    };
    use crate::sekai::schema::{ObjectType, PropertyDef, PropertyType};

    const PARAM_SCHEMA: &str = r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"n":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#;
    const PARAM_SCHEMA_MARKED: &str = r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"n":{"type":"string"},"access_marking":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#;

    fn dataset(id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn isolated_transform() -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "iso-stream".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
                requires: Default::default(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    fn create_type() -> GovernedActionType {
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "stream.record.create".into(),
            version: "1".into(),
            description: "create".into(),
            parameter_schema_json: PARAM_SCHEMA.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: "stream_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            created_by: "alice".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
            ..Default::default()
        }
    }

    fn update_type() -> GovernedActionType {
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "stream.record.update".into(),
            version: "1".into(),
            description: "update".into(),
            parameter_schema_json: PARAM_SCHEMA_MARKED.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: "stream_record".into(),
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            enabled: true,
            created_by: "alice".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
            ..Default::default()
        }
    }

    fn seed_kind(db: &RuntimeDb) {
        db.upsert_object_type(&ObjectType {
            kind: "stream_record".into(),
            description: "fixture".into(),
            properties: vec![PropertyDef {
                name: "n".into(),
                prop_type: PropertyType::String,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    }

    fn claim_run(db: &RuntimeDb) -> crate::sekai::governed_transform::TransformWork {
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso-stream", false, 20)
            .unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable");
        assert_eq!(work.status, TRANSFORM_WORK_CLAIMED);
        work
    }

    fn claim_run_marked(
        db: &RuntimeDb,
        marking: &str,
    ) -> crate::sekai::governed_transform::TransformWork {
        db.create_object(&crate::domain::Object {
            id: "in-obj".into(),
            kind: "stream_record".into(),
            name: "in-obj".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::from([(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into())]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso-stream", false, 20)
            .unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable");
        work
    }

    fn setup_marked(marking: &str) -> (RuntimeDb, crate::sekai::governed_transform::TransformWork) {
        let db = RuntimeDb::memory();
        seed_kind(&db);
        db.put_governed_action_type(create_type(), "alice", 5)
            .unwrap();
        let work = claim_run_marked(&db, marking);
        (db, work)
    }

    fn edit(id: &str, n: &str) -> StreamingObjectEdit {
        StreamingObjectEdit {
            object_id: id.into(),
            name: id.into(),
            properties: HashMap::from([("n".into(), n.into())]),
        }
    }

    fn request(
        work: &crate::sekai::governed_transform::TransformWork,
        checkpoint: &str,
        edits: Vec<StreamingObjectEdit>,
    ) -> StreamingTransformApplyRequest {
        StreamingTransformApplyRequest {
            run_id: work.run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
            checkpoint: checkpoint.into(),
            action_type_id: "stream.record.create".into(),
            action_type_version: "1".into(),
            edits,
            input_positions: vec![StreamingInputPosition {
                source: "src".into(),
                position: checkpoint.into(),
            }],
        }
    }

    fn setup() -> (RuntimeDb, crate::sekai::governed_transform::TransformWork) {
        let db = RuntimeDb::memory();
        seed_kind(&db);
        db.put_governed_action_type(create_type(), "alice", 5)
            .unwrap();
        let work = claim_run(&db);
        (db, work)
    }

    fn apply_unrestricted(
        db: &RuntimeDb,
        request: StreamingTransformApplyRequest,
        actor: &str,
        now_ms: i64,
    ) -> Result<StreamingTransformApplyReceipt, StreamingApplyError> {
        apply(
            db,
            request,
            now_ms,
            StreamingApplyAuth {
                actor,
                tenant: "",
                resource_tenant: "",
                delegating_actor: None,
                machine_credential: false,
                policy_context: None,
            },
            |_, _, _| Ok(()),
        )
    }

    fn object_snapshot(db: &RuntimeDb) -> Vec<(String, String, i64)> {
        let mut rows = db
            .list_objects(&crate::domain::ListFilter {
                kind: Some("stream_record".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|object| {
                (
                    object.id,
                    object.properties.get("n").cloned().unwrap_or_default(),
                    object.updated,
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    }

    #[test]
    fn kill_and_restart_applies_each_source_record_once() {
        let n = 6usize;
        let (reference_db, reference_work) = setup();
        for i in 0..n {
            let checkpoint = format!("c{i}");
            apply_unrestricted(
                &reference_db,
                request(
                    &reference_work,
                    &checkpoint,
                    vec![edit(&format!("rec-{i}"), &i.to_string())],
                ),
                "alice",
                1_000 + i as i64,
            )
            .unwrap();
        }
        let expected = object_snapshot(&reference_db);
        assert_eq!(expected.len(), n);

        for crash_after in 0..=n {
            let (db, work) = setup();
            for i in 0..crash_after {
                let checkpoint = format!("c{i}");
                apply_unrestricted(
                    &db,
                    request(
                        &work,
                        &checkpoint,
                        vec![edit(&format!("rec-{i}"), &i.to_string())],
                    ),
                    "alice",
                    1_000 + i as i64,
                )
                .unwrap();
            }
            for i in 0..n {
                let checkpoint = format!("c{i}");
                let receipt = apply_unrestricted(
                    &db,
                    request(
                        &work,
                        &checkpoint,
                        vec![edit(&format!("rec-{i}"), &i.to_string())],
                    ),
                    "alice",
                    1_000 + i as i64,
                )
                .unwrap();
                assert_eq!(receipt.replay, i < crash_after);
                assert_eq!(receipt.objects.len(), 1);
                assert_eq!(receipt.objects[0].object_id, format!("rec-{i}"));
                assert_eq!(receipt.transform_version, work.definition_digest);
            }
            assert_eq!(object_snapshot(&db), expected);
        }
    }

    #[test]
    fn duplicate_worker_with_older_generation_is_fenced() {
        let (db, work) = setup();
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let mut stale = request(&work, "c1", vec![edit("rec-1", "1")]);
        stale.claim_generation = work.claim_generation.saturating_sub(1);
        let error = apply_unrestricted(&db, stale, "alice", 50).unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::FailedPrecondition(message) if message == STALE_TRANSFORM_CLAIM
        ));
        assert_eq!(object_snapshot(&db).len(), 1);
        assert!(db.get_object("rec-1").unwrap().is_none());
    }

    #[test]
    fn action_policy_deny_writes_nothing() {
        let (db, work) = setup();
        let mut policy = ActionPolicy::allow_all("ops");
        policy.default_decision = ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let error = apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("action policy denied")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn require_approval_is_refused() {
        let (db, work) = setup();
        let mut policy = ActionPolicy::allow_all("ops");
        policy
            .action_overrides
            .insert(SUBMIT_POLICY_ACTION.into(), ActionDecision::RequireApproval);
        db.upsert_action_policy(&policy).unwrap();
        let error = apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("require_approval")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn reclaim_replays_original_receipt_without_rewriting() {
        let (db, work) = setup();
        let first = apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        assert!(!first.replay);
        let (reclaimed, _) = db
            .claim_transform_work("ops", "runner-b", &work.run_id, 60_000, 70_000)
            .unwrap()
            .expect("reclaim after lease expiry");
        assert!(reclaimed.claim_generation > work.claim_generation);
        let replay = apply_unrestricted(
            &db,
            request(&reclaimed, "c0", vec![edit("rec-0", "changed")]),
            "alice",
            80_000,
        )
        .unwrap();
        assert!(replay.replay);
        assert_eq!(replay.objects, first.objects);
        assert_eq!(replay.claim_generation, first.claim_generation);
        let stored = db.get_object("rec-0").unwrap().expect("created once");
        assert_eq!(stored.properties.get("n").map(String::as_str), Some("0"));
        assert_eq!(object_snapshot(&db).len(), 1);
    }

    #[test]
    fn properties_cannot_retarget_object_id() {
        let (db, work) = setup();
        let mut hijack = edit("rec-0", "0");
        hijack
            .properties
            .insert("object_id".into(), "secret".into());
        let error =
            apply_unrestricted(&db, request(&work, "c0", vec![hijack]), "alice", 40).unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::InvalidArgument(message) if message.contains("reserved")
        ));
        assert!(db.get_object("secret").unwrap().is_none());
        assert!(db.get_object("rec-0").unwrap().is_none());
    }

    #[test]
    fn duplicate_object_id_in_batch_is_rejected() {
        let (db, work) = setup();
        let error = apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0"), edit("rec-0", "1")]),
            "alice",
            40,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::InvalidArgument(message) if message.contains("duplicate")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn object_authorize_deny_writes_nothing() {
        let (db, work) = setup();
        let error = apply(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            40,
            StreamingApplyAuth {
                actor: "alice",
                tenant: "",
                resource_tenant: "",
                delegating_actor: None,
                machine_credential: false,
                policy_context: None,
            },
            |_, _, _| {
                Err(StreamingApplyError::PermissionDenied(
                    "access denied".into(),
                ))
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message) if message == "access denied"
        ));
        assert!(object_snapshot(&db).is_empty());
        assert!(
            db.peek_streaming_transform_apply(
                &work.run_id,
                &work.claim_owner,
                work.claim_generation,
                &work.fencing_token,
                "c0",
                40,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn resource_tenant_freeze_blocks_apply() {
        let (db, work) = setup();
        db.set_write_freeze(&write_freeze::WriteFreeze {
            scope_kind: write_freeze::SCOPE_TENANT.into(),
            scope_value: "owner-tenant".into(),
            mode: write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "owner freeze".into(),
            enabled: true,
            updated_ms: 10,
        })
        .unwrap();
        let error = apply(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            40,
            StreamingApplyAuth {
                actor: "alice",
                tenant: "acting-tenant",
                resource_tenant: "owner-tenant",
                delegating_actor: None,
                machine_credential: false,
                policy_context: None,
            },
            |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("write freeze") && message.contains("owner-tenant")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn submission_criterion_fail_writes_nothing() {
        let (db, work) = setup();
        let mut typed = create_type();
        typed.version = "2".into();
        typed.submission_criteria = vec![
            crate::sekai::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "needs-scope".into(),
                kind: crate::sekai::action_type_criteria::CRITERION_KIND_REQUIRED_SCOPE_EQUALS
                    .into(),
                property: String::new(),
                value: "ops.stream".into(),
            },
        ];
        db.put_governed_action_type(typed, "alice", 6).unwrap();
        let mut gated = request(&work, "c0", vec![edit("rec-0", "0")]);
        gated.action_type_version = "2".into();
        let error = apply_unrestricted(&db, gated, "alice", 40).unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("needs-scope")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn committed_checkpoint_replays_after_action_type_disabled() {
        let (db, work) = setup();
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let mut disabled = create_type();
        disabled.enabled = false;
        db.put_governed_action_type(disabled, "alice", 6).unwrap();
        let replay = apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "changed")]),
            "alice",
            50,
        )
        .unwrap();
        assert!(replay.replay);
        let stored = db.get_object("rec-0").unwrap().expect("created once");
        assert_eq!(stored.properties.get("n").map(String::as_str), Some("0"));
    }

    fn claimed_batch(
        work: &crate::sekai::governed_transform::TransformWork,
        checkpoint: &str,
        edits: Vec<PlannedStreamingEdit>,
    ) -> StreamingTransformApplyBatch {
        StreamingTransformApplyBatch {
            run_id: work.run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
            checkpoint: checkpoint.into(),
            input_positions: Vec::new(),
            edits,
            transform_version: work.definition_digest.clone(),
            action_type_id: "stream.record.create".into(),
            action_type_version: "1".into(),
            policy_generation: "legacy".into(),
        }
    }

    #[test]
    fn stale_update_plan_fails_closed() {
        let (db, work) = setup();
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let original = db.get_object("rec-0").unwrap().expect("created");
        let mut changed = original.clone();
        changed.properties.insert("n".into(), "hijack".into());
        changed.updated = 99;
        db.update_object(&changed).unwrap();
        let mut planned = original.clone();
        planned.properties.insert("n".into(), "from-batch".into());
        planned.updated = 50;
        let error = db
            .apply_streaming_transform_batch(
                claimed_batch(
                    &work,
                    "c1",
                    vec![PlannedStreamingEdit {
                        create: false,
                        object: planned,
                        expected: Some(original),
                    }],
                ),
                "alice",
                50,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::FailedPrecondition(message)
                if message == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION
        ));
        let stored = db
            .get_object("rec-0")
            .unwrap()
            .expect("kept concurrent write");
        assert_eq!(
            stored.properties.get("n").map(String::as_str),
            Some("hijack")
        );
        assert!(
            db.peek_streaming_transform_apply(
                &work.run_id,
                &work.claim_owner,
                work.claim_generation,
                &work.fencing_token,
                "c1",
                50,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn missing_update_target_fails_closed() {
        let (db, work) = setup();
        let ghost = crate::domain::Object {
            id: "ghost".into(),
            kind: "stream_record".into(),
            name: "ghost".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::from([("n".into(), "1".into())]),
            created: 40,
            updated: 50,
        };
        let error = db
            .apply_streaming_transform_batch(
                claimed_batch(
                    &work,
                    "c1",
                    vec![PlannedStreamingEdit {
                        create: false,
                        object: ghost.clone(),
                        expected: Some(ghost),
                    }],
                ),
                "alice",
                50,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::FailedPrecondition(message) if message.contains("not found")
        ));
        assert!(
            db.peek_streaming_transform_apply(
                &work.run_id,
                &work.claim_owner,
                work.claim_generation,
                &work.fencing_token,
                "c1",
                50,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn autonomous_action_type_is_refused() {
        let (db, work) = setup();
        let mut autonomous = create_type();
        autonomous.type_id = "autonomous.stream.create".into();
        db.put_governed_action_type(autonomous, "alice", 6).unwrap();
        let mut request = request(&work, "c-auto", vec![edit("rec-auto", "1")]);
        request.action_type_id = "autonomous.stream.create".into();
        let error = apply_unrestricted(&db, request, "alice", 50).unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("autonomous")
        ));
        assert!(object_snapshot(&db).is_empty());
        assert!(
            db.peek_streaming_transform_apply(
                &work.run_id,
                &work.claim_owner,
                work.claim_generation,
                &work.fencing_token,
                "c-auto",
                50,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn opaque_checkpoints_are_not_trimmed() {
        let (db, work) = setup();
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let padded = apply_unrestricted(
            &db,
            request(&work, " c0", vec![edit("rec-pad", "1")]),
            "alice",
            50,
        )
        .unwrap();
        assert!(!padded.replay);
        assert_eq!(padded.checkpoint, " c0");
        assert_eq!(
            object_snapshot(&db),
            vec![
                ("rec-0".into(), "0".into(), 40),
                ("rec-pad".into(), "1".into(), 50),
            ]
        );
    }

    #[test]
    fn propose_only_agent_is_refused() {
        let (db, work) = setup();
        let error = apply_unrestricted(
            &db,
            request(&work, "c-agent", vec![edit("rec-agent", "1")]),
            "agent:fixture",
            50,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::PermissionDenied(message)
                if message.contains("propose-only")
        ));
        assert!(object_snapshot(&db).is_empty());
    }

    #[test]
    fn integer_parameters_are_coerced_from_wire_strings() {
        let (db, work) = setup();
        let mut typed = create_type();
        typed.version = "3".into();
        typed.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"n":{"type":"integer"}},"required":["object_id","n"],"additionalProperties":false}"#.into();
        db.put_governed_action_type(typed, "alice", 6).unwrap();
        let mut typed_request = request(&work, "c-int", vec![edit("rec-int", "7")]);
        typed_request.action_type_version = "3".into();
        apply_unrestricted(&db, typed_request, "alice", 50).unwrap();
        assert_eq!(
            object_snapshot(&db),
            vec![("rec-int".into(), "7".into(), 50)]
        );
        let mut wide = request(&work, "c-u64", vec![edit("rec-u64", "9223372036854775808")]);
        wide.action_type_version = "3".into();
        apply_unrestricted(&db, wide, "alice", 51).unwrap();
        assert_eq!(
            db.get_object("rec-u64")
                .unwrap()
                .expect("created")
                .properties
                .get("n")
                .map(String::as_str),
            Some("9223372036854775808")
        );
        let mut bad = request(&work, "c-bad", vec![edit("rec-bad", "x")]);
        bad.action_type_version = "3".into();
        let error = apply_unrestricted(&db, bad, "alice", 60).unwrap_err();
        assert!(matches!(
            error,
            StreamingApplyError::InvalidArgument(message) if message.contains("integer")
        ));
        assert!(db.get_object("rec-bad").unwrap().is_none());
    }

    #[test]
    fn concurrent_same_checkpoint_replays_instead_of_failing_plan() {
        let (db, work) = setup();
        let db = std::sync::Arc::new(db);
        let request = request(&work, "c-race", vec![edit("rec-race", "1")]);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = [0, 1].map(|_| {
            let db = db.clone();
            let barrier = barrier.clone();
            let request = request.clone();
            std::thread::spawn(move || {
                barrier.wait();
                apply_unrestricted(&db, request, "alice", 50)
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap().expect("apply"));
        assert_eq!(outcomes[0].run_id, outcomes[1].run_id);
        assert_eq!(outcomes[0].checkpoint, outcomes[1].checkpoint);
        assert_eq!(outcomes[0].objects, outcomes[1].objects);
        assert_eq!(outcomes.iter().filter(|receipt| !receipt.replay).count(), 1);
        assert_eq!(
            object_snapshot(&db),
            vec![("rec-race".into(), "1".into(), 50)]
        );
    }

    #[test]
    fn admitted_marking_floor_stamps_create_when_worker_omits() {
        let (db, work) = setup_marked("confidential");
        let run = db
            .get_governed_transform_run(&work.run_id)
            .unwrap()
            .expect("run");
        assert_eq!(run.markings_out, "confidential");
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let stored = db.get_object("rec-0").unwrap().expect("created");
        assert_eq!(
            stored
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .map(String::as_str),
            Some("confidential")
        );
    }

    #[test]
    fn admitted_marking_floor_overrides_public_create() {
        let (db, work) = setup_marked("confidential");
        let mut typed = create_type();
        typed.version = "4".into();
        typed.parameter_schema_json = PARAM_SCHEMA_MARKED.into();
        db.put_governed_action_type(typed, "alice", 6).unwrap();
        let mut public = edit("rec-0", "0");
        public
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into());
        let mut marked_request = request(&work, "c0", vec![public]);
        marked_request.action_type_version = "4".into();
        apply_unrestricted(&db, marked_request, "alice", 40).unwrap();
        let stored = db.get_object("rec-0").unwrap().expect("created");
        assert_eq!(
            stored
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .map(String::as_str),
            Some("confidential")
        );
    }

    #[test]
    fn update_preserves_stricter_existing_marking() {
        let (db, work) = setup();
        apply_unrestricted(
            &db,
            request(&work, "c0", vec![edit("rec-0", "0")]),
            "alice",
            40,
        )
        .unwrap();
        let mut stored = db.get_object("rec-0").unwrap().expect("created");
        stored
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "confidential".into());
        db.update_object(&stored).unwrap();
        db.put_governed_action_type(update_type(), "alice", 6)
            .unwrap();
        let mut public = edit("rec-0", "1");
        public
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into());
        let mut update = request(&work, "c1", vec![public]);
        update.action_type_id = "stream.record.update".into();
        apply_unrestricted(&db, update, "alice", 50).unwrap();
        let stored = db.get_object("rec-0").unwrap().expect("updated");
        assert_eq!(stored.properties.get("n").map(String::as_str), Some("1"));
        assert_eq!(
            stored
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .map(String::as_str),
            Some("confidential")
        );
    }
}
