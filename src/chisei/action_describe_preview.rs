//! Observational object-bound Action describe and preview (#836).
//!
//! Chisei owns these projections so budget and policy stay on the decision
//! side. They never persist an ActionInstance, write an object, redeem a
//! permit, or become submit authority. `SubmitActionInstance` still owns
//! admission.

use crate::chisei::budget::BudgetTracker;
use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::facts::action::RiskClass;
use crate::sekai::facts::action_instance::{
    SUBMIT_POLICY_ACTION, compute_request_digest, submit_budget_subject, validate_parameters_json,
};
use crate::sekai::facts::action_object_mutation;
use crate::sekai::facts::action_policy::ActionDecision;
use crate::sekai::facts::action_type_criteria::{
    ActionSubmissionCriterion, CriterionDecision, evaluate_submission_criteria, invoker_context,
};
use crate::sekai::facts::governed_action_type::{GovernedActionType, OBJECT_MUTATION_UPDATE};
use crate::sekai::facts::object_security::PrincipalPolicyContext;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const COMPENSATION_UNSUPPORTED: &str = "unsupported";
pub const PREVIEW_VALID: &str = "valid";
pub const PREVIEW_INVALID: &str = "invalid";
pub const PREVIEW_DENIED: &str = "denied";
pub const PREVIEW_STALE: &str = "stale";
pub const PREVIEW_UNAVAILABLE: &str = "unavailable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectActionDescription {
    pub namespace: String,
    pub object_id: String,
    pub object_updated_ms: i64,
    pub object_revision: String,
    pub type_id: String,
    pub version: String,
    pub parameter_schema_json: String,
    pub allowed_effect_kinds: Vec<String>,
    pub object_kind: String,
    pub object_mutation: String,
    pub enabled: bool,
    pub preview_supported: bool,
    pub compensation: String,
    pub submission_criteria: Vec<ActionSubmissionCriterion>,
    pub declared_effect_kinds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectActionPreviewRequest<'a> {
    pub actor: &'a str,
    pub object: &'a Object,
    pub type_id: &'a str,
    pub version: &'a str,
    pub parameters_json: &'a str,
    pub expected_object_updated_ms: i64,
    pub expected_object_revision: &'a str,
    pub evidence_submission_ids: &'a [String],
    pub policy_context: Option<&'a PrincipalPolicyContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectActionPreview {
    pub outcome: String,
    pub reason_code: String,
    pub request_digest: String,
    pub object_revision: String,
    pub object_updated_ms: i64,
    pub type_id: String,
    pub version: String,
    pub policy_decision: String,
    pub budget_decision: String,
    pub approval_state: String,
    pub compensation: String,
    pub failing_criterion: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectActionProjectionError {
    Unavailable,
    InvalidArgument(String),
}

pub fn object_revision(object: &Object) -> String {
    let mut properties = object
        .properties
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    properties.insert("_name".into(), object.name.clone());
    properties.insert("_external_id".into(), object.external_id.clone());
    let mut hasher = Sha256::new();
    hasher.update(object.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(object.kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(object.namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(object.updated.to_le_bytes());
    for (key, value) in properties {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn describe_object_action(
    db: &RuntimeDb,
    object: &Object,
    type_id: &str,
    version: &str,
) -> Result<ObjectActionDescription, ObjectActionProjectionError> {
    let type_def = load_object_bound_type(db, object, type_id, version)?;
    Ok(description_from(object, &type_def))
}

pub fn preview_object_action(
    db: &RuntimeDb,
    budget: Option<&BudgetTracker>,
    request: ObjectActionPreviewRequest<'_>,
) -> Result<ObjectActionPreview, ObjectActionProjectionError> {
    let ObjectActionPreviewRequest {
        actor,
        object,
        type_id,
        version,
        parameters_json,
        expected_object_updated_ms,
        expected_object_revision,
        evidence_submission_ids,
        policy_context,
    } = request;
    let type_def = match load_object_bound_type(db, object, type_id, version) {
        Ok(type_def) => type_def,
        Err(ObjectActionProjectionError::Unavailable) => {
            return Ok(unavailable_preview(object));
        }
        Err(error) => return Err(error),
    };
    let live_revision = object_revision(object);
    if (expected_object_updated_ms != 0 && expected_object_updated_ms != object.updated)
        || (!expected_object_revision.trim().is_empty()
            && expected_object_revision != live_revision)
    {
        return Ok(ObjectActionPreview {
            outcome: PREVIEW_STALE.into(),
            reason_code: "stale".into(),
            request_digest: String::new(),
            object_revision: live_revision,
            object_updated_ms: object.updated,
            type_id: type_def.type_id.clone(),
            version: type_def.version.clone(),
            policy_decision: String::new(),
            budget_decision: String::new(),
            approval_state: String::new(),
            compensation: COMPENSATION_UNSUPPORTED.into(),
            failing_criterion: String::new(),
        });
    }

    if let Err(error) = validate_parameters_json(parameters_json) {
        return Ok(invalid_preview(&type_def, object, &live_revision, error));
    }
    let object_id = parameter_object_id(parameters_json).unwrap_or_default();
    if object_id != object.id {
        return Ok(invalid_preview(
            &type_def,
            object,
            &live_revision,
            "parameters_json.object_id must match the described object".into(),
        ));
    }
    if let Err(error) =
        crate::chisei::evaluation_plan::validate_parameter_schema(&type_def.parameter_schema_json)
    {
        return Ok(invalid_preview(
            &type_def,
            object,
            &live_revision,
            format!("governed action type parameter schema invalid: {error}"),
        ));
    }
    if let Err(error) = crate::chisei::evaluation_plan::validate_parameters(
        &type_def.parameter_schema_json,
        parameters_json,
    ) {
        return Ok(invalid_preview(
            &type_def,
            object,
            &live_revision,
            format!("action parameters invalid: {error}"),
        ));
    }

    let request_digest = compute_request_digest(
        &object.namespace,
        &type_def.type_id,
        &type_def.version,
        parameters_json,
        evidence_submission_ids,
    )
    .map_err(ObjectActionProjectionError::InvalidArgument)?;

    if let Err(error) =
        action_object_mutation::plan(db, &type_def, &object.namespace, parameters_json)
    {
        return Ok(invalid_preview(
            &type_def,
            object,
            &live_revision,
            error.to_string(),
        ));
    }

    let stored_object = db
        .get_object(&object.id)
        .map_err(|_| ObjectActionProjectionError::Unavailable)?;
    let bound_object = stored_object.as_ref().unwrap_or(object);
    let policy = match db.active_object_policy(&bound_object.namespace, &bound_object.kind) {
        Ok(policy) => policy,
        Err(_) => return Ok(unavailable_preview(object)),
    };
    let invoker = invoker_context(actor, policy_context);
    match evaluate_submission_criteria(
        &type_def.submission_criteria,
        Some(bound_object),
        policy.as_ref(),
        &invoker,
    ) {
        CriterionDecision::Pass => {}
        CriterionDecision::Fail { criterion_id } => {
            return Ok(criterion_preview(
                &type_def,
                object,
                &live_revision,
                criterion_id,
            ));
        }
        CriterionDecision::Unavailable => return Ok(unavailable_preview(object)),
    }

    let policy_project = if type_def.policy_scope.trim().is_empty() {
        object.namespace.clone()
    } else {
        type_def.policy_scope.clone()
    };
    let resolved_policy = db
        .resolve_action_policy(actor, &object.namespace, &policy_project)
        .map_err(|_| ObjectActionProjectionError::Unavailable)?;
    let (policy_decision, approval_state) = match &resolved_policy {
        Some(policy) => match policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write) {
            ActionDecision::Allow => ("allow".to_string(), "none".to_string()),
            ActionDecision::Deny => ("deny".to_string(), "none".to_string()),
            ActionDecision::RequireApproval => {
                ("require_approval".to_string(), "required".to_string())
            }
        },
        None => ("allow".to_string(), "none".to_string()),
    };

    let budget_subject = submit_budget_subject(&object.namespace, actor, &type_def.budget_scope);
    let budget_decision = if let Some(budget) = budget {
        if budget.check(&budget_subject, 1).is_err() {
            "budget_exceeded".to_string()
        } else {
            "allow".to_string()
        }
    } else {
        "not_configured".to_string()
    };

    let denied = policy_decision == "deny"
        || policy_decision == "require_approval"
        || budget_decision == "budget_exceeded";
    Ok(ObjectActionPreview {
        outcome: if denied {
            PREVIEW_DENIED.into()
        } else {
            PREVIEW_VALID.into()
        },
        reason_code: if denied {
            if budget_decision == "budget_exceeded" {
                "budget_exceeded".into()
            } else {
                policy_decision.clone()
            }
        } else {
            "valid".into()
        },
        request_digest,
        object_revision: live_revision,
        object_updated_ms: object.updated,
        type_id: type_def.type_id,
        version: type_def.version,
        policy_decision,
        budget_decision,
        approval_state,
        compensation: COMPENSATION_UNSUPPORTED.into(),
        failing_criterion: String::new(),
    })
}

fn load_object_bound_type(
    db: &RuntimeDb,
    object: &Object,
    type_id: &str,
    version: &str,
) -> Result<GovernedActionType, ObjectActionProjectionError> {
    let type_id = type_id.trim();
    let version = version.trim();
    if type_id.is_empty() || version.is_empty() {
        return Err(ObjectActionProjectionError::InvalidArgument(
            "type_id and version are required".into(),
        ));
    }
    let Some(type_def) = db
        .get_governed_action_type(&object.namespace, type_id, version)
        .map_err(|_| ObjectActionProjectionError::Unavailable)?
    else {
        return Err(ObjectActionProjectionError::Unavailable);
    };
    if !type_def.enabled
        || type_def.object_mutation != OBJECT_MUTATION_UPDATE
        || type_def.object_kind != object.kind
    {
        return Err(ObjectActionProjectionError::Unavailable);
    }
    Ok(type_def)
}

fn description_from(object: &Object, type_def: &GovernedActionType) -> ObjectActionDescription {
    ObjectActionDescription {
        namespace: object.namespace.clone(),
        object_id: object.id.clone(),
        object_updated_ms: object.updated,
        object_revision: object_revision(object),
        type_id: type_def.type_id.clone(),
        version: type_def.version.clone(),
        parameter_schema_json: type_def.parameter_schema_json.clone(),
        allowed_effect_kinds: type_def.allowed_effect_kinds.clone(),
        object_kind: type_def.object_kind.clone(),
        object_mutation: type_def.object_mutation.clone(),
        enabled: type_def.enabled,
        preview_supported: true,
        compensation: COMPENSATION_UNSUPPORTED.into(),
        submission_criteria: type_def.submission_criteria.clone(),
        declared_effect_kinds: type_def.declared_effect_kinds.clone(),
    }
}

fn unavailable_preview(object: &Object) -> ObjectActionPreview {
    ObjectActionPreview {
        outcome: PREVIEW_UNAVAILABLE.into(),
        reason_code: "unavailable".into(),
        request_digest: String::new(),
        object_revision: String::new(),
        object_updated_ms: object.updated,
        type_id: String::new(),
        version: String::new(),
        policy_decision: String::new(),
        budget_decision: String::new(),
        approval_state: String::new(),
        compensation: COMPENSATION_UNSUPPORTED.into(),
        failing_criterion: String::new(),
    }
}

fn invalid_preview(
    type_def: &GovernedActionType,
    object: &Object,
    live_revision: &str,
    reason: String,
) -> ObjectActionPreview {
    ObjectActionPreview {
        outcome: PREVIEW_INVALID.into(),
        reason_code: reason,
        request_digest: String::new(),
        object_revision: live_revision.to_string(),
        object_updated_ms: object.updated,
        type_id: type_def.type_id.clone(),
        version: type_def.version.clone(),
        policy_decision: String::new(),
        budget_decision: String::new(),
        approval_state: String::new(),
        compensation: COMPENSATION_UNSUPPORTED.into(),
        failing_criterion: String::new(),
    }
}

fn criterion_preview(
    type_def: &GovernedActionType,
    object: &Object,
    live_revision: &str,
    criterion_id: String,
) -> ObjectActionPreview {
    ObjectActionPreview {
        outcome: PREVIEW_INVALID.into(),
        reason_code: criterion_id.clone(),
        request_digest: String::new(),
        object_revision: live_revision.to_string(),
        object_updated_ms: object.updated,
        type_id: type_def.type_id.clone(),
        version: type_def.version.clone(),
        policy_decision: String::new(),
        budget_decision: String::new(),
        approval_state: String::new(),
        compensation: COMPENSATION_UNSUPPORTED.into(),
        failing_criterion: criterion_id,
    }
}

fn parameter_object_id(parameters_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()?
        .get("object_id")?
        .as_str()
        .map(str::to_string)
}

impl std::fmt::Display for action_object_mutation::ActionObjectMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message)
            | Self::FailedPrecondition(message)
            | Self::Internal(message) => f.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::facts::governed_action_type::GovernedActionType;
    use std::collections::HashMap;

    fn object() -> Object {
        Object {
            id: "cust-1".into(),
            kind: "customer_record".into(),
            name: "Northwind".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: HashMap::from([("title".into(), "account".into())]),
            created: 10,
            updated: 20,
        }
    }

    fn update_type() -> GovernedActionType {
        GovernedActionType {
            namespace: "acme".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
            description: "Update one customer".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            ..Default::default()
        }
    }

    fn setup() -> (RuntimeDb, Object) {
        let db = RuntimeDb::memory();
        db.upsert_object_type(&crate::sekai::facts::schema::ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        let object = object();
        db.create_object(&object).unwrap();
        db.put_governed_action_type(update_type(), "operator", 1)
            .unwrap();
        (db, object)
    }

    #[test]
    fn describe_is_stable_for_the_same_object_and_type() {
        let (db, object) = setup();
        let first = describe_object_action(&db, &object, "customer.record.update", "1").unwrap();
        let second = describe_object_action(&db, &object, "customer.record.update", "1").unwrap();
        assert_eq!(first, second);
        assert!(first.preview_supported);
        assert_eq!(first.compensation, COMPENSATION_UNSUPPORTED);
        assert_eq!(first.object_revision, object_revision(&object));
    }

    #[test]
    fn describe_hides_kind_mismatch_and_disabled_types() {
        let (db, object) = setup();
        assert_eq!(
            describe_object_action(&db, &object, "missing", "1").unwrap_err(),
            ObjectActionProjectionError::Unavailable
        );
        db.set_governed_action_type_enabled("acme", "customer.record.update", "1", false, 2)
            .unwrap();
        assert_eq!(
            describe_object_action(&db, &object, "customer.record.update", "1").unwrap_err(),
            ObjectActionProjectionError::Unavailable
        );
    }

    #[test]
    fn preview_validates_without_writing() {
        let (db, object) = setup();
        let preview = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "1",
                parameters_json: r#"{"object_id":"cust-1","name":"Updated"}"#,
                expected_object_updated_ms: object.updated,
                expected_object_revision: &object_revision(&object),
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(preview.outcome, PREVIEW_VALID);
        assert!(!preview.request_digest.is_empty());
        assert_eq!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            db.get_object("cust-1").unwrap().unwrap().properties["title"],
            "account"
        );
    }

    #[test]
    fn stale_and_changed_parameters_fail_closed() {
        let (db, object) = setup();
        let stale = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "1",
                parameters_json: r#"{"object_id":"cust-1"}"#,
                expected_object_updated_ms: object.updated + 1,
                expected_object_revision: "",
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(stale.outcome, PREVIEW_STALE);
        let invalid = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "1",
                parameters_json: r#"{"object_id":"other"}"#,
                expected_object_updated_ms: object.updated,
                expected_object_revision: "",
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(invalid.outcome, PREVIEW_INVALID);
        let unknown = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "1",
                parameters_json: r#"{"object_id":"cust-1","extra":true}"#,
                expected_object_updated_ms: object.updated,
                expected_object_revision: "",
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(unknown.outcome, PREVIEW_INVALID);
    }

    #[test]
    fn preview_names_a_failing_visible_criterion() {
        let (db, mut object) = setup();
        object.properties.insert("state".into(), "draft".into());
        db.update_object(&object).unwrap();
        let mut type_def = update_type();
        type_def.version = "2".into();
        type_def.submission_criteria = vec![
            crate::sekai::facts::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "ready_for_review".into(),
                kind: crate::sekai::facts::action_type_criteria::CRITERION_KIND_PROPERTY_EQUALS
                    .into(),
                property: "state".into(),
                value: "ready".into(),
            },
        ];
        db.put_governed_action_type(type_def, "operator", 2)
            .unwrap();
        let preview = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "2",
                parameters_json: r#"{"object_id":"cust-1"}"#,
                expected_object_updated_ms: object.updated,
                expected_object_revision: "",
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(preview.outcome, PREVIEW_INVALID);
        assert_eq!(preview.reason_code, "ready_for_review");
        assert_eq!(preview.failing_criterion, "ready_for_review");
    }

    #[test]
    fn preview_hides_ungranted_criterion_properties() {
        use crate::sekai::facts::object_security::{
            OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
            ObjectSecurityPredicate, ObjectSecurityRule, PropertyGrant, PropertyGrantAccess,
        };
        use std::collections::BTreeMap;

        let (db, mut object) = setup();
        object.properties.insert("secret".into(), "yes".into());
        db.update_object(&object).unwrap();
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "customer_record".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-hidden-criterion", 3)
            .unwrap();
        db.activate_object_security_policies(
            "acme",
            &BTreeMap::from([("customer_record".into(), revision.revision_digest)]),
            "root",
            "activate-hidden-criterion",
            4,
        )
        .unwrap();
        let mut type_def = update_type();
        type_def.version = "3".into();
        type_def.submission_criteria = vec![
            crate::sekai::facts::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "has_clearance".into(),
                kind: crate::sekai::facts::action_type_criteria::CRITERION_KIND_PROPERTY_EQUALS
                    .into(),
                property: "secret".into(),
                value: "yes".into(),
            },
        ];
        db.put_governed_action_type(type_def, "operator", 5)
            .unwrap();
        let preview = preview_object_action(
            &db,
            None,
            ObjectActionPreviewRequest {
                actor: "alice",
                object: &object,
                type_id: "customer.record.update",
                version: "3",
                parameters_json: r#"{"object_id":"cust-1"}"#,
                expected_object_updated_ms: object.updated,
                expected_object_revision: "",
                evidence_submission_ids: &[],
                policy_context: None,
            },
        )
        .unwrap();
        assert_eq!(preview.outcome, PREVIEW_UNAVAILABLE);
        assert_eq!(preview.reason_code, "unavailable");
        assert!(preview.failing_criterion.is_empty());
        assert!(!preview.reason_code.contains("secret"));
        assert!(!format!("{preview:?}").contains("has_clearance"));
    }
}
