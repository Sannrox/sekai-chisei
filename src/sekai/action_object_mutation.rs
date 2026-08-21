//! One in-plane object create or update bound to a governed Action type.
//!
//! This is not an effect kind and not a graph-mutation language. A type may
//! bind one admitted kind and apply exactly one create or update through the
//! existing object persistence seam.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{KIND_CAPABILITY, KIND_EXTERNAL_EVIDENCE, Object, is_valid_property_key};
use crate::sekai::action_policy::{ACTION_POLICY_KIND, BLAST_RADIUS_KIND};
use crate::sekai::governed_action_type::{
    GovernedActionType, OBJECT_MUTATION_CREATE, OBJECT_MUTATION_UPDATE,
};
use crate::sekai::governed_facts;
use crate::sekai::markings::PRINCIPAL_PROFILE_KIND;
use crate::sekai::schema::SchemaRegistry;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionObjectMutationError {
    InvalidArgument(String),
    FailedPrecondition(String),
    Internal(String),
}

const PARAM_OBJECT_ID: &str = "object_id";
const PARAM_NAME: &str = "name";
const PARAM_NOTIFY_DELIVERY: &str = "notify_delivery";

const RESERVED_OBJECT_KINDS: &[&str] = &[
    "namespace",
    PRINCIPAL_PROFILE_KIND,
    ACTION_POLICY_KIND,
    BLAST_RADIUS_KIND,
    "action_approval",
    KIND_CAPABILITY,
    KIND_EXTERNAL_EVIDENCE,
    governed_facts::PROFILE_KIND,
    governed_facts::FACT_KIND,
    governed_facts::WAIVER_KIND,
];

#[derive(Debug, Clone)]
pub(crate) struct AppliedObjectMutation {
    pub object_id: String,
    pub object_kind: String,
    pub mutation: String,
    pub created: bool,
    previous: Option<Object>,
    applied_updated: i64,
}

#[derive(Debug, Clone)]
pub(crate) enum PlannedObjectMutation {
    Create(Object),
    Update(Object),
}

impl PlannedObjectMutation {
    fn mutation(&self) -> &'static str {
        match self {
            Self::Create(_) => OBJECT_MUTATION_CREATE,
            Self::Update(_) => OBJECT_MUTATION_UPDATE,
        }
    }
}

pub(crate) fn plan(
    db: &RuntimeDb,
    type_def: &GovernedActionType,
    namespace: &str,
    parameters_json: &str,
) -> Result<Option<PlannedObjectMutation>, ActionObjectMutationError> {
    let object_kind = type_def.object_kind.trim();
    let mutation = type_def.object_mutation.trim();
    if object_kind.is_empty() && mutation.is_empty() {
        return Ok(None);
    }
    if RESERVED_OBJECT_KINDS.contains(&object_kind) {
        return Err(ActionObjectMutationError::FailedPrecondition(format!(
            "object_kind {object_kind:?} is reserved"
        )));
    }
    if db
        .get_object_type(object_kind)
        .map_err(ActionObjectMutationError::Internal)?
        .is_none()
    {
        return Err(ActionObjectMutationError::FailedPrecondition(format!(
            "unknown object kind {object_kind}; admit the kind before submit"
        )));
    }

    let parameters: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|error| ActionObjectMutationError::InvalidArgument(error.to_string()))?;
    let object_id = parameters
        .get(PARAM_OBJECT_ID)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ActionObjectMutationError::InvalidArgument("object_id parameter required".into())
        })?;
    if object_id.is_empty() {
        return Err(ActionObjectMutationError::InvalidArgument(
            "object_id parameter required".into(),
        ));
    }
    if object_id.chars().any(char::is_whitespace) {
        return Err(ActionObjectMutationError::InvalidArgument(
            "object_id must not contain whitespace".into(),
        ));
    }
    if object_id.starts_with("namespace:") {
        return Err(ActionObjectMutationError::InvalidArgument(
            "namespace:* identifiers are reserved for namespace boundaries".into(),
        ));
    }

    let name = parameters
        .get(PARAM_NAME)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(object_id)
        .to_string();
    let properties = object_properties(&parameters)?;
    let existing = db
        .get_object(object_id)
        .map_err(ActionObjectMutationError::Internal)?;

    match mutation {
        OBJECT_MUTATION_CREATE => {
            if existing.is_some() {
                return Err(ActionObjectMutationError::FailedPrecondition(format!(
                    "object {object_id} already exists"
                )));
            }
            let planned = Object {
                id: object_id.to_string(),
                kind: object_kind.to_string(),
                name,
                namespace: namespace.to_string(),
                external_id: String::new(),
                properties,
                created: 0,
                updated: 0,
            };
            validate_object_schema(db, &planned)?;
            Ok(Some(PlannedObjectMutation::Create(planned)))
        }
        OBJECT_MUTATION_UPDATE => {
            let existing = existing.ok_or_else(|| {
                ActionObjectMutationError::FailedPrecondition(format!(
                    "object {object_id} not found"
                ))
            })?;
            if existing.kind != object_kind {
                return Err(ActionObjectMutationError::FailedPrecondition(format!(
                    "object {object_id} kind {} does not match {object_kind}",
                    existing.kind
                )));
            }
            if existing.namespace != namespace {
                return Err(ActionObjectMutationError::FailedPrecondition(format!(
                    "object {object_id} is not in namespace {namespace}"
                )));
            }
            let mut merged = existing.properties;
            merged.extend(properties);
            let planned = Object {
                id: existing.id,
                kind: existing.kind,
                name: if parameters.get(PARAM_NAME).is_some() {
                    name
                } else {
                    existing.name
                },
                namespace: existing.namespace,
                external_id: existing.external_id,
                properties: merged,
                created: existing.created,
                updated: existing.updated,
            };
            validate_object_schema(db, &planned)?;
            Ok(Some(PlannedObjectMutation::Update(planned)))
        }
        other => Err(ActionObjectMutationError::FailedPrecondition(format!(
            "unknown object_mutation {other:?}"
        ))),
    }
}

pub(crate) fn apply(
    db: &RuntimeDb,
    planned: PlannedObjectMutation,
    actor: &str,
    now_ms: i64,
) -> Result<AppliedObjectMutation, ActionObjectMutationError> {
    let mutation = planned.mutation().to_string();
    let mut object = match planned {
        PlannedObjectMutation::Create(object) => object,
        PlannedObjectMutation::Update(object) => object,
    };
    let created = mutation == OBJECT_MUTATION_CREATE;
    if created {
        object.created = now_ms;
    }
    object.updated = now_ms;
    let object_id = object.id.clone();
    let object_kind = object.kind.clone();
    let previous = if created {
        db.create_object_with_audit(&object, actor)
            .map_err(ActionObjectMutationError::Internal)?;
        None
    } else {
        Some(
            db.update_object_with_audit(&object, actor)
                .map_err(ActionObjectMutationError::Internal)?
                .ok_or_else(|| {
                    ActionObjectMutationError::FailedPrecondition(format!(
                        "object {object_id} not found"
                    ))
                })?,
        )
    };
    Ok(AppliedObjectMutation {
        object_id,
        object_kind,
        mutation,
        created,
        previous,
        applied_updated: object.updated,
    })
}

pub(crate) fn compensate(db: &RuntimeDb, applied: &AppliedObjectMutation, actor: &str) {
    if applied.created {
        // Only abort the original create. If another writer already mutated
        // the row, leave it rather than deleting committed follow-on history.
        if let Ok(Some(current)) = db.get_object(&applied.object_id)
            && current.kind == applied.object_kind
            && current.created == current.updated
        {
            let _ = db.abort_unreceipted_object_create(&applied.object_id);
        }
        return;
    }
    let Some(mut previous) = applied.previous.clone() else {
        return;
    };
    if let Ok(Some(current)) = db.get_object(&applied.object_id)
        && current.updated == applied.applied_updated
    {
        previous.updated = current.updated.saturating_add(1);
        let _ = db.update_object_with_audit(&previous, actor);
    }
}

fn validate_object_schema(
    db: &RuntimeDb,
    object: &Object,
) -> Result<(), ActionObjectMutationError> {
    let object_type = db
        .get_object_type(&object.kind)
        .map_err(ActionObjectMutationError::Internal)?
        .ok_or_else(|| {
            ActionObjectMutationError::FailedPrecondition(format!(
                "unknown object kind {}; admit the kind before submit",
                object.kind
            ))
        })?;
    let interfaces = db
        .list_interfaces()
        .map_err(ActionObjectMutationError::Internal)?;
    SchemaRegistry::from_types_and_interfaces(vec![object_type], interfaces)
        .validate(object)
        .map_err(ActionObjectMutationError::FailedPrecondition)
}

fn object_properties(
    parameters: &serde_json::Value,
) -> Result<HashMap<String, String>, ActionObjectMutationError> {
    let Some(object) = parameters.as_object() else {
        return Err(ActionObjectMutationError::InvalidArgument(
            "parameters_json must be a JSON object".into(),
        ));
    };
    let mut properties = HashMap::new();
    for (key, value) in object {
        if matches!(
            key.as_str(),
            PARAM_OBJECT_ID | PARAM_NAME | PARAM_NOTIFY_DELIVERY
        ) {
            continue;
        }
        if !is_valid_property_key(key) {
            return Err(ActionObjectMutationError::InvalidArgument(format!(
                "invalid object property key {key}"
            )));
        }
        let Some(stored) = property_value(value) else {
            return Err(ActionObjectMutationError::InvalidArgument(format!(
                "object property {key} must be a string, number, or boolean"
            )));
        };
        properties.insert(key.clone(), stored);
    }
    Ok(properties)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
    use crate::sekai::schema::{ObjectType, PropertyDef, PropertyType};

    #[test]
    fn object_id_whitespace_is_rejected() {
        let db = RuntimeDb::memory();
        db.upsert_object_type(&ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "create".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        let error = plan(&db, &type_def, "acme", r#"{"object_id":" rec-1 "}"#).unwrap_err();
        assert!(matches!(
            error,
            ActionObjectMutationError::InvalidArgument(_)
        ));
        assert!(db.get_object("rec-1").unwrap().is_none());
    }

    #[test]
    fn missing_required_kind_property_fails_closed() {
        let db = RuntimeDb::memory();
        db.upsert_object_type(&ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![PropertyDef {
                name: "city".into(),
                prop_type: PropertyType::String,
                required: true,
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
        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "create".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        let error = plan(&db, &type_def, "acme", r#"{"object_id":"rec-schema"}"#).unwrap_err();
        assert!(matches!(
            error,
            ActionObjectMutationError::FailedPrecondition(_)
        ));
        assert!(db.get_object("rec-schema").unwrap().is_none());
    }

    #[test]
    fn aborted_create_can_reuse_the_object_id() {
        let db = RuntimeDb::memory();
        db.upsert_object_type(&ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "create".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        let planned = plan(&db, &type_def, "acme", r#"{"object_id":"rec-abort"}"#)
            .unwrap()
            .expect("planned");
        let applied = apply(&db, planned, "alice", 10).unwrap();
        compensate(&db, &applied, "alice");
        let planned = plan(&db, &type_def, "acme", r#"{"object_id":"rec-abort"}"#)
            .unwrap()
            .expect("planned after abort");
        apply(&db, planned, "alice", 20).unwrap();
        assert_eq!(
            db.get_object("rec-abort").unwrap().unwrap().kind,
            "customer_record"
        );
    }

    #[test]
    fn aborted_update_restores_the_prior_record() {
        let db = RuntimeDb::memory();
        db.upsert_object_type(&ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        let create = GovernedActionType {
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "create".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"city":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        let planned = plan(
            &db,
            &create,
            "acme",
            r#"{"object_id":"rec-restore","city":"oslo"}"#,
        )
        .unwrap()
        .expect("planned");
        apply(&db, planned, "alice", 10).unwrap();
        let update = GovernedActionType {
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            type_id: "customer.record.update".into(),
            ..create
        };
        let planned = plan(
            &db,
            &update,
            "acme",
            r#"{"object_id":"rec-restore","city":"bergen"}"#,
        )
        .unwrap()
        .expect("planned");
        let applied = apply(&db, planned, "alice", 20).unwrap();
        assert_eq!(
            db.get_object("rec-restore")
                .unwrap()
                .unwrap()
                .properties
                .get("city")
                .map(String::as_str),
            Some("bergen")
        );
        compensate(&db, &applied, "alice");
        assert_eq!(
            db.get_object("rec-restore")
                .unwrap()
                .unwrap()
                .properties
                .get("city")
                .map(String::as_str),
            Some("oslo")
        );
    }
}

fn property_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}
