//! One in-plane object create or update bound to a governed Action type.
//!
//! This is not an effect kind and not a graph-mutation language. A type may
//! bind one admitted kind and apply exactly one create or update through the
//! existing object persistence seam.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{KIND_CAPABILITY, KIND_EXTERNAL_EVIDENCE, Object, is_valid_property_key};
use crate::sekai::action_policy::{ACTION_POLICY_KIND, BLAST_RADIUS_KIND};
use crate::sekai::feedback_package::KIND_OBSERVATION;
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

fn unique_constraint_failed(error: &str) -> bool {
    error.contains("UNIQUE constraint failed")
        || error.contains("duplicate key value violates unique constraint")
}

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
    crate::sekai::trust_score::TRUST_SCORING_RULE_KIND,
    crate::sekai::object_comment::OBJECT_COMMENT_KIND,
    crate::sekai::media_upload::MEDIA_KIND,
];

#[derive(Debug, Clone)]
pub(crate) struct AppliedObjectMutation {
    pub object_id: String,
    pub object_kind: String,
    pub mutation: String,
    pub created: bool,
    pub object: Object,
    previous: Option<Object>,
    applied_updated: i64,
}

#[derive(Debug, Clone)]
pub(crate) enum PlannedObjectMutation {
    Create(Object),
    /// The object to write and the object as planning read it; the write
    /// applies only if it is unchanged, so a concurrent change (a raised
    /// marking among them) is never overwritten by a stale plan.
    Update(Object, Box<Object>),
}

impl PlannedObjectMutation {
    fn mutation(&self) -> &'static str {
        match self {
            Self::Create(_) => OBJECT_MUTATION_CREATE,
            Self::Update(..) => OBJECT_MUTATION_UPDATE,
        }
    }
}

/// Plans the object an admitted Action writes. `submitter` is the principal
/// that submitted the instance, `None` where there is none (a streaming
/// transform). `marking` is the instance's
/// marking (#1706), `None` where no instance is admitted (previews,
/// transforms that stamp their own): the written object carries the least
/// upper bound of it, the object's current marking and any marking the
/// parameters set, so an Action can neither write below what it was derived
/// from nor lower an object's marking. An object now marked above the
/// instance changed after admission derived the marking, and is refused.
pub(crate) fn plan(
    db: &RuntimeDb,
    type_def: &GovernedActionType,
    namespace: &str,
    parameters_json: &str,
    submitter: Option<&str>,
    marking: Option<&str>,
    now_ms: i64,
) -> Result<Option<PlannedObjectMutation>, ActionObjectMutationError> {
    let object_kind = type_def.object_kind.trim();
    let mutation = type_def.object_mutation.trim();
    if object_kind.is_empty() && mutation.is_empty() {
        return Ok(None);
    }
    if object_kind == crate::sekai::catalog::CATALOG_ENTRY_KIND {
        return plan_catalog_curation(
            db,
            mutation,
            namespace,
            parameters_json,
            submitter,
            marking,
            now_ms,
        )
        .map(Some);
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
            let mut planned = Object {
                id: object_id.to_string(),
                kind: object_kind.to_string(),
                name,
                namespace: namespace.to_string(),
                external_id: String::new(),
                properties,
                created: 0,
                updated: 0,
            };
            inherit_marking(db, namespace, &mut planned, None, marking)?;
            validate_object_schema(db, &planned)?;
            validate_object_write(db, &mut planned, now_ms)?;
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
            let existing_marking =
                crate::sekai::markings::object_marking_token(&existing).map(str::to_string);
            let snapshot = Box::new(existing.clone());
            let mut merged = existing.properties;
            merged.extend(properties);
            let mut planned = Object {
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
            inherit_marking(
                db,
                namespace,
                &mut planned,
                existing_marking.as_deref(),
                marking,
            )?;
            validate_object_schema(db, &planned)?;
            validate_object_write(db, &mut planned, now_ms)?;
            Ok(Some(PlannedObjectMutation::Update(planned, snapshot)))
        }
        other => Err(ActionObjectMutationError::FailedPrecondition(format!(
            "unknown object_mutation {other:?}"
        ))),
    }
}

/// Catalog curation (#1686, ADR 0122): an Action may only update a catalog
/// entry's curated fields, submitted by an owner or the steward, and may
/// only raise its marking. Registration still writes everything else.
fn plan_catalog_curation(
    db: &RuntimeDb,
    mutation: &str,
    namespace: &str,
    parameters_json: &str,
    submitter: Option<&str>,
    marking: Option<&str>,
    now_ms: i64,
) -> Result<PlannedObjectMutation, ActionObjectMutationError> {
    use crate::sekai::catalog::{CatalogError, curate};
    if mutation != OBJECT_MUTATION_UPDATE {
        return Err(ActionObjectMutationError::FailedPrecondition(
            "catalog entries are registered, and Actions only curate them".into(),
        ));
    }
    let parameters: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|error| ActionObjectMutationError::InvalidArgument(error.to_string()))?;
    if parameters.get(PARAM_NAME).is_some() {
        return Err(ActionObjectMutationError::InvalidArgument(
            "a catalog entry's name comes from its source".into(),
        ));
    }
    let object_id = parameters
        .get(PARAM_OBJECT_ID)
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            ActionObjectMutationError::InvalidArgument("object_id parameter required".into())
        })?;
    let existing = db
        .get_object(object_id)
        .map_err(ActionObjectMutationError::Internal)?
        .filter(|object| {
            object.kind == crate::sekai::catalog::CATALOG_ENTRY_KIND
                && object.namespace == namespace
        })
        .ok_or_else(|| {
            ActionObjectMutationError::FailedPrecondition(format!(
                "catalog entry {object_id} not found in namespace {namespace}"
            ))
        })?;
    let lattice = db
        .get_classification_lattice(namespace)
        .map_err(ActionObjectMutationError::Internal)?;
    let edits = object_properties(&parameters)?;
    let mut planned = curate(
        &existing,
        submitter.unwrap_or_default(),
        edits,
        lattice.as_ref(),
    )
    .map_err(|error| match error {
        CatalogError::Invalid(message) => ActionObjectMutationError::InvalidArgument(message),
        CatalogError::Denied(message) => ActionObjectMutationError::FailedPrecondition(message),
        CatalogError::Storage(message) => ActionObjectMutationError::Internal(message),
        CatalogError::Conflict | CatalogError::Superseded => {
            ActionObjectMutationError::FailedPrecondition("catalog entry changed".into())
        }
    })?;
    // The admission check runs on the entry as stored: a curated raise is
    // above the instance's marking by design, and `curate` allowed it only
    // because it does not lower the stored one.
    let existing_marking =
        crate::sekai::markings::object_marking_token(&existing).map(str::to_string);
    let mut admitted = existing.clone();
    inherit_marking(
        db,
        namespace,
        &mut admitted,
        existing_marking.as_deref(),
        marking,
    )?;
    // The written entry carries at least what the Action was admitted under
    // (a binding may be marked above the entry), joined with the curated
    // marking.
    if let Some(joined) = crate::sekai::markings::object_marking_token(&admitted) {
        let joined = joined.to_string();
        let raised = crate::sekai::catalog::raised_marking(
            crate::sekai::markings::object_marking_token(&planned).unwrap_or_default(),
            &joined,
            lattice.as_ref(),
        )
        .map_err(|error| {
            ActionObjectMutationError::FailedPrecondition(format!("marking: {error:?}"))
        })?;
        planned.properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
            raised,
        );
    }
    validate_object_write(db, &mut planned, now_ms)?;
    Ok(PlannedObjectMutation::Update(planned, Box::new(existing)))
}

/// Applies an admitted Action's object write. Its change rows carry the
/// Action's attribution (operation, instance and receipt), so history links
/// to the operation by stored id.
pub(crate) fn apply(
    db: &RuntimeDb,
    planned: PlannedObjectMutation,
    actor: &str,
    attribution: &crate::sekai::audit::ChangeAttribution,
    now_ms: i64,
) -> Result<AppliedObjectMutation, ActionObjectMutationError> {
    let mutation = planned.mutation().to_string();
    let (mut object, snapshot) = match planned {
        PlannedObjectMutation::Create(object) => (object, None),
        PlannedObjectMutation::Update(object, snapshot) => (object, Some(snapshot)),
    };
    let created = mutation == OBJECT_MUTATION_CREATE;
    if created {
        object.created = now_ms;
    }
    object.updated = now_ms;
    let object_id = object.id.clone();
    let object_kind = object.kind.clone();
    let object_external_id = object.external_id.clone();
    let applied_updated = object.updated;
    let previous = if created {
        db.create_object_attributed(&object, actor, None, attribution)
            .map_err(|error| {
                if object_kind == KIND_OBSERVATION && unique_constraint_failed(&error) {
                    ActionObjectMutationError::FailedPrecondition(format!(
                        "observation external identity {object_external_id} already exists"
                    ))
                } else {
                    ActionObjectMutationError::Internal(error)
                }
            })?;
        None
    } else {
        Some(
            db.update_object_attributed(&object, snapshot.as_deref(), actor, None, attribution)
                .map_err(|error| {
                    if error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION {
                        ActionObjectMutationError::FailedPrecondition(format!(
                            "object {object_id} changed since the Action was planned; submit again"
                        ))
                    } else {
                        ActionObjectMutationError::Internal(error)
                    }
                })?
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
        object,
        previous,
        applied_updated,
    })
}

/// Outcome of committing a parked grant with its object write.
pub(crate) enum ParkedGrant {
    Granted(Option<Box<AppliedObjectMutation>>),
    NotParked,
    Stale,
}

/// Applies the planned write and moves the parked instance to `granted` in
/// one transaction, so a crash or a concurrent decision can never leave the
/// write without the grant (#1139).
pub(crate) fn grant_parked(
    db: &RuntimeDb,
    planned: Option<PlannedObjectMutation>,
    granted: &crate::sekai::action_instance::ActionInstance,
    target_object_id: &str,
    parked_object_digest: &str,
    actor: &str,
    now_ms: i64,
) -> Result<ParkedGrant, ActionObjectMutationError> {
    use crate::sekai::action_instance::{ParkedGrantOutcome, ParkedGrantWrite};
    let prepared = planned.map(|planned| {
        let mutation = planned.mutation().to_string();
        let created = mutation == OBJECT_MUTATION_CREATE;
        let mut object = match planned {
            PlannedObjectMutation::Create(object) | PlannedObjectMutation::Update(object, _) => {
                object
            }
        };
        if created {
            object.created = now_ms;
        }
        object.updated = now_ms;
        (mutation, created, object)
    });
    let write = prepared.as_ref().map(|(_, created, object)| {
        if *created {
            ParkedGrantWrite::Create(object.clone())
        } else {
            ParkedGrantWrite::Update(object.clone())
        }
    });
    let outcome = db
        .grant_parked_action_instance(
            granted,
            target_object_id,
            parked_object_digest,
            write.as_ref(),
            actor,
        )
        .map_err(ActionObjectMutationError::Internal)?;
    Ok(match outcome {
        ParkedGrantOutcome::NotParked => ParkedGrant::NotParked,
        ParkedGrantOutcome::Stale => ParkedGrant::Stale,
        ParkedGrantOutcome::Granted { previous } => {
            ParkedGrant::Granted(prepared.map(|(mutation, created, object)| {
                Box::new(AppliedObjectMutation {
                    object_id: object.id.clone(),
                    object_kind: object.kind.clone(),
                    mutation,
                    created,
                    applied_updated: object.updated,
                    object,
                    previous,
                })
            }))
        }
    })
}

fn validate_object_write(
    db: &RuntimeDb,
    planned: &mut Object,
    now_ms: i64,
) -> Result<(), ActionObjectMutationError> {
    crate::sekai::feedback_package::validate_object_write(db, planned, now_ms)
        .and_then(|()| crate::sekai::function_document::validate_lineage_write(db, planned, now_ms))
        .map_err(ActionObjectMutationError::FailedPrecondition)
}

/// Best-effort follow-up after an Action's object write is durable. Runs
/// again on admission replay, so each step must be idempotent.
pub(crate) fn complete_object_write(db: &RuntimeDb, object: &Object, actor: &str, now_ms: i64) {
    crate::sekai::feedback_package::complete_object_write(db, object, now_ms);
    let _ = crate::sekai::function_document::complete_lineage_write(db, actor, object, now_ms);
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

/// Stamps `object` with the least upper bound of its planned marking, the
/// marking it had before (`existing`) and the Action's. Unknown or
/// incomparable tokens refuse the write.
fn inherit_marking(
    db: &RuntimeDb,
    namespace: &str,
    object: &mut Object,
    existing: Option<&str>,
    instance_marking: Option<&str>,
) -> Result<(), ActionObjectMutationError> {
    let planned = crate::sekai::markings::object_marking_token(object).map(str::to_string);
    let marking = instance_marking.filter(|token| !token.trim().is_empty());
    if existing.is_none() && marking.is_none() {
        return Ok(());
    }
    let lattice = db
        .get_classification_lattice(namespace)
        .map_err(ActionObjectMutationError::Internal)?;
    let (_, joined) = crate::sekai::classification_lattice::union_input_marking_tokens(
        lattice.as_ref(),
        [planned.as_deref(), existing, marking],
    )
    .map_err(|error| ActionObjectMutationError::FailedPrecondition(format!("marking: {error}")))?;
    // Admission derived the instance marking from this object; one now
    // marked above it changed since, and the Action would act below it.
    // Compared as markings, not spellings: the instance's must equal its own
    // join with everything the object carries. Joining it with itself puts
    // both sides in the same canonical form.
    let canonical = |tokens: &[Option<&str>]| {
        crate::sekai::classification_lattice::union_input_marking_tokens(
            lattice.as_ref(),
            tokens.iter().copied(),
        )
        .map(|(_, joined)| joined)
        .map_err(|error| ActionObjectMutationError::FailedPrecondition(format!("marking: {error}")))
    };
    if let Some(instance_marking) = instance_marking
        && canonical(&[Some(instance_marking), Some(instance_marking)])?
            != canonical(&[Some(instance_marking), joined.as_deref()])?
    {
        return Err(ActionObjectMutationError::FailedPrecondition(format!(
            "object {} marking changed since the Action was admitted; submit again",
            object.id
        )));
    }
    if let Some(joined) = joined {
        object.properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
            joined,
        );
    }
    Ok(())
}

pub(crate) fn object_properties(
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

fn property_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
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
            ..Default::default()
        };
        let error = plan(
            &db,
            &type_def,
            "acme",
            r#"{"object_id":" rec-1 "}"#,
            None,
            None,
            10,
        )
        .unwrap_err();
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
            ..Default::default()
        };
        let error = plan(
            &db,
            &type_def,
            "acme",
            r#"{"object_id":"rec-schema"}"#,
            None,
            None,
            10,
        )
        .unwrap_err();
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
            ..Default::default()
        };
        let planned = plan(
            &db,
            &type_def,
            "acme",
            r#"{"object_id":"rec-abort"}"#,
            None,
            None,
            10,
        )
        .unwrap()
        .expect("planned");
        let applied = apply(&db, planned, "alice", &Default::default(), 10).unwrap();
        compensate(&db, &applied, "alice");
        let planned = plan(
            &db,
            &type_def,
            "acme",
            r#"{"object_id":"rec-abort"}"#,
            None,
            None,
            20,
        )
        .unwrap()
        .expect("planned after abort");
        apply(&db, planned, "alice", &Default::default(), 20).unwrap();
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
            ..Default::default()
        };
        let planned = plan(
            &db,
            &create,
            "acme",
            r#"{"object_id":"rec-restore","city":"oslo"}"#,
            None,
            None,
            10,
        )
        .unwrap()
        .expect("planned");
        apply(&db, planned, "alice", &Default::default(), 10).unwrap();
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
            None,
            None,
            20,
        )
        .unwrap()
        .expect("planned");
        let applied = apply(&db, planned, "alice", &Default::default(), 20).unwrap();
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

    #[test]
    fn written_objects_inherit_the_action_marking_and_never_drop_their_own() {
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
            parameter_schema_json: r#"{"type":"object"}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_CREATE.into(),
            enabled: true,
            ..Default::default()
        };
        let marking = |planned: &Option<PlannedObjectMutation>| match planned {
            Some(
                PlannedObjectMutation::Create(object) | PlannedObjectMutation::Update(object, _),
            ) => crate::sekai::markings::object_marking_token(object).map(str::to_string),
            None => None,
        };
        // A created object carries the Action's marking.
        let created = plan(
            &db,
            &create,
            "acme",
            r#"{"object_id":"rec-marked"}"#,
            None,
            Some("confidential"),
            10,
        )
        .unwrap();
        assert_eq!(marking(&created).as_deref(), Some("confidential"));
        apply(&db, created.unwrap(), "alice", &Default::default(), 10).unwrap();
        // An update cannot lower the object's marking through a parameter,
        // and keeps the stricter of the object's and the Action's.
        let update = GovernedActionType {
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            type_id: "customer.record.update".into(),
            ..create
        };
        let lowered = plan(
            &db,
            &update,
            "acme",
            r#"{"object_id":"rec-marked","access_marking":"public"}"#,
            None,
            Some("confidential"),
            20,
        )
        .unwrap();
        assert_eq!(marking(&lowered).as_deref(), Some("confidential"));
        // The same marking spelled differently is the same marking.
        assert!(
            plan(
                &db,
                &update,
                "acme",
                r#"{"object_id":"rec-marked"}"#,
                None,
                Some("CONFIDENTIAL"),
                22,
            )
            .is_ok()
        );
        // An object marked above the instance changed after admission
        // derived the marking; the Action would act below it.
        assert!(matches!(
            plan(
                &db,
                &update,
                "acme",
                r#"{"object_id":"rec-marked"}"#,
                None,
                Some("internal"),
                25,
            ),
            Err(ActionObjectMutationError::FailedPrecondition(message)) if message.contains("changed")
        ));
        // An unknown marking refuses the write.
        assert!(matches!(
            plan(
                &db,
                &update,
                "acme",
                r#"{"object_id":"rec-marked"}"#,
                None,
                Some("ultra-secret"),
                30,
            ),
            Err(ActionObjectMutationError::FailedPrecondition(_))
        ));
    }
}
