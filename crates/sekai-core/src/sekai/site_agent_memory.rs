//! Site agent working memory (`sekai.site-agent-memory/v1`, ADR 0139, #1612).
//!
//! A working memory item is a note one site agent instance keeps across its
//! wakes. It is an ordinary governed object bound to that instance, written
//! only through its governed Actions, which leave receipts; direct object
//! writes of this kind are refused. Only the instance's own principal writes
//! its memory, so a frozen instance writes none (its principal's Actions are
//! refused at admission). An item carries the marking its Action was
//! admitted under and can only be raised, as any Action-written object.
//!
//! Forgetting is an update: Actions have no delete mutation. It empties the
//! content and sets `forgotten`, and a forgotten item is never written again.
//! Earlier values stay in the change history under a restricted
//! (`sensitive`) property classification, readable only by object admins.
//! Forget also empties `content` in the retained parameters of the Actions
//! that wrote the item (#1969), leaving each Action's stored request digest
//! as it was so receipt and digest verification still match the original
//! submit. Later Action and decision-memory writes that still name a
//! forgotten item store empty `content` too.
//!
//! Working memory is neither Kioku (epistemic memory Chisei derives from
//! operation outcomes) nor decision memory (precedents of parked reviews).
//! `ListSiteAgentWorkingMemory` (#1968) is the agent-turn read: an item is
//! returned only when the instance principal and the requester can each
//! read it. SQLite is the reference store, as for site agent instances
//! (ADR 0136).

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object, PropertyFilter};
use crate::sekai::governed_action_type::{
    EFFECT_KIND_NOTIFY, GovernedActionType, OBJECT_MUTATION_CREATE, OBJECT_MUTATION_UPDATE,
};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, default_property_classification,
};

pub const CONTRACT: &str = "sekai.site-agent-memory/v1";
pub const KIND: &str = "site_agent_memory";
pub const ACTION_CREATE: &str = "site_agent.memory.create";
pub const ACTION_UPDATE: &str = "site_agent.memory.update";
pub const ACTION_FORGET: &str = "site_agent.memory.forget";
pub const ACTION_VERSION: &str = "1";
pub const INSTANCE_PROPERTY: &str = "instance_id";
pub const CONTENT_PROPERTY: &str = "content";
pub const TOPIC_PROPERTY: &str = "topic";
/// `"true"` once forgotten; set only by the forget Action.
pub const FORGOTTEN_PROPERTY: &str = "forgotten";

/// Register the memory ObjectType and its create, update and forget Actions
/// in `namespace`. Idempotent.
pub fn install(db: &RuntimeDb, namespace: &str, actor: &str, now_ms: i64) -> Result<(), String> {
    let property = |name: &str, required: bool, description: &str, restricted: bool| {
        let classification = if restricted {
            "sensitive".to_string()
        } else {
            default_property_classification()
        };
        PropertyDef {
            name: name.into(),
            prop_type: PropertyType::String,
            required,
            description: description.into(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification,
            struct_fields: Vec::new(),
        }
    };
    db.upsert_object_type(&ObjectType {
        kind: KIND.into(),
        description: "Site agent working memory item (sekai.site-agent-memory/v1)".into(),
        properties: vec![
            property(
                INSTANCE_PROPERTY,
                true,
                "The site agent instance that keeps this item.",
                false,
            ),
            // Sensitive (a restricted classification), so earlier values in
            // the change history stay with object admins once forgotten.
            property(
                CONTENT_PROPERTY,
                false,
                "The note; empty once forgotten.",
                true,
            ),
            property(TOPIC_PROPERTY, false, "Optional topic of the note.", false),
            property(
                FORGOTTEN_PROPERTY,
                false,
                "\"true\" once forgotten; set by the forget Action.",
                false,
            ),
        ],
        is_builtin: false,
        implements: Vec::new(),
    })?;
    let marking = crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    let text = serde_json::json!({"type": "string", "minLength": 1});
    put_action(
        db,
        namespace,
        ACTION_CREATE,
        OBJECT_MUTATION_CREATE,
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "object_id": {"type": "string"},
                "name": {"type": "string"},
                marking: {"type": "string"},
                INSTANCE_PROPERTY: text,
                CONTENT_PROPERTY: text,
                TOPIC_PROPERTY: text,
            },
            "required": ["object_id", INSTANCE_PROPERTY, CONTENT_PROPERTY],
        }),
        actor,
        now_ms,
    )?;
    put_action(
        db,
        namespace,
        ACTION_UPDATE,
        OBJECT_MUTATION_UPDATE,
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "object_id": {"type": "string"},
                "name": {"type": "string"},
                marking: {"type": "string"},
                CONTENT_PROPERTY: text,
                TOPIC_PROPERTY: text,
            },
            "required": ["object_id"],
        }),
        actor,
        now_ms,
    )?;
    // Forget sets only the flag and empties the content.
    put_action(
        db,
        namespace,
        ACTION_FORGET,
        OBJECT_MUTATION_UPDATE,
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "object_id": {"type": "string"},
                CONTENT_PROPERTY: {"type": "string", "enum": [""]},
                FORGOTTEN_PROPERTY: {"type": "string", "enum": ["true"]},
            },
            "required": ["object_id", CONTENT_PROPERTY, FORGOTTEN_PROPERTY],
        }),
        actor,
        now_ms,
    )
}

fn put_action(
    db: &RuntimeDb,
    namespace: &str,
    type_id: &str,
    mutation: &str,
    schema: serde_json::Value,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    db.put_governed_action_type(
        GovernedActionType {
            namespace: namespace.into(),
            type_id: type_id.into(),
            version: ACTION_VERSION.into(),
            description: format!("{type_id}: write a {CONTRACT} item"),
            parameter_schema_json: schema.to_string(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: KIND.into(),
            object_mutation: mutation.into(),
            enabled: true,
            ..Default::default()
        },
        actor,
        now_ms,
    )?;
    Ok(())
}

/// Kinds written only through their governed Actions: site agent instances
/// (ADR 0136) and their working memory. Direct writes are refused, and an
/// unreadable one reads as missing.
pub fn is_action_only_kind(kind: &str) -> bool {
    kind == KIND || kind == crate::sekai::site_agent_instance::KIND
}

/// Whether `message` is this module's refusal because the memory's instance
/// is frozen, gone, or acts as another principal: the writer may not write
/// now, as when the commit itself refuses (#1970).
pub fn is_owner_refusal(message: &str) -> bool {
    (message.starts_with("site agent instance ")
        && (message.ends_with(" is frozen") || message.ends_with(" not found in this namespace")))
        || message.starts_with("only the principal of site agent instance ")
}

/// Whether `object` is a working memory item that was forgotten.
pub fn is_forgotten(object: &Object) -> bool {
    object.kind == KIND
        && object
            .properties
            .get(FORGOTTEN_PROPERTY)
            .map(String::as_str)
            == Some("true")
}

/// Live (not forgotten) working memory of `instance_id` in `namespace`,
/// newest id last. Visibility is applied by the caller (#1968).
pub fn list_live_for_instance(
    db: &RuntimeDb,
    namespace: &str,
    instance_id: &str,
) -> Result<Vec<Object>, String> {
    let mut items = db.list_all_objects(&ListFilter {
        kind: Some(KIND.into()),
        namespace: Some(namespace.into()),
        property_filters: vec![PropertyFilter {
            key: INSTANCE_PROPERTY.into(),
            op: "eq".into(),
            value: instance_id.into(),
        }],
        ..Default::default()
    })?;
    items.retain(|object| !is_forgotten(object));
    items.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(items)
}

/// Actions whose parameters may hold a memory item's note.
pub fn is_writer_action(type_id: &str) -> bool {
    type_id == ACTION_CREATE || type_id == ACTION_UPDATE || type_id == ACTION_FORGET
}

/// Empty `content` in retained Action parameters. `None` when there is
/// nothing to redact. Callers keep the stored request digest: this does
/// not recompute it.
pub fn redact_content_parameter(parameters_json: &str) -> Option<String> {
    let mut value = serde_json::from_str::<serde_json::Value>(parameters_json).ok()?;
    let object = value.as_object_mut()?;
    let content = object.get(CONTENT_PROPERTY)?.as_str()?;
    if content.is_empty() {
        return None;
    }
    object.insert(
        CONTENT_PROPERTY.to_string(),
        serde_json::Value::String(String::new()),
    );
    serde_json::to_string(&value).ok()
}

/// Object id a writer Action named, if any.
pub fn writer_object_id(parameters_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()?
        .get("object_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

/// Empty `content` on a writer Action, including an offline base value.
/// Keeps the stored request digest.
pub fn redact_writer_instance(
    instance: &mut crate::sekai::action_instance::ActionInstance,
) -> bool {
    if !is_writer_action(&instance.type_id) {
        return false;
    }
    let mut changed = false;
    if let Some(redacted) = redact_content_parameter(&instance.parameters_json) {
        instance.parameters_json = redacted;
        changed = true;
    }
    if let Some(offline) = instance.offline.as_mut()
        && let Some(Some(content)) = offline.base_properties.get_mut(CONTENT_PROPERTY)
        && !content.is_empty()
    {
        content.clear();
        changed = true;
    }
    changed
}

/// True when the stored writer row already has empty `content` and
/// `incoming` still carries a note for the same object. A later
/// transition must not restore forgotten content from a stale copy.
pub fn stored_writer_already_redacted(
    stored_parameters: Option<&str>,
    incoming: &crate::sekai::action_instance::ActionInstance,
) -> bool {
    let Some(stored) = stored_parameters else {
        return false;
    };
    if writer_object_id(stored) != writer_object_id(&incoming.parameters_json) {
        return false;
    }
    redact_content_parameter(stored).is_none()
        && redact_content_parameter(&incoming.parameters_json).is_some()
}

/// Empty forgotten notes copied into decision-memory parameters and facts.
pub fn redact_decision_memory(memory: &mut crate::sekai::decision_memory::DecisionMemory) -> bool {
    let mut changed = false;
    for field in [
        &mut memory.parameters_json,
        &mut memory.facts_json,
        &mut memory.conditions_json,
    ] {
        if let Some(redacted) = redact_content_parameter(field) {
            *field = redacted;
            changed = true;
        }
    }
    changed
}

/// Memory rules on a governed object write, submitted by `submitter`.
/// Other kinds pass through.
pub fn validate_object_write(
    db: &RuntimeDb,
    object: &Object,
    submitter: Option<&str>,
) -> Result<(), String> {
    if object.kind != KIND {
        return Ok(());
    }
    if db.backend_name() != "sqlite" {
        return Err(
            "site agent working memory is unavailable on this store; SQLite is the reference store (ADR 0139)"
                .into(),
        );
    }
    let instance_id = object
        .properties
        .get(INSTANCE_PROPERTY)
        .map(String::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| format!("{INSTANCE_PROPERTY} is required"))?;
    if let Some(existing) = db
        .get_object(&object.id)?
        .filter(|existing| existing.kind == KIND)
    {
        if is_forgotten(&existing) {
            return Err(format!("memory item {} was forgotten", object.id));
        }
        if existing
            .properties
            .get(INSTANCE_PROPERTY)
            .map(String::as_str)
            != Some(instance_id)
        {
            return Err(format!(
                "memory item {} cannot move to another instance",
                object.id
            ));
        }
    }
    let instance = db
        .get_object(instance_id)?
        .filter(|instance| {
            instance.kind == crate::sekai::site_agent_instance::KIND
                && instance.namespace == object.namespace
        })
        .ok_or_else(|| format!("site agent instance {instance_id} not found in this namespace"))?;
    // Checked here as well as at admission: a write parked before the
    // instance froze must not land after it.
    crate::sekai::site_agent_instance::require_not_frozen(&instance)?;
    let principal = instance
        .properties
        .get("principal_id")
        .map(String::as_str)
        .unwrap_or_default();
    // An agent's memory is its own: only the instance's principal writes it.
    if submitter != Some(principal) {
        return Err(format!(
            "only the principal of site agent instance {instance_id} writes its memory"
        ));
    }
    if is_forgotten(object)
        && !object
            .properties
            .get(CONTENT_PROPERTY)
            .is_none_or(String::is_empty)
    {
        return Err("a forgotten memory item keeps no content".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_instance::{
        ActionInstance, AdmissionLease, STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED,
        compute_request_digest, lease_clock_ms,
    };
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionOutcome,
        ActionInstanceAdmissionRequest,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;

    const NAMESPACE: &str = "site";
    /// An org-owned service principal; `agent:` principals park for
    /// approval until they hold an autonomy grant.
    const AGENT: &str = "svc-line-7";

    /// A namespace with the memory types and one instance acting as AGENT.
    /// The instance is stored directly: its own admission is covered by the
    /// instance module.
    fn setup() -> RuntimeDb {
        let db = RuntimeDb::memory();
        install(&db, NAMESPACE, "operator", 1).unwrap();
        db.create_object(&Object {
            id: "line-7".into(),
            kind: crate::sekai::site_agent_instance::KIND.into(),
            name: "line-7".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: HashMap::from([("principal_id".into(), AGENT.into())]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db
    }

    fn admit(
        db: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
        actor: &str,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        ActionInstanceAdmission::new(db, None).admit(
            ActionInstanceAdmissionRequest {
                agent_turn: None,
                namespace: NAMESPACE.into(),
                type_id: type_id.into(),
                version: ACTION_VERSION.into(),
                parameters_json: parameters.to_string(),
                idempotency_key: key.into(),
                evidence_submission_ids: Vec::new(),
                request_id: String::new(),
                ontology_digest: String::new(),
                autonomous_envelope_id: String::new(),
                policy_context: Default::default(),
                delegating_actor: None,
                budget_already_reserved: false,
                resource_tenant: String::new(),
                binding_markings: Vec::new(),
                source_object_id: String::new(),
                marking_gate: Default::default(),
                expected_object_revision: String::new(),
                offline: None,
            },
            actor,
            10,
        )
    }

    fn remember(db: &RuntimeDb, key: &str, actor: &str) -> Result<(), String> {
        admit(
            db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "valve 3 sticks"}),
            key,
            actor,
        )
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
    }

    #[test]
    fn only_the_instance_principal_writes_its_memory_with_a_receipt() {
        let db = setup();
        let refused = remember(&db, "other", "svc-other").unwrap_err();
        assert!(refused.contains("only the principal"), "{refused}");
        assert!(db.get_object("note-1").unwrap().is_none());

        let admitted = admit(
            &db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "valve 3 sticks"}),
            "mine",
            AGENT,
        )
        .unwrap();
        assert_eq!(admitted.instance.status, STATUS_ADMITTED);
        let note = db.get_object("note-1").unwrap().unwrap();
        assert_eq!(note.properties[CONTENT_PROPERTY], "valve 3 sticks");
        assert!(
            db.get_operation_receipt(&admitted.instance.operation_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn forgetting_empties_the_item_for_good_and_leaves_a_receipt() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        // The forget Action only empties the content.
        assert!(
            admit(
                &db,
                ACTION_FORGET,
                json!({"object_id": "note-1", "content": "kept", "forgotten": "true"}),
                "bad-forget",
                AGENT,
            )
            .is_err()
        );
        let forgotten = admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        let note = db.get_object("note-1").unwrap().unwrap();
        assert!(is_forgotten(&note));
        assert_eq!(note.properties[CONTENT_PROPERTY], "");
        assert!(
            db.get_operation_receipt(&forgotten.instance.operation_id)
                .unwrap()
                .is_some()
        );
        let message = format!(
            "{:?}",
            admit(
                &db,
                ACTION_UPDATE,
                json!({"object_id": "note-1", "content": "back again"}),
                "revive",
                AGENT,
            )
            .unwrap_err()
        );
        assert!(message.contains("was forgotten"), "{message}");
        // The content property is restricted, so its history is admin-only.
        let content = db
            .get_object_type(KIND)
            .unwrap()
            .unwrap()
            .properties
            .into_iter()
            .find(|property| property.name == CONTENT_PROPERTY)
            .unwrap();
        assert!(crate::sekai::schema::is_restricted_property_classification(
            &content.classification
        ));
    }

    #[test]
    fn redact_content_parameter_empties_only_nonempty_content() {
        assert_eq!(
            redact_content_parameter(r#"{"object_id":"note-1","content":"secret"}"#)
                .and_then(|json| serde_json::from_str::<Value>(&json).ok())
                .and_then(|value| value
                    .get(CONTENT_PROPERTY)
                    .and_then(Value::as_str)
                    .map(str::to_owned)),
            Some(String::new())
        );
        assert_eq!(
            redact_content_parameter(r#"{"object_id":"note-1","content":""}"#),
            None
        );
        assert_eq!(redact_content_parameter(r#"{"object_id":"note-1"}"#), None);
        assert!(is_writer_action(ACTION_CREATE));
        assert!(is_writer_action(ACTION_UPDATE));
        assert!(is_writer_action(ACTION_FORGET));
        assert!(!is_writer_action("site.ping"));
    }

    /// Forget empties retained writer-Action parameters so a reader of those
    /// Actions cannot recover the note, and keeps the original request digest.
    #[test]
    fn forgetting_redacts_writer_action_content_and_keeps_the_digest() {
        let db = setup();
        let created = admit(
            &db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "valve 3 sticks"}),
            "create",
            AGENT,
        )
        .unwrap();
        admit(
            &db,
            ACTION_UPDATE,
            json!({"object_id": "note-1", "content": "valve 3 still sticks"}),
            "update",
            AGENT,
        )
        .unwrap();
        let original = db
            .get_action_instance(&created.instance.instance_id)
            .unwrap()
            .unwrap();
        let original_digest = original.request_digest.clone();
        let original_params = original.parameters_json.clone();
        assert!(
            original_params.contains("valve 3 sticks"),
            "{}",
            original_params
        );

        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();

        let stored = db
            .get_action_instance(&created.instance.instance_id)
            .unwrap()
            .unwrap();
        let content = serde_json::from_str::<Value>(&stored.parameters_json)
            .unwrap()
            .get(CONTENT_PROPERTY)
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_string();
        assert_eq!(content, "");
        assert!(
            !stored.parameters_json.contains("valve 3 sticks"),
            "{}",
            stored.parameters_json
        );
        assert_eq!(stored.request_digest, original_digest);
        let from_redacted = compute_request_digest(
            &stored.namespace,
            &stored.type_id,
            &stored.version,
            &stored.parameters_json,
            &stored.evidence_submission_ids,
        )
        .unwrap();
        assert_ne!(from_redacted, stored.request_digest);
        assert_eq!(
            compute_request_digest(
                &stored.namespace,
                &stored.type_id,
                &stored.version,
                &original_params,
                &stored.evidence_submission_ids,
            )
            .unwrap(),
            stored.request_digest
        );

        let updated = db
            .get_action_instance_by_idempotency(NAMESPACE, "update")
            .unwrap()
            .unwrap();
        let updated_content = serde_json::from_str::<Value>(&updated.parameters_json)
            .unwrap()
            .get(CONTENT_PROPERTY)
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_string();
        assert_eq!(updated_content, "");
        assert!(
            !updated.parameters_json.contains("still sticks"),
            "{}",
            updated.parameters_json
        );

        let listed = db.list_action_instances(NAMESPACE, None, None, 50).unwrap();
        assert!(
            listed.iter().all(|instance| {
                serde_json::from_str::<Value>(&instance.parameters_json)
                    .ok()
                    .and_then(|value| {
                        value
                            .get(CONTENT_PROPERTY)
                            .and_then(Value::as_str)
                            .map(|content| content.is_empty())
                    })
                    .unwrap_or(true)
            }),
            "{listed:?}"
        );
    }

    fn decision_row(id: &str, note: &str) -> crate::sekai::decision_memory::DecisionMemory {
        let parameters = json!({"object_id": "note-1", "content": note}).to_string();
        crate::sekai::decision_memory::DecisionMemory {
            memory_id: id.into(),
            namespace: NAMESPACE.into(),
            type_id: ACTION_UPDATE.into(),
            version: ACTION_VERSION.into(),
            instance_id: id.into(),
            outcome: "grant".into(),
            reason: "ok".into(),
            conditions_json: String::new(),
            facts_json: parameters.clone(),
            decided_by: "operator".into(),
            decided_at_ms: 10,
            superseded: false,
            parameters_json: parameters,
        }
    }

    #[test]
    fn forgetting_redacts_decision_memory_facts() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        db.put_decision_memory(&decision_row("decided", "valve 3 sticks"))
            .unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        let stored = db.get_decision_memory("decided").unwrap().unwrap();
        for field in [&stored.parameters_json, &stored.facts_json] {
            let content = serde_json::from_str::<Value>(field)
                .unwrap()
                .get(CONTENT_PROPERTY)
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            assert_eq!(content, "", "{field}");
            assert!(!field.contains("valve 3 sticks"), "{field}");
        }
    }

    #[test]
    fn a_late_decision_memory_write_cannot_restore_forgotten_content() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        db.put_decision_memory(&decision_row("late", "valve 3 sticks"))
            .unwrap();
        let stored = db.get_decision_memory("late").unwrap().unwrap();
        for field in [&stored.parameters_json, &stored.facts_json] {
            let content = serde_json::from_str::<Value>(field)
                .unwrap()
                .get(CONTENT_PROPERTY)
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            assert_eq!(content, "", "{field}");
            assert!(!field.contains("valve 3 sticks"), "{field}");
        }
    }

    fn writer_action(
        instance_id: &str,
        type_id: &str,
        key: &str,
        content: &str,
        status: &str,
    ) -> ActionInstance {
        let parameters_json = json!({"object_id": "note-1", "content": content}).to_string();
        let request_digest =
            compute_request_digest(NAMESPACE, type_id, ACTION_VERSION, &parameters_json, &[])
                .unwrap();
        ActionInstance {
            agent_turn: None,
            autonomous_envelope_id: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            instance_id: instance_id.into(),
            namespace: NAMESPACE.into(),
            type_id: type_id.into(),
            version: ACTION_VERSION.into(),
            principal: AGENT.into(),
            delegating_actor: None,
            parameters_json,
            request_digest,
            idempotency_key: key.into(),
            operation_id: instance_id.into(),
            status: status.into(),
            deny_reason: String::new(),
            evidence_submission_ids: vec![],
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        }
    }

    fn stored_content(instance: &ActionInstance) -> String {
        serde_json::from_str::<Value>(&instance.parameters_json)
            .ok()
            .and_then(|value| {
                value
                    .get(CONTENT_PROPERTY)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "missing".into())
    }

    /// A denied writer stored after forget keeps empty content and the
    /// original request digest.
    #[test]
    fn a_late_action_instance_write_cannot_restore_forgotten_content() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        let mut original = writer_action(
            "late",
            ACTION_UPDATE,
            "late",
            "valve 3 sticks",
            STATUS_DENIED,
        );
        original.offline = Some(crate::sekai::offline_action::OfflineSubmission {
            prepared_at_ms: 5,
            base_updated_ms: 1,
            base_properties: [(CONTENT_PROPERTY.into(), Some("valve 3 sticks".into()))].into(),
            lease_id: String::new(),
            device_id: String::new(),
        });
        let digest = original.request_digest.clone();
        let stored = db.put_action_instance(&original).unwrap();
        assert_eq!(stored_content(&stored), "");
        assert!(
            !stored.parameters_json.contains("valve 3 sticks"),
            "{}",
            stored.parameters_json
        );
        assert_eq!(
            stored
                .offline
                .as_ref()
                .and_then(|offline| offline.base_properties.get(CONTENT_PROPERTY).cloned())
                .flatten()
                .as_deref(),
            Some("")
        );
        assert_eq!(stored.request_digest, digest);
        let loaded = db.get_action_instance("late").unwrap().unwrap();
        assert_eq!(stored_content(&loaded), "");
        assert_eq!(loaded.request_digest, digest);
    }

    /// Denying a parked update after forget does not write the original
    /// note back into the stored Action body.
    #[test]
    fn a_parked_transition_cannot_restore_forgotten_content() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        let mut parked = writer_action(
            "parked-update",
            ACTION_UPDATE,
            "parked-update",
            "valve 3 still sticks",
            STATUS_PARKED,
        );
        parked.offline = Some(crate::sekai::offline_action::OfflineSubmission {
            prepared_at_ms: 5,
            base_updated_ms: 1,
            base_properties: [(CONTENT_PROPERTY.into(), Some("valve 3 still sticks".into()))]
                .into(),
            lease_id: String::new(),
            device_id: String::new(),
        });
        db.put_action_instance(&parked).unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        let after_forget = db.get_action_instance("parked-update").unwrap().unwrap();
        assert_eq!(stored_content(&after_forget), "");
        assert_eq!(
            after_forget
                .offline
                .as_ref()
                .and_then(|offline| offline.base_properties.get(CONTENT_PROPERTY).cloned())
                .flatten()
                .as_deref(),
            Some("")
        );
        let mut denied = parked.clone();
        denied.status = STATUS_DENIED.into();
        denied.deny_reason = "no".into();
        assert!(db.decide_parked_action_instance(&denied).unwrap());
        let stored = db.get_action_instance("parked-update").unwrap().unwrap();
        assert_eq!(stored.status, STATUS_DENIED);
        assert_eq!(stored_content(&stored), "");
        assert!(
            !stored.parameters_json.contains("still sticks"),
            "{}",
            stored.parameters_json
        );
        assert_eq!(
            stored
                .offline
                .as_ref()
                .and_then(|offline| offline.base_properties.get(CONTENT_PROPERTY).cloned())
                .flatten()
                .as_deref(),
            Some("")
        );
        assert_eq!(stored.request_digest, parked.request_digest);
    }

    /// Taking over an abandoned reservation after forget keeps empty
    /// content: the takeover writes only the new lease.
    #[test]
    fn takeover_cannot_restore_forgotten_content() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        let mut reserved = writer_action(
            "reserved",
            ACTION_UPDATE,
            "reserved",
            "valve 3 sticks",
            STATUS_ADMITTED,
        );
        reserved.admission_lease = Some(AdmissionLease {
            owner: "worker".into(),
            generation: 1,
            expires_at_ms: lease_clock_ms() - 1,
            write_committed: Some(false),
            receipt_recorded: Some(false),
            written_object_digest: None,
            follow_ups_recorded: None,
            decision_follow_ups_recorded: None,
            decision_budget_reserved: None,
        });
        db.put_action_instance(&reserved).unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        let expired = reserved.admission_lease.clone().unwrap();
        assert!(
            db.take_over_admission(&reserved, &expired, &expired.succeeding())
                .unwrap()
        );
        let taken = db.get_action_instance("reserved").unwrap().unwrap();
        assert_eq!(stored_content(&taken), "");
        assert!(
            !taken.parameters_json.contains("valve 3 sticks"),
            "{}",
            taken.parameters_json
        );
        assert!(taken.admission_lease.unwrap().generation > 1);
    }

    #[test]
    fn a_write_parked_before_a_freeze_does_not_land_after_it() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        let mut instance = db.get_object("line-7").unwrap().unwrap();
        instance.properties.insert(
            crate::sekai::site_agent_instance::FROZEN_PROPERTY.into(),
            "true".into(),
        );
        db.update_object(&instance).unwrap();
        let mut note = db.get_object("note-1").unwrap().unwrap();
        note.properties
            .insert(CONTENT_PROPERTY.into(), "late".into());
        let refused = validate_object_write(&db, &note, Some(AGENT)).unwrap_err();
        assert!(refused.contains("frozen"), "{refused}");
    }

    #[test]
    fn a_frozen_instance_writes_no_memory() {
        let db = setup();
        let mut instance = db.get_object("line-7").unwrap().unwrap();
        instance.properties.insert(
            crate::sekai::site_agent_instance::FROZEN_PROPERTY.into(),
            "true".into(),
        );
        db.update_object(&instance).unwrap();
        let denied = admit(
            &db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "x"}),
            "frozen",
            AGENT,
        )
        .unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert!(db.get_object("note-1").unwrap().is_none());
    }

    #[test]
    fn an_item_keeps_its_marking_and_cannot_be_lowered() {
        let db = setup();
        admit(
            &db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "x",
                "access_marking": "confidential"}),
            "create",
            AGENT,
        )
        .unwrap();
        assert_eq!(
            crate::sekai::markings::object_marking_token(
                &db.get_object("note-1").unwrap().unwrap()
            ),
            Some("confidential")
        );
        // A lower marking is never written: the stored one stands.
        let _ = admit(
            &db,
            ACTION_UPDATE,
            json!({"object_id": "note-1", "content": "y", "access_marking": "public"}),
            "lower",
            AGENT,
        );
        assert_eq!(
            crate::sekai::markings::object_marking_token(
                &db.get_object("note-1").unwrap().unwrap()
            ),
            Some("confidential")
        );
    }

    #[test]
    fn memory_is_an_action_only_kind() {
        assert!(is_action_only_kind(KIND));
        assert!(is_action_only_kind(crate::sekai::site_agent_instance::KIND));
        assert!(!is_action_only_kind("component"));
    }

    #[test]
    fn list_live_omits_forgotten_items_and_other_instances() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        db.create_object(&Object {
            id: "note-other".into(),
            kind: KIND.into(),
            name: "note-other".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: HashMap::from([
                (INSTANCE_PROPERTY.into(), "other".into()),
                (CONTENT_PROPERTY.into(), "elsewhere".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        admit(
            &db,
            ACTION_FORGET,
            json!({"object_id": "note-1", "content": "", "forgotten": "true"}),
            "forget",
            AGENT,
        )
        .unwrap();
        db.create_object(&Object {
            id: "note-live".into(),
            kind: KIND.into(),
            name: "note-live".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: HashMap::from([
                (INSTANCE_PROPERTY.into(), "line-7".into()),
                (CONTENT_PROPERTY.into(), "kept".into()),
            ]),
            created: 2,
            updated: 2,
        })
        .unwrap();
        let live = list_live_for_instance(&db, NAMESPACE, "line-7").unwrap();
        assert_eq!(
            live.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
            ["note-live"]
        );
    }

    /// A freeze committing between planning and the write denies the
    /// Action with a receipt naming the freeze, and writes nothing (#1970).
    #[test]
    fn a_freeze_committing_before_the_write_denies_it() {
        let db = setup();
        remember(&db, "create", AGENT).unwrap();
        crate::sekai::action_instance_admission::freeze_before_next_commit("line-7");
        let refused = admit(
            &db,
            ACTION_UPDATE,
            json!({"object_id": "note-1", "content": "after the freeze"}),
            "late",
            AGENT,
        )
        .unwrap();
        assert_eq!(refused.instance.status, STATUS_DENIED);
        assert_eq!(
            refused.instance.deny_reason,
            "site agent instance line-7 is frozen"
        );
        let stored = db
            .get_action_instance(&refused.instance.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, STATUS_DENIED);
        assert_eq!(
            db.get_object("note-1").unwrap().unwrap().properties[CONTENT_PROPERTY],
            "valve 3 sticks"
        );
        let receipt = db
            .get_operation_receipt(&refused.instance.operation_id)
            .unwrap()
            .expect("receipt");
        assert!(receipt.events.iter().any(|event| {
            event.attributes.get("deny_reason").map(String::as_str)
                == Some("site agent instance line-7 is frozen")
        }));
    }

    /// The same holds for an Action that writes no object: it commits at
    /// its receipt, and a freeze committed since admission denies it.
    #[test]
    fn a_freeze_committing_before_an_effects_only_action_denies_it() {
        let db = setup();
        db.put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: NAMESPACE.into(),
                type_id: "site.ping".into(),
                version: ACTION_VERSION.into(),
                parameter_schema_json: r#"{"type":"object","properties":{"note":{"type":"string"}},"required":["note"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![
                    crate::sekai::governed_action_type::EFFECT_KIND_NOTIFY.into(),
                ],
                enabled: true,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        crate::sekai::action_instance_admission::freeze_before_next_commit("line-7");
        let refused = admit(&db, "site.ping", json!({"note": "check"}), "ping", AGENT).unwrap();
        assert_eq!(refused.instance.status, STATUS_DENIED);
        assert_eq!(
            refused.instance.deny_reason,
            "site agent instance line-7 is frozen"
        );
        assert!(
            db.list_action_effects_for_instance(&refused.instance.instance_id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_memory_write_is_refused_for_a_moved_or_missing_instance() {
        use crate::sekai::action_instance::memory_refusal;
        assert_eq!(
            memory_refusal("line-7", AGENT, None).as_deref(),
            Some("site agent instance line-7 not found in this namespace")
        );
        assert_eq!(
            memory_refusal("line-7", AGENT, Some((Some("svc-other".into()), None))).as_deref(),
            Some("only the principal of site agent instance line-7 writes its memory")
        );
        assert_eq!(
            memory_refusal("line-7", AGENT, Some((Some(AGENT.into()), None))),
            None
        );
    }

    /// A memory write parked before its instance froze ends denied with a
    /// receipt when an approver grants it (#1970).
    #[test]
    fn a_parked_memory_write_granted_after_a_freeze_ends_denied() {
        let db = setup();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(NAMESPACE);
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let parked = admit(
            &db,
            ACTION_CREATE,
            json!({"object_id": "note-1", "instance_id": "line-7", "content": "x"}),
            "parked",
            AGENT,
        )
        .unwrap()
        .instance;
        assert_eq!(parked.status, crate::sekai::action_instance::STATUS_PARKED);
        let mut instance = db.get_object("line-7").unwrap().unwrap();
        instance.properties.insert(
            crate::sekai::site_agent_instance::FROZEN_PROPERTY.into(),
            "true".into(),
        );
        db.update_object(&instance).unwrap();
        let decided = ActionInstanceAdmission::new(&db, None)
            .decide(
                crate::sekai::action_instance_admission::ActionInstanceDecisionRequest {
                    instance_id: parked.instance_id.clone(),
                    decision: "grant".into(),
                    reason: "ok".into(),
                    decider_principals: vec!["operator".into()],
                    decider_is_namespace_admin: true,
                    delegating_actor: None,
                    execution_claim: None,
                },
                "operator",
                20,
            )
            .unwrap();
        assert_eq!(decided.instance.status, STATUS_DENIED);
        assert_eq!(
            decided.instance.deny_reason,
            "site agent instance line-7 is frozen"
        );
        assert!(db.get_object("note-1").unwrap().is_none());
        assert!(
            db.get_operation_receipt(&parked.operation_id)
                .unwrap()
                .is_some()
        );
    }
}
