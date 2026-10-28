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
//! (`sensitive`) property classification, readable only by object admins,
//! and in the parameters of the Actions that wrote them, readable by whoever
//! may read those Actions. Erasing them is #1969.
//!
//! Working memory is neither Kioku (epistemic memory Chisei derives from
//! operation outcomes) nor decision memory (precedents of parked reviews).
//! Reading it as both the agent and the person it acts for is #1968.
//! SQLite is the reference store, as for site agent instances (ADR 0136).

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
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
    use crate::sekai::action_instance::{STATUS_ADMITTED, STATUS_DENIED};
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
