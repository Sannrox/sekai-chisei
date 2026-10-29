//! Site agent instances (`sekai.site-agent-instance/v1`, ADR 0136, #1933).
//!
//! An instance binds a site responsibility to the agent member of a
//! published, certified definition revision and acts as an org-owned
//! principal. It is an ordinary object written only through its governed
//! Actions, which leave receipts; direct object writes of this kind are
//! refused. It grants no authority: grants and markings stay on the
//! principal, and reads apply markings as to any object.
//!
//! Admission refuses a revision that is unpublished, not certified, or in
//! another namespace, and an `agent_member` that is not an agent member of
//! it. An update re-checks only when the revision or member changes.
//! SQLite is the reference store; PostgreSQL refuses instance writes until a
//! parity slice (ADR 0136). Freezing (#1934) is its own pair of Actions: a
//! frozen instance admits no new wake and no new Action submitted by its
//! principal. Schedule wakes (#1951) read `wake_policies`; working memory is
//! `site_agent_memory` (ADR 0139).

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::agent_promotion::MEMBER_KIND_AGENT;
use crate::sekai::governed_action_type::{
    EFFECT_KIND_NOTIFY, GovernedActionType, OBJECT_MUTATION_CREATE, OBJECT_MUTATION_UPDATE,
};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, default_property_classification,
};

pub const CONTRACT: &str = "sekai.site-agent-instance/v1";
pub const KIND: &str = "site_agent_instance";
pub const ACTION_CREATE: &str = "site_agent.instance.create";
pub const ACTION_UPDATE: &str = "site_agent.instance.update";
pub const ACTION_FREEZE: &str = "site_agent.instance.freeze";
pub const ACTION_UNFREEZE: &str = "site_agent.instance.unfreeze";
/// `"true"` while the instance is frozen; set only by the freeze and
/// unfreeze Actions (#1934).
pub const FROZEN_PROPERTY: &str = "frozen";
/// Comma-separated wake tokens, such as `schedule:3600000` (#1951).
pub const WAKE_POLICIES_PROPERTY: &str = "wake_policies";
pub const ACTION_VERSION: &str = "1";

/// `(name, required, description)` of each instance property.
const PROPERTIES: &[(&str, bool, &str)] = &[
    (
        "definition_revision_digest",
        true,
        "The published, certified definition revision the instance runs.",
    ),
    (
        "agent_member",
        true,
        "The agent member of that revision the instance runs.",
    ),
    (
        "principal_id",
        true,
        "The org-owned principal the instance acts as.",
    ),
    (
        "responsibility",
        true,
        "The object ids or the ObjectSet the instance owns.",
    ),
    (
        WAKE_POLICIES_PROPERTY,
        false,
        "Comma-separated wake tokens; schedule:<every_ms> wakes the instance on an interval.",
    ),
    (
        "autonomy_envelope_id",
        false,
        "Autonomous envelope that live autonomous admission follows (ADR 0059).",
    ),
];

/// Register the instance ObjectType and its create and update Actions in
/// `namespace`. Idempotent.
pub fn install(db: &RuntimeDb, namespace: &str, actor: &str, now_ms: i64) -> Result<(), String> {
    db.upsert_object_type(&ObjectType {
        kind: KIND.into(),
        description: "Site agent instance (sekai.site-agent-instance/v1)".into(),
        properties: PROPERTIES
            .iter()
            .chain(&[(
                FROZEN_PROPERTY,
                false,
                "\"true\" while frozen; set by the freeze and unfreeze Actions.",
            )])
            .map(|(name, required, description)| PropertyDef {
                name: (*name).into(),
                prop_type: PropertyType::String,
                required: *required,
                description: (*description).into(),
                enum_values: Vec::new(),
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: default_property_classification(),
                struct_fields: Vec::new(),
            })
            .collect(),
        is_builtin: false,
        implements: Vec::new(),
    })?;
    for (type_id, mutation, required) in [
        (
            ACTION_CREATE,
            OBJECT_MUTATION_CREATE,
            serde_json::json!([
                "object_id",
                "definition_revision_digest",
                "agent_member",
                "principal_id",
                "responsibility"
            ]),
        ),
        (
            ACTION_UPDATE,
            OBJECT_MUTATION_UPDATE,
            serde_json::json!(["object_id"]),
        ),
    ] {
        let mut properties = serde_json::Map::new();
        properties.insert("object_id".into(), serde_json::json!({"type": "string"}));
        properties.insert("name".into(), serde_json::json!({"type": "string"}));
        properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            serde_json::json!({"type": "string"}),
        );
        for (name, _, _) in PROPERTIES {
            properties.insert(
                (*name).into(),
                serde_json::json!({"type": "string", "minLength": 1}),
            );
        }
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
            "required": required,
        });
        put_action(db, namespace, type_id, mutation, schema, actor, now_ms)?;
    }
    // Freeze and unfreeze set only the flag; create and update never can.
    for (type_id, frozen) in [(ACTION_FREEZE, "true"), (ACTION_UNFREEZE, "false")] {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "object_id": {"type": "string"},
                FROZEN_PROPERTY: {"type": "string", "enum": [frozen]},
            },
            "required": ["object_id", FROZEN_PROPERTY],
        });
        put_action(
            db,
            namespace,
            type_id,
            OBJECT_MUTATION_UPDATE,
            schema,
            actor,
            now_ms,
        )?;
    }
    Ok(())
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
            description: format!("{type_id}: write a {CONTRACT} instance"),
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

/// The frozen instance in `namespace` whose principal is `principal`, if
/// any. Action admission refuses that principal's new Actions while one is
/// frozen, and wake admission (#1611) refuses the instance's wakes.
pub fn frozen_instance_for(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
) -> Result<Option<String>, String> {
    if principal.trim().is_empty() {
        return Ok(None);
    }
    Ok(db
        .find_by_property(KIND, "principal_id", principal)?
        .into_iter()
        .find(|instance| {
            instance.namespace == namespace
                && instance.properties.get(FROZEN_PROPERTY).map(String::as_str) == Some("true")
        })
        .map(|instance| instance.id))
}

/// Stands for several instances that act as one principal on different
/// definition revisions, so no one revision answers for their decisions.
pub const AMBIGUOUS_REVISION: &str = "ambiguous";

/// The definition revision behind `principal` in `namespace`: `None` when no
/// site agent instance acts as it, otherwise the revision digest its
/// instances share, empty when they record none, or [`AMBIGUOUS_REVISION`]
/// when they differ. Security dispositions stamp it so precision is
/// measured per revision (#1990). It is read when the write is planned and
/// is not fenced at commit (ADR 0135).
pub fn definition_revision_for(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
) -> Result<Option<String>, String> {
    let revisions: std::collections::BTreeSet<String> = db
        .find_by_property(KIND, "principal_id", principal)?
        .into_iter()
        .filter(|instance| instance.namespace == namespace)
        .map(|instance| {
            instance
                .properties
                .get("definition_revision_digest")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    Ok(match revisions.len() {
        0 => None,
        1 => revisions.into_iter().next(),
        _ => Some(AMBIGUOUS_REVISION.into()),
    })
}

/// Refuse a wake of `instance` while it is frozen (#1934).
pub fn require_not_frozen(instance: &Object) -> Result<(), String> {
    if instance.properties.get(FROZEN_PROPERTY).map(String::as_str) == Some("true") {
        return Err(format!("site agent instance {} is frozen", instance.id));
    }
    Ok(())
}

/// Instance rules on a governed object write. Other kinds pass through.
pub fn validate_object_write(db: &RuntimeDb, object: &Object, now_ms: i64) -> Result<(), String> {
    if object.kind != KIND {
        return Ok(());
    }
    if db.backend_name() != "sqlite" {
        return Err(
            "site agent instances are unavailable on this store; SQLite is the reference store (ADR 0136)"
                .into(),
        );
    }
    for (name, required, _) in PROPERTIES {
        if *required && property(object, name).is_none() {
            return Err(format!("{name} is required"));
        }
    }
    if let Some(wake) = property(object, WAKE_POLICIES_PROPERTY) {
        crate::sekai::agent_wake::parse(wake)?;
    }
    let digest = property(object, "definition_revision_digest").unwrap_or_default();
    let member = property(object, "agent_member").unwrap_or_default();
    // An update re-checks the binding only when it changes.
    if let Some(existing) = db.get_object(&object.id)?
        && existing.kind == KIND
        && property(&existing, "definition_revision_digest") == Some(digest)
        && property(&existing, "agent_member") == Some(member)
    {
        return Ok(());
    }
    let revision = db
        .get_definition_revision(&object.namespace, digest)?
        .filter(|revision| revision.published)
        .ok_or_else(|| {
            format!("definition revision {digest} is not published in this namespace")
        })?;
    if !revision.members.iter().any(|candidate| {
        candidate.member_kind == MEMBER_KIND_AGENT && candidate.member_id == member
    }) {
        return Err(format!(
            "{member} is not an agent member of definition revision {digest}"
        ));
    }
    let certified = db
        .get_agent_definition_certification(&object.namespace, digest)?
        .is_some_and(|certification| certification.gate(now_ms).admitted);
    if !certified {
        return Err(format!(
            "definition revision {digest} has no current certification"
        ));
    }
    Ok(())
}

fn property<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object
        .properties
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
    };
    use crate::sekai::agent_definition::AGENT_DEFINITION_VERSION;
    use crate::sekai::agent_promotion::{AgentDefinitionCertification, STATUS_PASS};
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use serde_json::{Value, json};

    const NAMESPACE: &str = "site";
    const ACTOR: &str = "operator";

    /// A published revision with one agent member `triage`, certified when
    /// `certified`. Returns its digest.
    fn published_revision(runtime: &RuntimeDb, parent: &str, certified: bool) -> String {
        let member = DefinitionMemberInput {
            member_kind: MEMBER_KIND_AGENT.into(),
            member_id: "triage".into(),
            member_digest: String::new(),
            definition_json: json!({
                "contract_version": AGENT_DEFINITION_VERSION, "name": "Triage",
                "task_class": "lookup", "instructions": format!("Inspect records {parent}."),
                "allowed_action_types": ["Ticket.inspect"]
            })
            .to_string(),
        }
        .prepare(NAMESPACE)
        .unwrap();
        let mut revision = prepare_revision(
            NAMESPACE,
            parent,
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            false,
            ACTOR,
            1,
        )
        .unwrap();
        revision.published = true;
        let bound_at_ms = chrono::Utc::now().timestamp_millis();
        let certification = |revoked_at_ms| AgentDefinitionCertification {
            namespace: NAMESPACE.into(),
            revision_digest: revision.revision_digest.clone(),
            suite_id: "suite-1".into(),
            certification_id: format!("cert-{parent}"),
            baseline_status: STATUS_PASS.into(),
            latest_status: STATUS_PASS.into(),
            expires_at_ms: bound_at_ms + 86_400_000,
            revoked_at_ms,
            bound_by: "certifier".into(),
            bound_at_ms,
            mean_score_milli: None,
        };
        runtime
            .put_agent_definition_certification(&certification(0))
            .unwrap();
        crate::db::definition_branch::insert_merged_revision_for_test(
            runtime.as_sqlite().unwrap(),
            &revision,
            std::slice::from_ref(&member),
        )
        .unwrap();
        if !certified {
            runtime
                .put_agent_definition_certification(&certification(bound_at_ms + 1))
                .unwrap();
        }
        revision.revision_digest
    }

    fn admit(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
    ) -> Result<String, ActionInstanceAdmissionError> {
        admit_as(runtime, type_id, parameters, key, ACTOR).map(|instance| instance.operation_id)
    }

    fn admit_as(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
        actor: &str,
    ) -> Result<crate::sekai::action_instance::ActionInstance, ActionInstanceAdmissionError> {
        ActionInstanceAdmission::new(runtime, None)
            .admit(
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
                    offline: None,
                    expected_object_revision: String::new(),
                },
                actor,
                2_000,
            )
            .map(|admitted| admitted.instance)
    }

    fn instance(digest: &str, member: &str) -> Value {
        json!({
            "object_id": "line-7",
            "definition_revision_digest": digest,
            "agent_member": member,
            "principal_id": "org:line-7-agent",
            "responsibility": "line:7"
        })
    }

    fn refusal(outcome: Result<String, ActionInstanceAdmissionError>) -> String {
        match outcome {
            Err(ActionInstanceAdmissionError::FailedPrecondition(message)) => message,
            other => panic!("expected FailedPrecondition, got {other:?}"),
        }
    }

    /// A principal's revision is its instances' shared revision, and
    /// instances on different revisions answer [`AMBIGUOUS_REVISION`]
    /// (#1990).
    #[test]
    fn a_principal_answers_for_one_revision_or_is_ambiguous() {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        let first = published_revision(&runtime, "", true);
        let second = published_revision(&runtime, &first, true);
        let principal = "org:line-7-agent";
        assert_eq!(
            definition_revision_for(&runtime, NAMESPACE, principal).unwrap(),
            None
        );
        admit(&runtime, ACTION_CREATE, instance(&first, "triage"), "a").unwrap();
        assert_eq!(
            definition_revision_for(&runtime, NAMESPACE, principal).unwrap(),
            Some(first)
        );
        let mut other = instance(&second, "triage");
        other["object_id"] = "line-8".into();
        other["responsibility"] = "line:8".into();
        admit(&runtime, ACTION_CREATE, other, "b").unwrap();
        assert_eq!(
            definition_revision_for(&runtime, NAMESPACE, principal).unwrap(),
            Some(AMBIGUOUS_REVISION.into())
        );
        assert_eq!(
            definition_revision_for(&runtime, "elsewhere", principal).unwrap(),
            None
        );
    }

    /// Instances are created and updated through their Actions, each with a
    /// receipt, and bind only to the agent member of a published, certified
    /// revision (#1933).
    #[test]
    fn instances_bind_only_to_a_certified_published_agent_revision() {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        let certified = published_revision(&runtime, "", true);
        let uncertified = published_revision(&runtime, &certified, false);

        let message = refusal(admit(
            &runtime,
            ACTION_CREATE,
            instance(&format!("sha256:{}", "0".repeat(64)), "triage"),
            "unpublished",
        ));
        assert!(message.contains("is not published"), "{message}");
        let message = refusal(admit(
            &runtime,
            ACTION_CREATE,
            instance(&uncertified, "triage"),
            "uncertified",
        ));
        assert!(message.contains("no current certification"), "{message}");
        let message = refusal(admit(
            &runtime,
            ACTION_CREATE,
            instance(&certified, "ticket"),
            "member",
        ));
        assert!(message.contains("not an agent member"), "{message}");
        assert!(runtime.get_object("line-7").unwrap().is_none());

        let created = admit(
            &runtime,
            ACTION_CREATE,
            instance(&certified, "triage"),
            "create",
        )
        .unwrap();
        assert!(runtime.get_operation_receipt(&created).unwrap().is_some());
        let updated = admit(
            &runtime,
            ACTION_UPDATE,
            json!({"object_id": "line-7", "responsibility": "line:7,line:8"}),
            "update",
        )
        .unwrap();
        assert!(runtime.get_operation_receipt(&updated).unwrap().is_some());
        let stored = runtime.get_object("line-7").unwrap().unwrap();
        assert_eq!(stored.kind, KIND);
        assert_eq!(stored.properties["responsibility"], "line:7,line:8");
        // Rebinding to an uncertified revision is checked again.
        let message = refusal(admit(
            &runtime,
            ACTION_UPDATE,
            json!({"object_id": "line-7", "definition_revision_digest": uncertified}),
            "rebind",
        ));
        assert!(message.contains("no current certification"), "{message}");
        // Wake tokens are checked on every write (#1951).
        let message = refusal(admit(
            &runtime,
            ACTION_UPDATE,
            json!({"object_id": "line-7", WAKE_POLICIES_PROPERTY: "nightly"}),
            "bad-wake",
        ));
        assert!(message.contains("unknown wake policy"), "{message}");
        admit(
            &runtime,
            ACTION_UPDATE,
            json!({"object_id": "line-7", WAKE_POLICIES_PROPERTY: "schedule:3600000"}),
            "wake",
        )
        .unwrap();
    }

    /// A frozen instance's principal is refused new Actions with a named,
    /// recorded denial; other principals are not; unfreeze restores
    /// admission (#1934).
    #[test]
    fn freezing_refuses_the_instance_principal_until_unfrozen() {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        let certified = published_revision(&runtime, "", true);
        admit(
            &runtime,
            ACTION_CREATE,
            instance(&certified, "triage"),
            "create",
        )
        .unwrap();
        let principal = "org:line-7-agent";
        let touch = |key: &str, actor: &str| {
            admit_as(
                &runtime,
                ACTION_UPDATE,
                json!({"object_id": "line-7", "responsibility": format!("line:{key}")}),
                key,
                actor,
            )
            .unwrap()
        };
        assert_eq!(touch("before", principal).status, "admitted");

        admit(
            &runtime,
            ACTION_FREEZE,
            json!({"object_id": "line-7", "frozen": "true"}),
            "freeze",
        )
        .unwrap();
        assert!(require_not_frozen(&runtime.get_object("line-7").unwrap().unwrap()).is_err());
        let refused = touch("frozen", principal);
        assert_eq!(refused.status, "denied");
        assert_eq!(refused.deny_reason, "site agent instance line-7 is frozen");
        assert!(
            runtime
                .get_operation_receipt(&refused.operation_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(touch("other", ACTOR).status, "admitted");
        // Create and update cannot set the flag; only the freeze pair can.
        assert!(
            admit(
                &runtime,
                ACTION_UPDATE,
                json!({"object_id": "line-7", "frozen": "false"}),
                "sneak",
            )
            .is_err()
        );

        admit(
            &runtime,
            ACTION_UNFREEZE,
            json!({"object_id": "line-7", "frozen": "false"}),
            "thaw",
        )
        .unwrap();
        assert_eq!(touch("after", principal).status, "admitted");
    }
}
