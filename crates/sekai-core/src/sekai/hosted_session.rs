//! Bounded hosted session (#2132).
//!
//! A session is an ordinary object. Join and intent are governed Actions.
//! The host owns the clock, the membership cap, and persistence. Domain
//! maths stay in the workload: this module records an intent at host time
//! onto the member's graph. Direct object writes of these kinds are refused.
//! A read view returns the caller's graph only.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::action_instance::PlanReference;
use crate::sekai::action_object_mutation::Submitter;
use crate::sekai::action_type_criteria::{
    ActionSubmissionCriterion, CRITERION_KIND_SUBJECT_EQUALS_PROPERTY,
};
use crate::sekai::governed_action_type::{
    EFFECT_KIND_NOTIFY, GovernedActionType, OBJECT_MUTATION_CREATE, OBJECT_MUTATION_UPDATE,
};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, default_property_classification,
};
use serde_json::{Value, json};

pub const CONTRACT: &str = "sekai.hosted-session/v1";
pub const SESSION_KIND: &str = "hosted_session";
pub const MEMBER_KIND: &str = "hosted_session_member";
pub const ACTION_CREATE: &str = "hosted_session.create";
pub const ACTION_JOIN: &str = "hosted_session.join";
pub const ACTION_INTENT: &str = "hosted_session.intent";
pub const ACTION_VERSION: &str = "1";
pub const GRAPH_PROPERTY: &str = "graph";
pub const APPLIED_AT_PROPERTY: &str = "applied_at_ms";
const MEMBER_CRITERION: &str = "member_owns_graph";

/// Session plus the caller's graph. Other members' graphs are omitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub session_id: String,
    pub seed: String,
    pub cap: u32,
    pub members: Vec<String>,
    pub graph: Option<String>,
    pub applied_at_ms: Option<i64>,
}

/// True for the session and member kinds, which change only through Actions.
pub fn is_action_only_kind(kind: &str) -> bool {
    kind == SESSION_KIND || kind == MEMBER_KIND
}

/// Canonical member object id. `session_id` and `member_id` must not contain
/// `:` or whitespace.
pub fn member_object_id(session_id: &str, member_id: &str) -> String {
    format!("hs:{session_id}:{member_id}")
}

/// Register the session and member types and their Actions. Idempotent.
pub fn install(db: &RuntimeDb, namespace: &str, actor: &str, now_ms: i64) -> Result<(), String> {
    db.upsert_object_type(&ObjectType {
        kind: SESSION_KIND.into(),
        description: "Bounded hosted session (sekai.hosted-session/v1)".into(),
        properties: vec![
            property("seed", true, "Host seed or session identity.", "public"),
            property(
                "cap",
                true,
                "Maximum members the host will admit.",
                "public",
            ),
        ],
        is_builtin: false,
        implements: Vec::new(),
    })?;
    db.upsert_object_type(&ObjectType {
        kind: MEMBER_KIND.into(),
        description: "Hosted session member graph (sekai.hosted-session/v1)".into(),
        properties: vec![
            property("session_id", true, "Session this member joined.", "public"),
            property(
                "member_id",
                true,
                "Principal that owns this graph.",
                "public",
            ),
            property(
                GRAPH_PROPERTY,
                true,
                "Opaque member graph. Hidden from other members.",
                "sensitive",
            ),
            property(
                APPLIED_AT_PROPERTY,
                false,
                "Host clock of the last applied intent.",
                "public",
            ),
        ],
        is_builtin: false,
        implements: Vec::new(),
    })?;
    put_action(
        db,
        namespace,
        ActionSpec {
            type_id: ACTION_CREATE,
            object_kind: SESSION_KIND,
            mutation: OBJECT_MUTATION_CREATE,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "object_id": {"type": "string"},
                    "name": {"type": "string"},
                    "seed": {"type": "string", "minLength": 1},
                    "cap": {"type": "integer", "minimum": 1},
                },
                "required": ["object_id", "seed", "cap"],
            }),
            submission_criteria: Vec::new(),
        },
        actor,
        now_ms,
    )?;
    put_action(
        db,
        namespace,
        ActionSpec {
            type_id: ACTION_JOIN,
            object_kind: MEMBER_KIND,
            mutation: OBJECT_MUTATION_CREATE,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "object_id": {"type": "string"},
                    "name": {"type": "string"},
                    "session_id": {"type": "string", "minLength": 1},
                    "member_id": {"type": "string", "minLength": 1},
                },
                "required": ["object_id", "session_id", "member_id"],
            }),
            submission_criteria: Vec::new(),
        },
        actor,
        now_ms,
    )?;
    put_action(
        db,
        namespace,
        ActionSpec {
            type_id: ACTION_INTENT,
            object_kind: MEMBER_KIND,
            mutation: OBJECT_MUTATION_UPDATE,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "object_id": {"type": "string"},
                    "intent": {"type": "string", "minLength": 1},
                    "client_clock_ms": {"type": "integer"},
                },
                "required": ["object_id", "intent"],
            }),
            submission_criteria: vec![ActionSubmissionCriterion {
                criterion_id: MEMBER_CRITERION.into(),
                kind: CRITERION_KIND_SUBJECT_EQUALS_PROPERTY.into(),
                property: "member_id".into(),
                value: String::new(),
            }],
        },
        actor,
        now_ms,
    )?;
    Ok(())
}

/// Session object a join read, so the admission write serializes against it.
pub fn plan_references(
    db: &RuntimeDb,
    planned: &Object,
    mutation: &str,
) -> Result<Vec<PlanReference>, String> {
    if planned.kind != MEMBER_KIND || mutation != OBJECT_MUTATION_CREATE {
        return Ok(Vec::new());
    }
    let Some(session_id) = planned
        .properties
        .get("session_id")
        .filter(|id| !id.is_empty())
    else {
        return Ok(Vec::new());
    };
    Ok(vec![match db.get_object(session_id)? {
        Some(session) if session.kind == SESSION_KIND => PlanReference::Present(session),
        _ => PlanReference::Absent(session_id.clone()),
    }])
}

/// Apply `intent` onto `planned` from the object snapshot already merged
/// into it, at the host clock. Client timestamps stay in the Action
/// parameters and never become object properties.
pub fn stamp_intent(
    planned: &mut Object,
    parameters_json: &str,
    now_ms: i64,
) -> Result<(), String> {
    if planned.kind != MEMBER_KIND {
        return Ok(());
    }
    let parameters: Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("parameters_json: {error}"))?;
    let intent = parameters
        .get("intent")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "intent is required".to_string())?;
    let graph = planned
        .properties
        .get(GRAPH_PROPERTY)
        .map(String::as_str)
        .unwrap_or("[]");
    let applied = apply_graph(graph, intent, now_ms)?;
    planned.properties.insert(GRAPH_PROPERTY.into(), applied);
    planned
        .properties
        .insert(APPLIED_AT_PROPERTY.into(), now_ms.to_string());
    Ok(())
}

/// Refusal when `members` already fills `session`'s cap. `None` while a
/// seat remains.
pub fn join_cap_refusal(session: &Object, members: u32) -> Result<Option<String>, String> {
    if session.kind != SESSION_KIND {
        return Ok(None);
    }
    let cap = parse_cap(
        session
            .properties
            .get("cap")
            .map(String::as_str)
            .unwrap_or(""),
    )?;
    Ok((members >= cap).then(|| format!("hosted session {} is at cap {cap}", session.id)))
}

/// Rewrite Action parameters so the object write uses host membership.
/// Intent application waits for the plan snapshot so a concurrent intent
/// cannot overwrite a committed graph. Client timestamps are dropped.
pub fn rewrite_parameters(
    db: &RuntimeDb,
    type_def: &GovernedActionType,
    namespace: &str,
    parameters_json: &str,
    submitter: Option<Submitter<'_>>,
    _now_ms: i64,
) -> Result<String, String> {
    let parameters: Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("parameters_json: {error}"))?;
    match type_def.type_id.as_str() {
        ACTION_CREATE => rewrite_create(&parameters),
        ACTION_JOIN => rewrite_join(db, namespace, &parameters, submitter),
        ACTION_INTENT => rewrite_intent(db, namespace, &parameters, submitter),
        other => Err(format!("unsupported hosted session Action {other}")),
    }
}

/// Session metadata and the caller's graph only.
pub fn read_view(
    db: &RuntimeDb,
    namespace: &str,
    session_id: &str,
    principal: &str,
) -> Result<SessionView, String> {
    let session = db
        .get_object(session_id)?
        .filter(|object| object.kind == SESSION_KIND && object.namespace == namespace)
        .ok_or_else(|| format!("hosted session {session_id} not found"))?;
    let cap = parse_cap(
        session
            .properties
            .get("cap")
            .map(String::as_str)
            .unwrap_or(""),
    )?;
    let mut members = db
        .find_by_property(MEMBER_KIND, "session_id", session_id)?
        .into_iter()
        .filter(|member| member.namespace == namespace)
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.id.cmp(&right.id));
    let member_ids = members
        .iter()
        .filter_map(|member| member.properties.get("member_id").cloned())
        .collect();
    let own = members
        .iter()
        .find(|member| member.properties.get("member_id").map(String::as_str) == Some(principal));
    Ok(SessionView {
        session_id: session.id,
        seed: session.properties.get("seed").cloned().unwrap_or_default(),
        cap,
        members: member_ids,
        graph: own.and_then(|member| member.properties.get(GRAPH_PROPERTY).cloned()),
        applied_at_ms: own.and_then(|member| {
            member
                .properties
                .get(APPLIED_AT_PROPERTY)
                .and_then(|value| value.parse().ok())
        }),
    })
}

/// Record `intent` on `graph` at the host clock. Workload libraries replace
/// this with domain apply; the host never interprets the intent.
pub fn apply_graph(graph: &str, intent: &str, host_clock_ms: i64) -> Result<String, String> {
    let mut events: Vec<Value> = if graph.trim().is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str(graph) {
            Ok(Value::Array(events)) => events,
            Ok(other) => vec![other],
            Err(_) => vec![json!({ "state": graph })],
        }
    };
    events.push(json!({
        "intent": intent,
        "applied_at_ms": host_clock_ms,
    }));
    serde_json::to_string(&events).map_err(|error| error.to_string())
}

fn rewrite_create(parameters: &Value) -> Result<String, String> {
    let object_id = required_token(parameters, "object_id")?;
    let seed = required_token(parameters, "seed")?;
    let cap = json_u32(parameters, "cap")?;
    Ok(json!({
        "object_id": object_id,
        "seed": seed,
        "cap": cap.to_string(),
    })
    .to_string())
}

fn rewrite_join(
    db: &RuntimeDb,
    namespace: &str,
    parameters: &Value,
    submitter: Option<Submitter<'_>>,
) -> Result<String, String> {
    let object_id = required_object_id(parameters)?;
    let session_id = required_token(parameters, "session_id")?;
    let member_id = required_token(parameters, "member_id")?;
    if object_id != member_object_id(&session_id, &member_id) {
        return Err(format!(
            "object_id must be {}",
            member_object_id(&session_id, &member_id)
        ));
    }
    require_self(submitter, &member_id)?;
    let session = db
        .get_object(&session_id)?
        .filter(|object| object.kind == SESSION_KIND && object.namespace == namespace)
        .ok_or_else(|| format!("hosted session {session_id} not found"))?;
    let cap = parse_cap(
        session
            .properties
            .get("cap")
            .map(String::as_str)
            .unwrap_or(""),
    )?;
    let members = db
        .find_by_property(MEMBER_KIND, "session_id", &session_id)?
        .into_iter()
        .filter(|member| member.namespace == namespace)
        .count();
    if members >= cap as usize {
        return Err(format!("hosted session {session_id} is at cap {cap}"));
    }
    Ok(json!({
        "object_id": object_id,
        "session_id": session_id,
        "member_id": member_id,
        "graph": "[]",
    })
    .to_string())
}

fn rewrite_intent(
    db: &RuntimeDb,
    namespace: &str,
    parameters: &Value,
    submitter: Option<Submitter<'_>>,
) -> Result<String, String> {
    let object_id = required_object_id(parameters)?;
    if parameters
        .get("intent")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err("intent is required".into());
    }
    let existing = db
        .get_object(&object_id)?
        .filter(|object| object.kind == MEMBER_KIND && object.namespace == namespace)
        .ok_or_else(|| format!("hosted session member {object_id} not found"))?;
    let member_id = existing
        .properties
        .get("member_id")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "member_id is required".to_string())?;
    require_self(submitter, member_id)?;
    Ok(json!({ "object_id": object_id }).to_string())
}

fn require_self(submitter: Option<Submitter<'_>>, member_id: &str) -> Result<(), String> {
    match submitter {
        Some(submitter) if submitter.principal == member_id => Ok(()),
        Some(submitter) => Err(format!(
            "principal {} cannot act as hosted session member {member_id}",
            submitter.principal
        )),
        None => Err("hosted session join and intent require a submitter".into()),
    }
}

fn required_object_id(parameters: &Value) -> Result<String, String> {
    let value = parameters
        .get("object_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "object_id is required".to_string())?;
    if value.chars().any(char::is_whitespace) {
        return Err("object_id must not contain whitespace".into());
    }
    Ok(value.to_string())
}

fn required_token(parameters: &Value, field: &str) -> Result<String, String> {
    let value = parameters
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field} is required"))?;
    if value.chars().any(|ch| ch.is_whitespace() || ch == ':') {
        return Err(format!("{field} must not contain whitespace or ':'"));
    }
    Ok(value.to_string())
}

fn json_u32(parameters: &Value, field: &str) -> Result<u32, String> {
    let parsed = match parameters.get(field) {
        Some(Value::Number(number)) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
        Some(Value::String(text)) => text.parse().ok(),
        _ => None,
    };
    parsed
        .filter(|value| *value >= 1)
        .ok_or_else(|| format!("{field} must be an integer >= 1"))
}

fn parse_cap(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value >= 1)
        .ok_or_else(|| "cap must be an integer >= 1".into())
}

fn property(name: &str, required: bool, description: &str, classification: &str) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        prop_type: PropertyType::String,
        required,
        description: description.into(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: if classification == "public" {
            default_property_classification()
        } else {
            classification.into()
        },
        struct_fields: Vec::new(),
    }
}

struct ActionSpec {
    type_id: &'static str,
    object_kind: &'static str,
    mutation: &'static str,
    schema: Value,
    submission_criteria: Vec<ActionSubmissionCriterion>,
}

fn put_action(
    db: &RuntimeDb,
    namespace: &str,
    spec: ActionSpec,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    db.put_governed_action_type(
        GovernedActionType {
            namespace: namespace.into(),
            type_id: spec.type_id.into(),
            version: ACTION_VERSION.into(),
            description: format!("{}: write a {CONTRACT} object", spec.type_id),
            parameter_schema_json: spec.schema.to_string(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: spec.object_kind.into(),
            object_mutation: spec.mutation.into(),
            enabled: true,
            submission_criteria: spec.submission_criteria,
            ..Default::default()
        },
        actor,
        now_ms,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::action_instance::STATUS_ADMITTED;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NAMESPACE: &str = "shard";
    const HOST: &str = "host";
    const ALICE: &str = "alice";
    const BOB: &str = "bob";
    const CAROL: &str = "carol";
    const SESSION: &str = "session-1";

    fn admit(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
        actor: &str,
        now_ms: i64,
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
                now_ms,
            )
            .map(|admitted| admitted.instance)
    }

    fn refusal(
        outcome: Result<
            crate::sekai::action_instance::ActionInstance,
            ActionInstanceAdmissionError,
        >,
    ) -> String {
        match outcome {
            Err(ActionInstanceAdmissionError::FailedPrecondition(message)) => message,
            other => panic!("expected FailedPrecondition, got {other:?}"),
        }
    }

    fn open() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, HOST, 1_000).unwrap();
        runtime
    }

    fn create_session(runtime: &RuntimeDb) {
        let instance = admit(
            runtime,
            ACTION_CREATE,
            json!({"object_id": SESSION, "seed": "seed-7", "cap": 2}),
            "create",
            HOST,
            1_000,
        )
        .unwrap();
        assert_eq!(instance.status, STATUS_ADMITTED);
    }

    fn join(runtime: &RuntimeDb, member: &str, key: &str, now_ms: i64) {
        let instance = admit(
            runtime,
            ACTION_JOIN,
            json!({
                "object_id": member_object_id(SESSION, member),
                "session_id": SESSION,
                "member_id": member,
            }),
            key,
            member,
            now_ms,
        )
        .unwrap();
        assert_eq!(instance.status, STATUS_ADMITTED);
    }

    #[test]
    fn a_session_id_with_a_colon_cannot_be_created() {
        let runtime = open();
        let message = refusal(admit(
            &runtime,
            ACTION_CREATE,
            json!({"object_id": "room:1", "seed": "seed-7", "cap": 1}),
            "create-colon",
            HOST,
            1_000,
        ));
        assert!(
            message.contains("object_id must not contain whitespace or ':'"),
            "{message}"
        );
    }

    #[test]
    fn two_members_join_and_a_third_is_refused() {
        let runtime = open();
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        join(&runtime, BOB, "join-b", 2_100);
        let message = refusal(admit(
            &runtime,
            ACTION_JOIN,
            json!({
                "object_id": member_object_id(SESSION, CAROL),
                "session_id": SESSION,
                "member_id": CAROL,
            }),
            "join-c",
            CAROL,
            2_200,
        ));
        assert!(message.contains("at cap 2"), "{message}");
        let view = read_view(&runtime, NAMESPACE, SESSION, ALICE).unwrap();
        assert_eq!(view.members, vec![ALICE.to_string(), BOB.to_string()]);
        assert_eq!(view.graph.as_deref(), Some("[]"));
    }

    #[test]
    fn intent_uses_the_host_clock_and_ignores_a_client_stamp() {
        let runtime = open();
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        let instance = admit(
            &runtime,
            ACTION_INTENT,
            json!({
                "object_id": member_object_id(SESSION, ALICE),
                "intent": "move",
                "client_clock_ms": 1,
            }),
            "intent-1",
            ALICE,
            9_000,
        )
        .unwrap();
        assert_eq!(instance.status, STATUS_ADMITTED);
        let stored = runtime
            .get_object(&member_object_id(SESSION, ALICE))
            .unwrap()
            .unwrap();
        assert_eq!(stored.properties[APPLIED_AT_PROPERTY], "9000");
        assert!(!stored.properties.contains_key("client_clock_ms"));
        assert!(!stored.properties.contains_key("intent"));
        let graph: Value = serde_json::from_str(&stored.properties[GRAPH_PROPERTY]).unwrap();
        assert_eq!(graph[0]["applied_at_ms"], 9_000);
        assert_eq!(graph[0]["intent"], "move");
        let view = read_view(&runtime, NAMESPACE, SESSION, ALICE).unwrap();
        assert_eq!(view.applied_at_ms, Some(9_000));
    }

    #[test]
    fn duplicate_idempotency_does_not_apply_twice() {
        let runtime = open();
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        let first = admit(
            &runtime,
            ACTION_INTENT,
            json!({
                "object_id": member_object_id(SESSION, ALICE),
                "intent": "fire",
            }),
            "same-key",
            ALICE,
            4_000,
        )
        .unwrap();
        let second = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    agent_turn: None,
                    namespace: NAMESPACE.into(),
                    type_id: ACTION_INTENT.into(),
                    version: ACTION_VERSION.into(),
                    parameters_json: json!({
                        "object_id": member_object_id(SESSION, ALICE),
                        "intent": "fire",
                    })
                    .to_string(),
                    idempotency_key: "same-key".into(),
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
                ALICE,
                4_500,
            )
            .unwrap();
        assert!(second.replay);
        assert_eq!(second.instance.instance_id, first.instance_id);
        let stored = runtime
            .get_object(&member_object_id(SESSION, ALICE))
            .unwrap()
            .unwrap();
        let graph: Vec<Value> = serde_json::from_str(&stored.properties[GRAPH_PROPERTY]).unwrap();
        assert_eq!(graph.len(), 1);
        assert_eq!(graph[0]["applied_at_ms"], 4_000);
    }

    #[test]
    fn a_member_cannot_write_or_read_another_member_graph() {
        let runtime = open();
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        join(&runtime, BOB, "join-b", 2_100);
        admit(
            &runtime,
            ACTION_INTENT,
            json!({
                "object_id": member_object_id(SESSION, ALICE),
                "intent": "secret",
            }),
            "alice-secret",
            ALICE,
            3_000,
        )
        .unwrap();
        let denied = admit(
            &runtime,
            ACTION_INTENT,
            json!({
                "object_id": member_object_id(SESSION, ALICE),
                "intent": "steal",
            }),
            "bob-steal",
            BOB,
            3_100,
        )
        .unwrap();
        assert_eq!(denied.status, "denied");
        assert_eq!(denied.deny_reason, MEMBER_CRITERION);
        let alice = read_view(&runtime, NAMESPACE, SESSION, ALICE).unwrap();
        let bob = read_view(&runtime, NAMESPACE, SESSION, BOB).unwrap();
        assert!(
            alice
                .graph
                .as_ref()
                .is_some_and(|graph| graph.contains("secret"))
        );
        assert_eq!(bob.graph.as_deref(), Some("[]"));
        assert!(!bob.graph.as_deref().unwrap_or_default().contains("secret"));
    }

    #[test]
    fn restart_resumes_the_session_from_durable_state() {
        let path = std::env::temp_dir().join(format!(
            "hosted-session-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path_str = path.to_str().expect("utf-8 path");
        {
            let runtime = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path_str).unwrap()));
            install(&runtime, NAMESPACE, HOST, 1_000).unwrap();
            create_session(&runtime);
            join(&runtime, ALICE, "join-a", 2_000);
            admit(
                &runtime,
                ACTION_INTENT,
                json!({
                    "object_id": member_object_id(SESSION, ALICE),
                    "intent": "hold",
                }),
                "hold",
                ALICE,
                6_000,
            )
            .unwrap();
        }
        let runtime = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path_str).unwrap()));
        let view = read_view(&runtime, NAMESPACE, SESSION, ALICE).unwrap();
        assert_eq!(view.seed, "seed-7");
        assert_eq!(view.applied_at_ms, Some(6_000));
        assert!(
            view.graph
                .as_ref()
                .is_some_and(|graph| graph.contains("hold"))
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }

    #[test]
    fn concurrent_joins_at_the_last_seat_admit_exactly_one() {
        let runtime = std::sync::Arc::new(open());
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = [BOB, CAROL].map(|member| {
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admit(
                    &runtime,
                    ACTION_JOIN,
                    json!({
                        "object_id": member_object_id(SESSION, member),
                        "session_id": SESSION,
                        "member_id": member,
                    }),
                    &format!("join-{member}"),
                    member,
                    3_000,
                )
            })
        });
        let outcomes = handles.map(|handle| handle.join().expect("join thread"));
        let admitted = outcomes
            .iter()
            .filter(|outcome| {
                outcome
                    .as_ref()
                    .is_ok_and(|instance| instance.status == STATUS_ADMITTED)
            })
            .count();
        let refused = outcomes.iter().filter(|outcome| outcome.is_err()).count();
        assert_eq!(admitted, 1, "{outcomes:?}");
        assert_eq!(refused, 1, "{outcomes:?}");
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                Err(ActionInstanceAdmissionError::FailedPrecondition(message))
                    if message.contains("at cap 2")
            )),
            "{outcomes:?}"
        );
        let view = read_view(&runtime, NAMESPACE, SESSION, ALICE).unwrap();
        assert_eq!(view.members.len(), 2);
    }

    #[test]
    fn concurrent_intents_keep_every_committed_event() {
        let runtime = std::sync::Arc::new(open());
        create_session(&runtime);
        join(&runtime, ALICE, "join-a", 2_000);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = ["alpha", "beta"].map(|intent| {
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admit(
                    &runtime,
                    ACTION_INTENT,
                    json!({
                        "object_id": member_object_id(SESSION, ALICE),
                        "intent": intent,
                    }),
                    &format!("intent-{intent}"),
                    ALICE,
                    4_000,
                )
            })
        });
        let outcomes = handles.map(|handle| handle.join().expect("intent thread"));
        let mut applied = 0;
        for (intent, outcome) in ["alpha", "beta"].into_iter().zip(outcomes) {
            match outcome {
                Ok(instance) if instance.status == STATUS_ADMITTED => applied += 1,
                Err(_) => {
                    let retried = admit(
                        &runtime,
                        ACTION_INTENT,
                        json!({
                            "object_id": member_object_id(SESSION, ALICE),
                            "intent": intent,
                        }),
                        &format!("intent-{intent}-retry"),
                        ALICE,
                        4_100,
                    )
                    .unwrap();
                    assert_eq!(retried.status, STATUS_ADMITTED);
                    applied += 1;
                }
                other => panic!("unexpected intent outcome {other:?}"),
            }
        }
        assert_eq!(applied, 2);
        let stored = runtime
            .get_object(&member_object_id(SESSION, ALICE))
            .unwrap()
            .unwrap();
        let graph: Vec<Value> = serde_json::from_str(&stored.properties[GRAPH_PROPERTY]).unwrap();
        let intents: Vec<&str> = graph
            .iter()
            .filter_map(|event| event["intent"].as_str())
            .collect();
        assert_eq!(graph.len(), 2, "{graph:?}");
        assert!(intents.contains(&"alpha"), "{intents:?}");
        assert!(intents.contains(&"beta"), "{intents:?}");
    }
}
