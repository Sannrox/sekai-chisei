//! System One Function fill for object-bound Actions.
//!
//! The Function reads an authorized object projection and returns closed
//! Action parameters. It does not persist an instance or write the object.

use crate::chisei::egress::{self, ContextEgressRecord};
use crate::domain::Object;
use crate::sekai::governed_action_type::GovernedActionType;
use crate::sekai::schema::ObjectType;
use sekai_provider::system_one::{
    SystemOneBind, SystemOneRequest, SystemOneResponse, TypeSafeClient, parameters_from_answers,
    request_from_bind,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn bind_of(type_def: &GovernedActionType) -> Option<&SystemOneBind> {
    type_def.system_one.as_ref().filter(|bind| !bind.is_empty())
}

/// Empty caller parameters: a blank string, JSON `null`, or `{}`.
///
/// Any other JSON, including a partial object, is caller-supplied and is
/// not filled. Invalid JSON is not empty.
pub fn parameters_are_empty(parameters_json: &str) -> bool {
    let trimmed = parameters_json.trim();
    if trimmed.is_empty() {
        return true;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Null) => true,
        Ok(Value::Object(map)) => map.is_empty(),
        _ => false,
    }
}

pub fn should_fill(type_def: &GovernedActionType, parameters_json: &str) -> bool {
    parameters_are_empty(parameters_json) && bind_of(type_def).is_some()
}

/// Bind + parameter-body provenance for a filled or client-copied proposal.
///
/// Empty when the type has no bind. Submit does not re-invoke the Function;
/// admit attributes the type version's pinned bind to the admitted body.
pub fn fill_provenance_json(
    type_def: &GovernedActionType,
    parameters_json: &str,
) -> Result<String, String> {
    let Some(bind) = bind_of(type_def) else {
        return Ok(String::new());
    };
    let bind_canonical =
        serde_json::to_string(bind).map_err(|error| format!("system_one bind encode: {error}"))?;
    let bind_digest = format!("sha256:{:x}", Sha256::digest(bind_canonical.as_bytes()));
    let parameters: Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
    if !parameters.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }
    let parameter_canonical = serde_json::to_string(&parameters)
        .map_err(|error| format!("system_one parameter encode: {error}"))?;
    let parameter_digest = format!(
        "sha256:{:x}",
        Sha256::digest(parameter_canonical.as_bytes())
    );
    serde_json::to_string(&serde_json::json!({
        "model": bind.model,
        "type_id": type_def.type_id,
        "version": type_def.version,
        "bind_digest": bind_digest,
        "parameter_digest": parameter_digest,
    }))
    .map_err(|error| format!("system_one fill provenance encode: {error}"))
}

pub fn project_object_state(
    object: &Object,
    object_type: Option<&ObjectType>,
) -> (Value, ContextEgressRecord) {
    let mut record = egress::new_record(object);
    let mut state = Map::new();
    if egress::include_identity(object) {
        state.insert("id".into(), Value::String(object.id.clone()));
        if !object.name.is_empty() {
            state.insert("name".into(), Value::String(object.name.clone()));
        }
        if !object.external_id.is_empty() {
            state.insert(
                "external_id".into(),
                Value::String(object.external_id.clone()),
            );
        }
    }
    let mut fields = object.properties.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    for field in fields {
        if let Some(value) =
            egress::filter_property_with_schema(object, &field, object_type, &mut record, true)
        {
            state.insert(field, Value::String(value));
        }
    }
    (Value::Object(state), record)
}

pub fn request_for_object(
    type_def: &GovernedActionType,
    object: &Object,
    object_type: Option<&ObjectType>,
) -> Result<(SystemOneRequest, ContextEgressRecord), String> {
    let bind = bind_of(type_def).ok_or_else(|| "action type has no system_one bind".to_string())?;
    let (state, record) = project_object_state(object, object_type);
    Ok((request_from_bind(bind, state)?, record))
}

pub fn proposed_parameters(
    type_def: &GovernedActionType,
    object: &Object,
    response: &SystemOneResponse,
) -> Result<String, String> {
    let bind = bind_of(type_def).ok_or_else(|| "action type has no system_one bind".to_string())?;
    let parameters = parameters_from_answers(bind, response, &object.id)?;
    crate::chisei::evaluation_plan::validate_parameters(
        &type_def.parameter_schema_json,
        &parameters,
    )
    .map_err(|error| format!("system_one parameters invalid: {error}"))?;
    Ok(parameters)
}

pub async fn fill_proposed_parameters(
    type_def: &GovernedActionType,
    object: &Object,
    object_type: Option<&ObjectType>,
    client: &TypeSafeClient,
) -> Result<(String, ContextEgressRecord), String> {
    let (request, record) = request_for_object(type_def, object, object_type)?;
    let response = client.evaluate(&request).await?;
    Ok((proposed_parameters(type_def, object, &response)?, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::governed_action_type::{GovernedActionType, OBJECT_MUTATION_UPDATE};
    use sekai_provider::system_one::SystemOneQuestionBind;
    use serde_json::json;
    use std::collections::HashMap;

    fn type_def() -> GovernedActionType {
        GovernedActionType {
            namespace: "acme".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            description: "Triage a support ticket".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"department":{"type":"string","enum":["billing","technical","sales"]}},"required":["object_id","department"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            object_kind: "support_ticket".into(),
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            system_one: Some(SystemOneBind {
                model: "jev-1.13.0".into(),
                questions: vec![SystemOneQuestionBind {
                    parameter: "department".into(),
                    question_type: "choice".into(),
                    instructions: "Which team should handle this".into(),
                    criteria: json!({"billing": null, "technical": null, "sales": null}),
                }],
            }),
            enabled: true,
            ..Default::default()
        }
    }

    fn object() -> Object {
        Object {
            id: "ticket-1".into(),
            kind: "support_ticket".into(),
            name: "hidden-name".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("title".into(), "payouts failing".into()),
                (egress::EXTERNAL_PROPERTIES_KEY.into(), "title".into()),
                ("secret".into(), "do-not-send".into()),
            ]),
            created: 1,
            updated: 2,
        }
    }

    #[test]
    fn state_omits_ungranted_fields_and_identity() {
        let (state, record) = project_object_state(&object(), None);
        assert_eq!(state, json!({"title": "payouts failing"}));
        assert!(record.redacted_fields.contains(&"secret".to_string()));
        assert!(!state.as_object().unwrap().contains_key("id"));
        assert!(!state.as_object().unwrap().contains_key("name"));
    }

    #[test]
    fn empty_parameters_select_the_bind() {
        assert!(should_fill(&type_def(), ""));
        assert!(should_fill(&type_def(), "   "));
        assert!(should_fill(&type_def(), "{}"));
        assert!(should_fill(&type_def(), "  {}  "));
        assert!(should_fill(&type_def(), "null"));
        assert!(!should_fill(&type_def(), "{"));
        assert!(!should_fill(&type_def(), r#"{"object_id":"ticket-1"}"#));
        assert!(!should_fill(
            &type_def(),
            r#"{"object_id":"ticket-1","department":"technical"}"#
        ));
        let mut unbound = type_def();
        unbound.system_one = None;
        assert!(!should_fill(&unbound, ""));
        assert!(!should_fill(&unbound, "{}"));
    }

    #[test]
    fn fill_provenance_binds_model_and_parameter_body() {
        let filled = r#"{"object_id":"ticket-1","department":"technical"}"#;
        let first = fill_provenance_json(&type_def(), filled).unwrap();
        let again = fill_provenance_json(&type_def(), filled).unwrap();
        assert_eq!(first, again);
        let value: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(value["model"], "jev-1.13.0");
        assert_eq!(value["type_id"], "support.triage");
        assert_eq!(value["version"], "1");
        assert!(
            value["bind_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            value["parameter_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        let other = fill_provenance_json(
            &type_def(),
            r#"{"object_id":"ticket-1","department":"billing"}"#,
        )
        .unwrap();
        assert_ne!(first, other);
        let mut unbound = type_def();
        unbound.system_one = None;
        assert_eq!(fill_provenance_json(&unbound, filled).unwrap(), "");
    }

    #[test]
    fn out_of_enum_choice_fails_closed() {
        let response = SystemOneResponse {
            model: "jev-1.13.0".into(),
            answers: [(
                "department".into(),
                json!({"type":"choice","choice":"marketing"}),
            )]
            .into_iter()
            .collect(),
            usage: None,
        };
        let error = proposed_parameters(&type_def(), &object(), &response).unwrap_err();
        assert!(error.contains("system_one parameters invalid"), "{error}");
    }

    #[tokio::test]
    async fn empty_parameters_fill_from_fixture_answers() {
        let app = axum::Router::new().route(
            "/v1/systemone",
            axum::routing::post(|| async {
                axum::Json(SystemOneResponse {
                    model: "jev-1.13.0".into(),
                    answers: [(
                        "department".into(),
                        json!({"type":"choice","choice":"technical"}),
                    )]
                    .into_iter()
                    .collect(),
                    usage: None,
                })
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = TypeSafeClient::new("test-key", format!("http://{addr}/v1/systemone"));
        let (filled, record) = fill_proposed_parameters(&type_def(), &object(), None, &client)
            .await
            .unwrap();
        assert!(record.included_fields.contains(&"title".to_string()));
        assert!(record.redacted_fields.contains(&"secret".to_string()));
        let parameters: Value = serde_json::from_str(&filled).unwrap();
        assert_eq!(
            parameters,
            json!({"object_id":"ticket-1","department":"technical"})
        );
    }

    #[test]
    fn answers_become_submitable_parameters() {
        let response = SystemOneResponse {
            model: "jev-1.13.0".into(),
            answers: [(
                "department".into(),
                json!({"type":"choice","choice":"technical"}),
            )]
            .into_iter()
            .collect(),
            usage: None,
        };
        let parameters: Value =
            serde_json::from_str(&proposed_parameters(&type_def(), &object(), &response).unwrap())
                .unwrap();
        assert_eq!(
            parameters,
            json!({"object_id":"ticket-1","department":"technical"})
        );
    }
}
