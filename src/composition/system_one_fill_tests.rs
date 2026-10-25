//! HTTP fixture for `fill_proposed_parameters`. The axum server stays in the
//! composition crate so `chisei-core` does not take an HTTP-server dependency.

use crate::chisei::object_schema::ObjectType;
use crate::chisei::system_one_action::{SystemOneActionType, fill_proposed_parameters};
use crate::domain::Object;
use chisei_provider::system_one::{SystemOneBind, SystemOneQuestionBind, SystemOneResponse};
use serde_json::json;
use std::collections::HashMap;

struct TestActionType {
    type_id: String,
    version: String,
    parameter_schema_json: String,
    system_one: Option<SystemOneBind>,
}

impl SystemOneActionType for TestActionType {
    fn type_id(&self) -> &str {
        &self.type_id
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn parameter_schema_json(&self) -> &str {
        &self.parameter_schema_json
    }
    fn system_one(&self) -> Option<&SystemOneBind> {
        self.system_one.as_ref()
    }
}

fn type_def() -> TestActionType {
    TestActionType {
        type_id: "support.triage".into(),
        version: "1".into(),
        parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"department":{"type":"string","enum":["billing","technical","sales"]}},"required":["object_id","department"],"additionalProperties":false}"#.into(),
        system_one: Some(SystemOneBind {
            model: "jev-1.13.0".into(),
            questions: vec![SystemOneQuestionBind {
                parameter: "department".into(),
                question_type: "choice".into(),
                instructions: "Which team should handle this".into(),
                criteria: json!({"billing": null, "technical": null, "sales": null}),
            }],
        }),
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
            (
                crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                "title".into(),
            ),
            ("secret".into(), "do-not-send".into()),
        ]),
        created: 1,
        updated: 2,
    }
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
                    json!({"type": "choice", "choice": "technical"}),
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
    let client = chisei_provider::system_one::TypeSafeClient::new(
        "test-key",
        format!("http://{addr}/v1/systemone"),
    );
    let (filled, record) =
        fill_proposed_parameters(&type_def(), &object(), None::<&ObjectType>, &client)
            .await
            .unwrap();
    assert!(record.included_fields.contains(&"title".to_string()));
    assert!(record.redacted_fields.contains(&"secret".to_string()));
    let parameters: serde_json::Value = serde_json::from_str(&filled).unwrap();
    assert_eq!(
        parameters,
        json!({"object_id": "ticket-1", "department": "technical"})
    );
}
