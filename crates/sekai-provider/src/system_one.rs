//! TypeSafe System One client and Action-parameter mapping.
//!
//! Jev is a decision Function, not a chat provider. Callers send a redacted
//! object projection as `state` plus typed questions and receive Choice, Score,
//! and Noul answers that map onto a closed Action parameter schema.

use super::llm::{
    HttpTimeouts, ProviderError, classify_reqwest_error, encode_provider_error,
    read_bounded_response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::env;

pub const DEFAULT_SYSTEM_ONE_URL: &str = "https://api.typesafe.ai/v1/systemone";
pub const API_KEY_ENV: &str = "TYPESAFE_API_KEY";
pub const BASE_URL_ENV: &str = "TYPESAFE_BASE_URL";
pub const MOVING_ALIAS: &str = "jev-latest";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemOneQuestion {
    #[serde(rename = "type")]
    pub question_type: String,
    pub instructions: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub criteria: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneRequest {
    pub state: Value,
    pub model: String,
    pub questions: BTreeMap<String, SystemOneQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneUsage {
    #[serde(default)]
    pub input_tokens: i64,
    #[serde(default)]
    pub output_tokens: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneResponse {
    pub model: String,
    pub answers: BTreeMap<String, Value>,
    #[serde(default)]
    pub usage: Option<SystemOneUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemOneQuestionBind {
    pub parameter: String,
    #[serde(rename = "type")]
    pub question_type: String,
    pub instructions: String,
    #[serde(default)]
    pub criteria: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemOneBind {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub questions: Vec<SystemOneQuestionBind>,
}

impl SystemOneBind {
    pub fn is_empty(&self) -> bool {
        self.model.trim().is_empty() && self.questions.is_empty()
    }

    pub fn validate_pin(&self) -> Result<(), String> {
        let model = self.model.trim();
        if model.is_empty() {
            return Err("system_one.model is required".into());
        }
        if model == MOVING_ALIAS {
            return Err(format!(
                "system_one.model must be a pinned id, not {MOVING_ALIAS}"
            ));
        }
        if self.questions.is_empty() {
            return Err("system_one.questions must not be empty".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for question in &self.questions {
            let parameter = question.parameter.trim();
            if parameter.is_empty() {
                return Err("system_one question parameter is required".into());
            }
            if parameter == "object_id" {
                return Err("system_one cannot bind reserved parameter object_id".into());
            }
            if !seen.insert(parameter.to_string()) {
                return Err(format!("duplicate system_one parameter {parameter:?}"));
            }
            match question.question_type.trim() {
                "choice" | "score" | "noul" => {}
                other => {
                    return Err(format!(
                        "system_one question type must be choice, score, or noul, got {other:?}"
                    ));
                }
            }
            if question.instructions.trim().is_empty() {
                return Err(format!(
                    "system_one question {parameter:?} instructions are required"
                ));
            }
        }
        Ok(())
    }
}

pub fn validate_bind_against_schema(bind: &SystemOneBind, schema_json: &str) -> Result<(), String> {
    bind.validate_pin()?;
    let schema: Value = serde_json::from_str(schema_json)
        .map_err(|error| format!("parameter schema must be JSON: {error}"))?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "parameter schema properties object required".to_string())?;
    for question in &bind.questions {
        let parameter = question.parameter.trim();
        let property = properties.get(parameter).ok_or_else(|| {
            format!("system_one parameter {parameter:?} is not in the Action schema")
        })?;
        let declared = property
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("parameter {parameter:?} type required"))?;
        match question.question_type.trim() {
            "choice" => {
                if declared != "string" {
                    return Err(format!(
                        "choice parameter {parameter:?} must be a string enum"
                    ));
                }
                let values = property
                    .get("enum")
                    .and_then(Value::as_array)
                    .filter(|values| !values.is_empty())
                    .ok_or_else(|| {
                        format!("choice parameter {parameter:?} must declare a non-empty enum")
                    })?;
                if !values.iter().all(|value| value.is_string()) {
                    return Err(format!(
                        "choice parameter {parameter:?} enum must be strings"
                    ));
                }
            }
            "score" | "noul" if declared != "number" => {
                return Err(format!(
                    "{} parameter {parameter:?} must be a number",
                    question.question_type
                ));
            }
            "score" | "noul" => {}
            _ => {}
        }
    }
    Ok(())
}

pub fn request_from_bind(bind: &SystemOneBind, state: Value) -> Result<SystemOneRequest, String> {
    bind.validate_pin()?;
    let mut questions = BTreeMap::new();
    for question in &bind.questions {
        questions.insert(
            question.parameter.trim().to_string(),
            SystemOneQuestion {
                question_type: question.question_type.trim().to_string(),
                instructions: question.instructions.clone(),
                criteria: question.criteria.clone(),
            },
        );
    }
    Ok(SystemOneRequest {
        state,
        model: bind.model.trim().to_string(),
        questions,
    })
}

pub fn parameters_from_answers(
    bind: &SystemOneBind,
    response: &SystemOneResponse,
    object_id: &str,
) -> Result<String, String> {
    bind.validate_pin()?;
    let mut parameters = Map::new();
    parameters.insert("object_id".into(), Value::String(object_id.to_string()));
    for question in &bind.questions {
        let parameter = question.parameter.trim();
        let answer = response.answers.get(parameter).ok_or_else(|| {
            format!("system_one response missing answer for parameter {parameter:?}")
        })?;
        let answer_type = answer
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("system_one answer {parameter:?} is missing type"))?;
        if answer_type != question.question_type.trim() {
            return Err(format!(
                "system_one answer {parameter:?} type {answer_type:?} does not match bind"
            ));
        }
        let value = match answer_type {
            "choice" => {
                let choice = answer
                    .get("choice")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("choice answer {parameter:?} is missing choice"))?;
                Value::String(choice.to_string())
            }
            "score" => {
                let score = answer
                    .get("score")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| format!("score answer {parameter:?} is missing score"))?;
                number_value(score)
            }
            "noul" => {
                let noul = answer
                    .get("noul")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| format!("noul answer {parameter:?} is missing noul"))?;
                number_value(noul)
            }
            other => {
                return Err(format!(
                    "unsupported system_one answer type {other:?} for {parameter:?}"
                ));
            }
        };
        parameters.insert(parameter.to_string(), value);
    }
    serde_json::to_string(&Value::Object(parameters))
        .map_err(|error| format!("system_one parameters must serialize: {error}"))
}

fn number_value(value: f64) -> Value {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

pub struct TypeSafeClient {
    api_key: String,
    endpoint: String,
    client: reqwest::Client,
}

impl TypeSafeClient {
    pub fn from_env() -> Result<Self, String> {
        let api_key = env::var(API_KEY_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{API_KEY_ENV} not set"))?;
        let endpoint = env::var(BASE_URL_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_SYSTEM_ONE_URL.to_string());
        Ok(Self::new(api_key, endpoint))
    }

    pub fn new(api_key: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            endpoint: endpoint.into(),
            client: HttpTimeouts::from_env().client(),
        }
    }

    pub async fn evaluate(&self, request: &SystemOneRequest) -> Result<SystemOneResponse, String> {
        if request.model.trim() == MOVING_ALIAS {
            return Err(encode_provider_error(ProviderError::Precondition(format!(
                "system_one.model must be a pinned id, not {MOVING_ALIAS}"
            ))));
        }
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .await
            .map_err(|error| classify_reqwest_error("system one", error))?;
        let status = response.status();
        let body = read_bounded_response(response, "system one").await?;
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&body);
            return Err(encode_provider_error(ProviderError::Upstream(format!(
                "system one returned {status}: {detail}"
            ))));
        }
        serde_json::from_slice(&body).map_err(|error| {
            encode_provider_error(ProviderError::Upstream(format!(
                "system one response is not JSON: {error}"
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::header::AUTHORIZATION;
    use axum::routing::post;
    use serde_json::json;

    const SCHEMA: &str = r#"{
        "type":"object",
        "properties":{
            "object_id":{"type":"string"},
            "department":{"type":"string","enum":["billing","technical","sales"]},
            "frustration":{"type":"number","minimum":0,"maximum":2},
            "is_urgent":{"type":"number","minimum":0,"maximum":1}
        },
        "required":["object_id","department","frustration","is_urgent"],
        "additionalProperties":false
    }"#;

    fn triage_bind() -> SystemOneBind {
        SystemOneBind {
            model: "jev-1.13.0".into(),
            questions: vec![
                SystemOneQuestionBind {
                    parameter: "department".into(),
                    question_type: "choice".into(),
                    instructions: "Which team should handle this".into(),
                    criteria: json!({
                        "billing": "Payment or subscription issues",
                        "technical": "Bugs or integration problems",
                        "sales": "Pricing or account questions"
                    }),
                },
                SystemOneQuestionBind {
                    parameter: "frustration".into(),
                    question_type: "score".into(),
                    instructions: "How frustrated the customer appears".into(),
                    criteria: json!([
                        "Calm, just stating facts",
                        "Frustrated but civil",
                        "Very angry, strong language"
                    ]),
                },
                SystemOneQuestionBind {
                    parameter: "is_urgent".into(),
                    question_type: "noul".into(),
                    instructions: "The message conveys urgency or time-sensitivity".into(),
                    criteria: Value::Null,
                },
            ],
        }
    }

    fn recorded_answers() -> SystemOneResponse {
        serde_json::from_value(json!({
            "model": "jev-1.13.0",
            "answers": {
                "department": {
                    "type": "choice",
                    "choice": "technical",
                    "probabilities": {"billing": 0.159, "technical": 0.84, "sales": 0.001},
                    "confidence": 0.596
                },
                "frustration": {
                    "type": "score",
                    "score": 1.035,
                    "legend": {
                        "0": "Calm, just stating facts",
                        "1": "Frustrated but civil",
                        "2": "Very angry, strong language"
                    },
                    "confidence": 0.842
                },
                "is_urgent": {
                    "type": "noul",
                    "noul": 0.999
                }
            },
            "usage": {"input_tokens": 312, "output_tokens": 48}
        }))
        .unwrap()
    }

    #[test]
    fn recorded_answers_map_onto_closed_action_parameters() {
        let bind = triage_bind();
        validate_bind_against_schema(&bind, SCHEMA).unwrap();
        let parameters: Value = serde_json::from_str(
            &parameters_from_answers(&bind, &recorded_answers(), "ticket-1").unwrap(),
        )
        .unwrap();
        assert_eq!(
            parameters,
            json!({
                "object_id": "ticket-1",
                "department": "technical",
                "frustration": 1.035,
                "is_urgent": 0.999
            })
        );
    }

    #[test]
    fn moving_alias_and_missing_enum_fail_closed() {
        let mut bind = triage_bind();
        bind.model = MOVING_ALIAS.into();
        assert!(
            validate_bind_against_schema(&bind, SCHEMA)
                .unwrap_err()
                .contains(MOVING_ALIAS)
        );

        let mut no_enum = triage_bind();
        no_enum.questions[0].parameter = "missing".into();
        assert!(
            validate_bind_against_schema(&no_enum, SCHEMA)
                .unwrap_err()
                .contains("not in the Action schema")
        );
    }

    #[tokio::test]
    async fn evaluate_posts_state_and_typed_questions() {
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None::<Value>));
        let captured_for_handler = captured.clone();
        let app = Router::new().route(
            "/v1/systemone",
            post(move |request: Request<Body>| {
                let captured_for_handler = captured_for_handler.clone();
                async move {
                    assert_eq!(
                        request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer test-key")
                    );
                    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
                        .await
                        .unwrap();
                    *captured_for_handler.lock().await =
                        Some(serde_json::from_slice(&body).unwrap());
                    axum::Json(recorded_answers())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = TypeSafeClient::new("test-key", format!("http://{addr}/v1/systemone"));
        let request = request_from_bind(
            &triage_bind(),
            json!({"title": "payouts failing for 3 days"}),
        )
        .unwrap();
        let response = client.evaluate(&request).await.unwrap();
        assert_eq!(response.answers["department"]["choice"], "technical");
        let posted = captured.lock().await.clone().unwrap();
        assert_eq!(posted["model"], "jev-1.13.0");
        assert_eq!(posted["questions"]["department"]["type"], "choice");
        assert_eq!(posted["state"]["title"], "payouts failing for 3 days");
    }
}
