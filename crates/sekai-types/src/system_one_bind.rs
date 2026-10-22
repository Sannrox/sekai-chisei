//! System One bind declared on a governed Action type.
//!
//! Sekai stores and validates the bind with the Action type; the Chisei
//! provider maps it onto a System One request.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Moving model alias a bind must not pin.
pub const MOVING_ALIAS: &str = "jev-latest";

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
