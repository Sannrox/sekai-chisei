//! Tool-use bridge (Plan 9, Phase D).
//!
//! Maps a model tool-call to a governed Sekai action. The chosen enforcement
//! point is the `ExecuteAction` boundary (option 1 in the plan): a client that
//! runs an LLM tool-call executes it by calling `ExecuteAction` with the mapped
//! action + params, so the call is policy-checked, blast-radius/budget
//! constrained, and audited before any graph mutation happens. This avoids
//! parsing provider-specific tool-call formats at the gateway and keeps the
//! single, sound trust boundary.
//!
//! The bridge itself is intentionally tiny and provider-agnostic: it converts a
//! tool-call's JSON arguments into the flat `param -> string` map that
//! `ExecuteAction` consumes. Governance is enforced server-side; this is just
//! the shape adapter.

use std::collections::HashMap;

/// A provider-agnostic model tool-call: the tool name plus its JSON arguments.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

impl ToolCall {
    pub fn new(name: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }

    /// Parse a tool-call whose arguments arrived as a JSON string (the common
    /// OpenAI/Anthropic shape where `arguments` is a serialized JSON object).
    pub fn from_json_arguments(
        name: impl Into<String>,
        arguments_json: &str,
    ) -> Result<Self, String> {
        let arguments = serde_json::from_str(arguments_json)
            .map_err(|e| format!("invalid tool arguments JSON: {e}"))?;
        Ok(Self::new(name, arguments))
    }

    /// The action name to invoke via `ExecuteAction`. Tool names map 1:1 to
    /// governed action names (builtin or registered action types).
    pub fn action_name(&self) -> &str {
        &self.name
    }

    /// Convert the tool arguments into `ExecuteAction` params. Scalar values are
    /// stringified; nested objects/arrays are serialized to JSON (so struct
    /// params round-trip). Errors if the arguments are not a JSON object.
    pub fn to_action_params(&self) -> Result<HashMap<String, String>, String> {
        let object = self
            .arguments
            .as_object()
            .ok_or_else(|| "tool arguments must be a JSON object".to_string())?;
        let mut params = HashMap::with_capacity(object.len());
        for (key, value) in object {
            params.insert(key.clone(), json_value_to_param(value));
        }
        Ok(params)
    }
}

fn json_value_to_param(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        // Objects/arrays keep their JSON form so struct/list params survive.
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_scalar_arguments_to_string_params() {
        let call = ToolCall::new(
            "set_property",
            json!({"id": "obj-1", "key": "count", "value": 3, "enabled": true}),
        );
        assert_eq!(call.action_name(), "set_property");
        let params = call.to_action_params().unwrap();
        assert_eq!(params["id"], "obj-1");
        assert_eq!(params["key"], "count");
        assert_eq!(params["value"], "3");
        assert_eq!(params["enabled"], "true");
    }

    #[test]
    fn nested_arguments_are_serialized_as_json() {
        let call = ToolCall::new("configure", json!({"spec": {"a": 1, "b": [2, 3]}}));
        let params = call.to_action_params().unwrap();
        // Nested object preserved as JSON for struct params.
        let parsed: serde_json::Value = serde_json::from_str(&params["spec"]).unwrap();
        assert_eq!(parsed, json!({"a": 1, "b": [2, 3]}));
    }

    #[test]
    fn from_json_arguments_parses_serialized_object() {
        let call = ToolCall::from_json_arguments("create_object", r#"{"id":"o1","kind":"widget"}"#)
            .unwrap();
        let params = call.to_action_params().unwrap();
        assert_eq!(params["id"], "o1");
        assert_eq!(params["kind"], "widget");
    }

    #[test]
    fn non_object_arguments_are_rejected() {
        let call = ToolCall::new("set_property", json!(["not", "an", "object"]));
        assert!(call.to_action_params().is_err());
        assert!(ToolCall::from_json_arguments("x", "not json").is_err());
    }
}
