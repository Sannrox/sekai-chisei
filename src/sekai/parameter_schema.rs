//! Closed v1 JSON parameter-schema subset shared by Action types and plans.
//!
//! This is a facts-layer contract: Action types persist the schema, and Chisei
//! evaluation plans reuse the same validator. Keep the vocabulary here so Sekai
//! does not import Chisei to admit a type.

use serde_json::Value;
use std::collections::BTreeSet;

const MAX_STRING_BYTES: usize = 1_024;

/// Validate only the closed v1 parameter-schema contract.
pub fn validate_parameter_schema(schema_json: &str) -> Result<(), String> {
    parse_parameter_schema(schema_json).map(|_| ())
}

pub(crate) fn parse_parameter_schema(input: &str) -> Result<Value, String> {
    if crate::sekai::json::contains_duplicate_object_keys(input)
        .map_err(|error| format!("parameter_schema_json must be JSON: {error}"))?
    {
        return Err("parameter schema must not contain duplicate object keys".into());
    }
    let mut schema: Value = serde_json::from_str(input)
        .map_err(|error| format!("parameter_schema_json must be JSON: {error}"))?;
    let root = schema
        .as_object_mut()
        .ok_or_else(|| "parameter_schema_json must be a JSON object".to_string())?;
    let allowed_root = ["type", "properties", "required", "additionalProperties"];
    if root.keys().any(|key| !allowed_root.contains(&key.as_str())) {
        return Err("parameter schema contains an unsupported root keyword".into());
    }
    if root.get("type").and_then(Value::as_str) != Some("object") {
        return Err("parameter schema type must be object".into());
    }
    if root.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
        return Err("parameter schema must set additionalProperties to false".into());
    }
    let properties = root
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "parameter schema properties object required".to_string())?;
    let required = root
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| "parameter schema required array required".to_string())?;
    let mut property_names = BTreeSet::new();
    for (name, property) in properties {
        validate_token("parameter name", name)?;
        property_names.insert(name.as_str());
        validate_parameter_property(name, property)?;
    }
    let mut seen_required = BTreeSet::new();
    for name in required {
        let name = name
            .as_str()
            .ok_or_else(|| "required parameter names must be strings".to_string())?;
        if !property_names.contains(name) || !seen_required.insert(name) {
            return Err("required parameters must be unique declared properties".into());
        }
    }
    Ok(schema)
}

pub(crate) fn validate_parameter_value(
    name: &str,
    schema: &Value,
    value: &Value,
) -> Result<(), String> {
    let parameter_type = schema["type"].as_str().expect("validated type");
    validate_primitive_type(name, parameter_type, value)?;
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let matches = if parameter_type == "number" {
            let number = safe_number(name, value)?;
            values.iter().any(|candidate| {
                safe_number(name, candidate)
                    .map(|candidate| candidate == number)
                    .unwrap_or(false)
            })
        } else {
            values.contains(value)
        };
        if !matches {
            return Err(format!("parameter {name:?} is not in its declared enum"));
        }
    }
    if parameter_type == "integer" {
        let integer = json_integer(value).expect("validated integer parameter");
        if schema
            .get("minimum")
            .and_then(json_integer)
            .is_some_and(|minimum| integer_cmp(integer, minimum).is_lt())
            || schema
                .get("maximum")
                .and_then(json_integer)
                .is_some_and(|maximum| integer_cmp(integer, maximum).is_gt())
        {
            return Err(format!("parameter {name:?} is outside its declared bounds"));
        }
    } else if parameter_type == "number" {
        let number = safe_number(name, value)?;
        if schema
            .get("minimum")
            .map(|minimum| safe_number(name, minimum))
            .transpose()?
            .is_some_and(|minimum| number < minimum)
            || schema
                .get("maximum")
                .map(|maximum| safe_number(name, maximum))
                .transpose()?
                .is_some_and(|maximum| number > maximum)
        {
            return Err(format!("parameter {name:?} is outside its declared bounds"));
        }
    }
    if let Some(string) = value.as_str() {
        let length = string.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| length > maximum)
        {
            return Err(format!(
                "parameter {name:?} length is outside its declared bounds"
            ));
        }
    }
    Ok(())
}

fn validate_parameter_property(name: &str, property: &Value) -> Result<(), String> {
    let property = property
        .as_object()
        .ok_or_else(|| format!("parameter {name:?} schema must be an object"))?;
    let allowed = [
        "type",
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
    ];
    if property.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "parameter {name:?} schema contains an unsupported keyword"
        ));
    }
    let parameter_type = property
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("parameter {name:?} type required"))?;
    if !matches!(parameter_type, "string" | "number" | "integer" | "boolean") {
        return Err(format!("parameter {name:?} has unsupported type"));
    }
    if let Some(values) = property.get("enum") {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| format!("parameter {name:?} enum must be a non-empty array"))?;
        for value in values {
            validate_primitive_type(name, parameter_type, value)?;
            if parameter_type == "number" {
                safe_number(name, value)?;
            }
        }
    }
    for keyword in ["minimum", "maximum"] {
        if let Some(value) = property.get(keyword)
            && (!matches!(parameter_type, "number" | "integer")
                || (parameter_type == "integer" && json_integer(value).is_none())
                || (parameter_type == "number" && safe_number(name, value).is_err()))
        {
            return Err(format!(
                "parameter {name:?} {keyword} requires a numeric type and value"
            ));
        }
    }
    for keyword in ["minLength", "maxLength"] {
        if let Some(value) = property.get(keyword)
            && (parameter_type != "string" || value.as_u64().is_none())
        {
            return Err(format!(
                "parameter {name:?} {keyword} requires a string type and integer value"
            ));
        }
    }
    if let (Some(minimum), Some(maximum)) = (property.get("minimum"), property.get("maximum")) {
        let inverted = if parameter_type == "integer" {
            integer_cmp(
                json_integer(minimum).expect("validated integer minimum"),
                json_integer(maximum).expect("validated integer maximum"),
            )
            .is_gt()
        } else {
            safe_number(name, minimum)? > safe_number(name, maximum)?
        };
        if inverted {
            return Err(format!(
                "parameter {name:?} minimum must not exceed maximum"
            ));
        }
    }
    if let (Some(minimum), Some(maximum)) = (
        property.get("minLength").and_then(Value::as_u64),
        property.get("maxLength").and_then(Value::as_u64),
    ) && minimum > maximum
    {
        return Err(format!(
            "parameter {name:?} minLength must not exceed maxLength"
        ));
    }
    Ok(())
}

fn validate_primitive_type(name: &str, parameter_type: &str, value: &Value) -> Result<(), String> {
    let valid = match parameter_type {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "parameter {name:?} does not match type {parameter_type}"
        ))
    }
}

#[derive(Clone, Copy)]
enum JsonInteger {
    Negative(i64),
    NonNegative(u64),
}

fn json_integer(value: &Value) -> Option<JsonInteger> {
    if let Some(value) = value.as_i64()
        && value < 0
    {
        Some(JsonInteger::Negative(value))
    } else {
        value.as_u64().map(JsonInteger::NonNegative)
    }
}

fn integer_cmp(left: JsonInteger, right: JsonInteger) -> std::cmp::Ordering {
    match (left, right) {
        (JsonInteger::Negative(left), JsonInteger::Negative(right)) => left.cmp(&right),
        (JsonInteger::Negative(_), JsonInteger::NonNegative(_)) => std::cmp::Ordering::Less,
        (JsonInteger::NonNegative(_), JsonInteger::Negative(_)) => std::cmp::Ordering::Greater,
        (JsonInteger::NonNegative(left), JsonInteger::NonNegative(right)) => left.cmp(&right),
    }
}

fn safe_number(name: &str, value: &Value) -> Result<f64, String> {
    const MAX_EXACT_INTEGER: u64 = (1_u64 << 53) - 1;
    if value
        .as_u64()
        .is_some_and(|value| value > MAX_EXACT_INTEGER)
        || value
            .as_i64()
            .is_some_and(|value| value.unsigned_abs() > MAX_EXACT_INTEGER)
    {
        return Err(format!(
            "number parameter {name:?} exceeds the exact v1 numeric range; use integer type"
        ));
    }
    let number = value
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| format!("parameter {name:?} must be a finite number"))?;
    if number.fract() == 0.0 && number.abs() > MAX_EXACT_INTEGER as f64 {
        return Err(format!(
            "number parameter {name:?} exceeds the exact v1 numeric range"
        ));
    }
    Ok(number)
}

fn validate_token(name: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > MAX_STRING_BYTES
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "{name} must be non-empty, canonical, bounded, and contain no whitespace"
        ));
    }
    Ok(())
}
