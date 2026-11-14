//! Untagged JSON for [`crate::sekai::PropertyValue`].
//!
//! HTTP proto JSON still accepts the previous string-form cells
//! (`{"title":"hello"}`) plus the generated oneof object form.

use crate::sekai::property_value::Kind;
use crate::sekai::{PropertyValue, StructValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Wire(PropertyValue);

#[derive(Serialize)]
struct StructEnvelope {
    kind: StructKind,
}

#[derive(Serialize)]
struct StructKind {
    #[serde(rename = "structValue")]
    struct_value: StructFields,
}

#[derive(Serialize)]
struct StructFields {
    fields: HashMap<String, Wire>,
}

impl From<Wire> for PropertyValue {
    fn from(wire: Wire) -> Self {
        wire.0
    }
}

impl From<PropertyValue> for Wire {
    fn from(value: PropertyValue) -> Self {
        Self(value)
    }
}

impl Serialize for Wire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0.kind {
            Some(Kind::StringValue(text)) => text.serialize(serializer),
            Some(Kind::IntValue(int)) => int.serialize(serializer),
            Some(Kind::FloatValue(float)) => float.serialize(serializer),
            Some(Kind::BoolValue(flag)) => flag.serialize(serializer),
            Some(Kind::StructValue(nested)) => StructEnvelope {
                kind: StructKind {
                    struct_value: StructFields {
                        fields: nested
                            .fields
                            .iter()
                            .map(|(key, value)| (key.clone(), Wire(value.clone())))
                            .collect(),
                    },
                },
            }
            .serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for Wire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        parse_wire(value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

fn parse_wire(value: Value) -> Result<PropertyValue, String> {
    match value {
        Value::String(text) => Ok(PropertyValue {
            kind: Some(Kind::StringValue(text)),
        }),
        Value::Bool(flag) => Ok(PropertyValue {
            kind: Some(Kind::BoolValue(flag)),
        }),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Ok(PropertyValue {
                    kind: Some(Kind::IntValue(int)),
                })
            } else if let Some(float) = number.as_f64().filter(|float| float.is_finite()) {
                Ok(PropertyValue {
                    kind: Some(Kind::FloatValue(float)),
                })
            } else {
                Err("property value number must be a finite int or float".into())
            }
        }
        Value::Object(fields) => {
            if is_tagged(&fields) {
                parse_tagged(fields)
            } else {
                let mut nested = HashMap::new();
                for (key, child) in fields {
                    nested.insert(key, parse_wire(child)?);
                }
                Ok(PropertyValue {
                    kind: Some(Kind::StructValue(StructValue { fields: nested })),
                })
            }
        }
        Value::Null => Ok(PropertyValue { kind: None }),
        Value::Array(_) => Err("property value must not be an array".into()),
    }
}

const ONEOF_KEYS: &[&str] = &[
    "stringValue",
    "intValue",
    "floatValue",
    "boolValue",
    "structValue",
];

fn is_tagged(fields: &Map<String, Value>) -> bool {
    match fields.get("kind") {
        Some(kind) if fields.len() == 1 => is_kind_envelope(kind),
        Some(_) => false,
        None => {
            fields.len() == 1
                && fields
                    .keys()
                    .next()
                    .is_some_and(|key| ONEOF_KEYS.contains(&key.as_str()))
        }
    }
}

fn is_kind_envelope(kind: &Value) -> bool {
    kind.as_object().is_some_and(|envelope| {
        envelope.len() == 1
            && envelope
                .keys()
                .any(|key| ONEOF_KEYS.contains(&key.as_str()))
    })
}

fn parse_tagged(mut fields: Map<String, Value>) -> Result<PropertyValue, String> {
    if let Some(kind) = fields.remove("kind") {
        let kind = serde_json::from_value(kind).map_err(|error| error.to_string())?;
        return Ok(PropertyValue { kind });
    }
    if let Some(text) = take_string(&mut fields, &["stringValue", "string_value"])? {
        return Ok(PropertyValue {
            kind: Some(Kind::StringValue(text)),
        });
    }
    if let Some(int) = take_i64(&mut fields, &["intValue", "int_value"])? {
        return Ok(PropertyValue {
            kind: Some(Kind::IntValue(int)),
        });
    }
    if let Some(float) = take_f64(&mut fields, &["floatValue", "float_value"])? {
        return Ok(PropertyValue {
            kind: Some(Kind::FloatValue(float)),
        });
    }
    if let Some(flag) = take_bool(&mut fields, &["boolValue", "bool_value"])? {
        return Ok(PropertyValue {
            kind: Some(Kind::BoolValue(flag)),
        });
    }
    if let Some(nested) = fields
        .remove("structValue")
        .or_else(|| fields.remove("struct_value"))
    {
        let nested = serde_json::from_value(nested).map_err(|error| error.to_string())?;
        return Ok(PropertyValue {
            kind: Some(Kind::StructValue(nested)),
        });
    }
    if let Some(Value::Object(nested)) = fields.remove("fields") {
        let mut parsed = HashMap::new();
        for (key, child) in nested {
            parsed.insert(key, parse_wire(child)?);
        }
        return Ok(PropertyValue {
            kind: Some(Kind::StructValue(StructValue { fields: parsed })),
        });
    }
    Err("property value object is missing a typed cell".into())
}

fn take_string(fields: &mut Map<String, Value>, keys: &[&str]) -> Result<Option<String>, String> {
    for key in keys {
        if let Some(value) = fields.remove(*key) {
            return match value {
                Value::String(text) => Ok(Some(text)),
                other => Err(format!("{key} must be a string, got {other}")),
            };
        }
    }
    Ok(None)
}

fn take_i64(fields: &mut Map<String, Value>, keys: &[&str]) -> Result<Option<i64>, String> {
    for key in keys {
        if let Some(value) = fields.remove(*key) {
            return match value.as_i64() {
                Some(int) => Ok(Some(int)),
                None => Err(format!("{key} must be an int")),
            };
        }
    }
    Ok(None)
}

fn take_f64(fields: &mut Map<String, Value>, keys: &[&str]) -> Result<Option<f64>, String> {
    for key in keys {
        if let Some(value) = fields.remove(*key) {
            return match value.as_f64().filter(|float| float.is_finite()) {
                Some(float) => Ok(Some(float)),
                None => Err(format!("{key} must be a finite float")),
            };
        }
    }
    Ok(None)
}

fn take_bool(fields: &mut Map<String, Value>, keys: &[&str]) -> Result<Option<bool>, String> {
    for key in keys {
        if let Some(value) = fields.remove(*key) {
            return match value.as_bool() {
                Some(flag) => Ok(Some(flag)),
                None => Err(format!("{key} must be a bool")),
            };
        }
    }
    Ok(None)
}
