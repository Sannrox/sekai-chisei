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
            // JSON has no NaN or infinity; serde_json would write `null`,
            // which parses back as an unset value. Refuse, as parsing does.
            Some(Kind::FloatValue(float)) if !float.is_finite() => Err(serde::ser::Error::custom(
                "property value float must be finite",
            )),
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

const STRING_KEYS: &[&str] = &["stringValue", "string_value"];
const INT_KEYS: &[&str] = &["intValue", "int_value"];
const FLOAT_KEYS: &[&str] = &["floatValue", "float_value"];
const BOOL_KEYS: &[&str] = &["boolValue", "bool_value"];
const STRUCT_KEYS: &[&str] = &["structValue", "struct_value"];

fn is_tagged_key(key: &str) -> bool {
    [STRING_KEYS, INT_KEYS, FLOAT_KEYS, BOOL_KEYS, STRUCT_KEYS]
        .into_iter()
        .any(|keys| keys.contains(&key))
}

fn is_tagged(fields: &Map<String, Value>) -> bool {
    match fields.get("kind") {
        Some(kind) if fields.len() == 1 => is_kind_envelope(kind),
        Some(_) => false,
        None => fields.len() == 1 && fields.keys().next().is_some_and(|key| is_tagged_key(key)),
    }
}

fn is_kind_envelope(kind: &Value) -> bool {
    kind.as_object().is_some_and(|envelope| {
        envelope.len() == 1 && envelope.keys().any(|key| is_tagged_key(key))
    })
}

fn take_i64(key: &str, value: Value) -> Result<i64, String> {
    if let Some(int) = value.as_i64() {
        return Ok(int);
    }
    if let Some(text) = value.as_str() {
        return text.parse().map_err(|_| format!("{key} must be an int"));
    }
    Err(format!("{key} must be an int"))
}

fn parse_tagged(mut fields: Map<String, Value>) -> Result<PropertyValue, String> {
    if let Some(kind) = fields.remove("kind") {
        let Value::Object(inner) = kind else {
            return Err("property value kind must be an object".into());
        };
        return parse_tagged(inner);
    }
    // `is_tagged` admits exactly one camelCase or snake_case oneof key.
    let Some((key, value)) = fields.into_iter().next() else {
        return Err("property value object is missing a typed cell".into());
    };
    let key_str = key.as_str();
    let kind = if STRING_KEYS.contains(&key_str) {
        match value {
            Value::String(text) => Kind::StringValue(text),
            other => return Err(format!("{key} must be a string, got {other}")),
        }
    } else if INT_KEYS.contains(&key_str) {
        Kind::IntValue(take_i64(key_str, value)?)
    } else if FLOAT_KEYS.contains(&key_str) {
        Kind::FloatValue(
            value
                .as_f64()
                .filter(|float| float.is_finite())
                .ok_or(format!("{key} must be a finite float"))?,
        )
    } else if BOOL_KEYS.contains(&key_str) {
        Kind::BoolValue(value.as_bool().ok_or(format!("{key} must be a bool"))?)
    } else if STRUCT_KEYS.contains(&key_str) {
        Kind::StructValue(serde_json::from_value(value).map_err(|error| error.to_string())?)
    } else {
        return Err("property value object is missing a typed cell".into());
    };
    Ok(PropertyValue { kind: Some(kind) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn float(value: f64) -> Wire {
        Wire(PropertyValue {
            kind: Some(Kind::FloatValue(value)),
        })
    }

    #[test]
    fn non_finite_floats_do_not_serialize() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(serde_json::to_string(&float(value)).is_err(), "{value}");
        }
    }

    #[test]
    fn tagged_cells_accept_string_int64_and_snake_case_keys() {
        let parse = |json: &str| serde_json::from_str::<Wire>(json).map(|wire| wire.0.kind);
        assert_eq!(
            parse(r#"{"stringValue":"a"}"#).unwrap(),
            Some(Kind::StringValue("a".into()))
        );
        assert_eq!(parse(r#"{"intValue":3}"#).unwrap(), Some(Kind::IntValue(3)));
        assert_eq!(
            parse(r#"{"kind":{"boolValue":true}}"#).unwrap(),
            Some(Kind::BoolValue(true))
        );
        assert_eq!(
            parse(r#"{"intValue":"5"}"#).unwrap(),
            Some(Kind::IntValue(5))
        );
        assert!(parse(r#"{"intValue":"nope"}"#).is_err());
        assert_eq!(
            parse(r#"{"int_value":5}"#).unwrap(),
            Some(Kind::IntValue(5))
        );
        assert_eq!(
            parse(r#"{"kind":{"int_value":5}}"#).unwrap(),
            Some(Kind::IntValue(5))
        );
        assert_eq!(
            parse(r#"{"string_value":"a"}"#).unwrap(),
            Some(Kind::StringValue("a".into()))
        );
    }

    #[test]
    fn finite_floats_round_trip() {
        let json = serde_json::to_string(&float(1.5)).unwrap();
        assert_eq!(json, "1.5");
        let parsed: Wire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0.kind, Some(Kind::FloatValue(1.5)));
    }
}
