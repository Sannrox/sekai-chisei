//! Object type and property schema vocabulary (ADR 0096 rule 5).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use sekai_domain::domain::ObjectKind;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyType {
    String,
    Int,
    Float,
    Bool,
    Enum,
    Timestamp,
    Link,
    Computed,
    Struct,
}

impl PropertyType {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "string" => Some(Self::String),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "bool" => Some(Self::Bool),
            "enum" => Some(Self::Enum),
            "timestamp" => Some(Self::Timestamp),
            "link" => Some(Self::Link),
            "computed" => Some(Self::Computed),
            "struct" => Some(Self::Struct),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Enum => "enum",
            Self::Timestamp => "timestamp",
            Self::Link => "link",
            Self::Computed => "computed",
            Self::Struct => "struct",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldDef {
    pub name: String,
    pub prop_type: PropertyType,
    pub required: bool,
    pub description: String,
    pub enum_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyDef {
    pub name: String,
    pub prop_type: PropertyType,
    pub required: bool,
    pub description: String,
    pub enum_values: Vec<String>,
    pub link_kind: String,
    pub compute_expr: String,
    #[serde(default = "default_property_classification")]
    pub classification: String,
    #[serde(default)]
    pub struct_fields: Vec<StructFieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectType {
    pub kind: ObjectKind,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub is_builtin: bool,
    pub implements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDef {
    pub name: String,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub is_builtin: bool,
}

pub fn default_property_classification() -> String {
    "public".to_string()
}

pub fn normalize_property_classification(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "public"
    } else {
        trimmed
    }
}

pub fn is_restricted_property_classification(value: &str) -> bool {
    matches!(
        normalize_property_classification(value),
        "internal" | "sensitive"
    )
}

pub fn is_valid_property_classification(value: &str) -> bool {
    matches!(
        normalize_property_classification(value),
        "public" | "internal" | "sensitive"
    )
}

/// Schema-typed property cell. JSON keeps the previous string form as a
/// string and accepts numbers/bools/objects untagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum PropertyValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Struct(BTreeMap<String, PropertyValue>),
}

impl PartialEq for PropertyValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Float(left), Self::Float(right)) => left.to_bits() == right.to_bits(),
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Struct(left), Self::Struct(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for PropertyValue {}

impl PartialEq<str> for PropertyValue {
    fn eq(&self, other: &str) -> bool {
        self.as_cell() == other
    }
}

impl PartialEq<&str> for PropertyValue {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for PropertyValue {
    fn eq(&self, other: &String) -> bool {
        self.as_cell() == *other
    }
}

impl From<String> for PropertyValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for PropertyValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<i64> for PropertyValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<bool> for PropertyValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for PropertyValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl PropertyValue {
    /// Dataset / clerk string form of this cell.
    pub fn as_cell(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => {
                if value.fract() == 0.0 && value.abs() < 1e15 {
                    format!("{value:.0}")
                } else {
                    ryu_or_display(*value)
                }
            }
            Self::String(value) => value.clone(),
            Self::Struct(fields) => serde_json::to_string(fields).unwrap_or_else(|_| "{}".into()),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn timestamp_millis(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::String(value) => parse_timestamp_millis(value),
            _ => None,
        }
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Bool(flag) => Ok(Self::Bool(*flag)),
            serde_json::Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    Ok(Self::Int(int))
                } else if let Some(float) = number.as_f64() {
                    if !float.is_finite() {
                        return Err("property value float must be finite".into());
                    }
                    Ok(Self::Float(float))
                } else {
                    Err("property value number is out of range".into())
                }
            }
            serde_json::Value::String(text) => Ok(Self::String(text.clone())),
            serde_json::Value::Object(fields) => {
                let mut out = BTreeMap::new();
                for (key, nested) in fields {
                    out.insert(key.clone(), Self::from_json(nested)?);
                }
                Ok(Self::Struct(out))
            }
            serde_json::Value::Null => Err("property value must not be null".into()),
            serde_json::Value::Array(_) => Err("property value must not be an array".into()),
        }
    }
}

/// Clerk / dataset / overlay string map for a typed property bag.
pub fn properties_as_cells(
    properties: &BTreeMap<String, PropertyValue>,
) -> BTreeMap<String, String> {
    properties
        .iter()
        .map(|(key, value)| (key.clone(), value.as_cell()))
        .collect()
}

fn ryu_or_display(value: f64) -> String {
    let mut text = value.to_string();
    if !text.contains('.') && !text.contains('e') && !text.contains('E') {
        text.push_str(".0");
    }
    text
}

/// Coerce inbound cells to the declared schema type. Named errors refuse
/// values that do not fit.
pub fn coerce_property_value(
    property: &str,
    declared: &PropertyDef,
    value: PropertyValue,
) -> Result<PropertyValue, String> {
    coerce_declared(
        property,
        declared.prop_type.clone(),
        &declared.enum_values,
        &declared.struct_fields,
        value,
    )
}

pub fn coerce_properties(
    object_type: &ObjectType,
    properties: BTreeMap<String, PropertyValue>,
) -> Result<BTreeMap<String, PropertyValue>, String> {
    let defs: BTreeMap<&str, &PropertyDef> = object_type
        .properties
        .iter()
        .map(|property| (property.name.as_str(), property))
        .collect();
    let mut out = BTreeMap::new();
    for (key, value) in properties {
        match defs.get(key.as_str()) {
            Some(declared) => {
                out.insert(key.clone(), coerce_property_value(&key, declared, value)?);
            }
            None => {
                out.insert(key, value);
            }
        }
    }
    Ok(out)
}

fn coerce_declared(
    property: &str,
    prop_type: PropertyType,
    enum_values: &[String],
    struct_fields: &[StructFieldDef],
    value: PropertyValue,
) -> Result<PropertyValue, String> {
    match prop_type {
        PropertyType::String | PropertyType::Link | PropertyType::Computed => match value {
            PropertyValue::String(text) => Ok(PropertyValue::String(text)),
            other => Ok(PropertyValue::String(other.as_cell())),
        },
        PropertyType::Enum => {
            let text = match value {
                PropertyValue::String(text) => text,
                other => other.as_cell(),
            };
            if enum_values.iter().any(|allowed| allowed == &text) {
                Ok(PropertyValue::String(text))
            } else {
                Err(format!(
                    "property {property}: value {text:?} not in {enum_values:?}"
                ))
            }
        }
        PropertyType::Bool => match value {
            PropertyValue::Bool(flag) => Ok(PropertyValue::Bool(flag)),
            PropertyValue::String(text) => match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(PropertyValue::Bool(true)),
                "false" | "0" | "no" => Ok(PropertyValue::Bool(false)),
                _ => Err(format!("property {property}: expected bool, got {text:?}")),
            },
            other => Err(format!(
                "property {property}: expected bool, got {}",
                other.as_cell()
            )),
        },
        PropertyType::Int => match value {
            PropertyValue::Int(int) => Ok(PropertyValue::Int(int)),
            PropertyValue::Float(float) => int_from_integral_float(property, float),
            PropertyValue::String(text) => text
                .parse::<i64>()
                .map(PropertyValue::Int)
                .map_err(|_| format!("property {property}: expected int, got {text:?}")),
            other => Err(format!(
                "property {property}: expected int, got {}",
                other.as_cell()
            )),
        },
        PropertyType::Float => match value {
            PropertyValue::Float(float) if float.is_finite() => Ok(PropertyValue::Float(float)),
            PropertyValue::Int(int) => Ok(PropertyValue::Float(int as f64)),
            PropertyValue::String(text) => match text.parse::<f64>() {
                Ok(parsed) if parsed.is_finite() => Ok(PropertyValue::Float(parsed)),
                _ => Err(format!("property {property}: expected float, got {text:?}")),
            },
            other => Err(format!(
                "property {property}: expected float, got {}",
                other.as_cell()
            )),
        },
        PropertyType::Timestamp => {
            let millis = match &value {
                PropertyValue::Int(int) => Some(*int),
                PropertyValue::String(text) => parse_timestamp_millis(text),
                _ => None,
            };
            millis.map(PropertyValue::Int).ok_or_else(|| {
                format!(
                    "property {property}: expected timestamp, got {}",
                    value.as_cell()
                )
            })
        }
        PropertyType::Struct => match value {
            PropertyValue::Struct(fields) => {
                coerce_struct_fields(property, struct_fields, fields).map(PropertyValue::Struct)
            }
            PropertyValue::String(text) => {
                let parsed: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| format!("property {property}: expected struct JSON object"))?;
                let coerced = PropertyValue::from_json(&parsed)?;
                match coerced {
                    PropertyValue::Struct(fields) => {
                        coerce_struct_fields(property, struct_fields, fields)
                            .map(PropertyValue::Struct)
                    }
                    _ => Err(format!("property {property}: expected struct JSON object")),
                }
            }
            _ => Err(format!("property {property}: expected struct JSON object")),
        },
    }
}

fn int_from_integral_float(property: &str, float: f64) -> Result<PropertyValue, String> {
    // 2^63 as f64 saturates when cast to i64; keep the upper bound exclusive.
    if !float.is_finite()
        || float.fract() != 0.0
        || float < i64::MIN as f64
        || float >= 9223372036854775808.0
    {
        return Err(format!(
            "property {property}: expected int, got {}",
            PropertyValue::Float(float).as_cell()
        ));
    }
    let int = float as i64;
    if int as f64 != float {
        return Err(format!(
            "property {property}: expected int, got {}",
            PropertyValue::Float(float).as_cell()
        ));
    }
    Ok(PropertyValue::Int(int))
}

/// True when two cells name the same value after string-form coerce.
/// Previously stored JSON strings compare equal to typed index cells.
/// Two String cells stay exact; numeric/bool folding is only for mixed
/// typed-versus-string-form identity upgrades.
pub fn property_values_equivalent(left: &PropertyValue, right: &PropertyValue) -> bool {
    if left == right {
        return true;
    }
    match (left, right) {
        (PropertyValue::Struct(left), PropertyValue::Struct(right)) => {
            property_maps_equivalent(left, right)
        }
        (PropertyValue::Struct(fields), PropertyValue::String(raw))
        | (PropertyValue::String(raw), PropertyValue::Struct(fields)) => {
            serde_json::from_str::<BTreeMap<String, PropertyValue>>(raw)
                .ok()
                .is_some_and(|parsed| property_maps_equivalent(fields, &parsed))
        }
        (PropertyValue::String(_), PropertyValue::String(_)) => false,
        (PropertyValue::Int(_), PropertyValue::Int(_))
        | (PropertyValue::Float(_), PropertyValue::Float(_))
        | (PropertyValue::Bool(_), PropertyValue::Bool(_)) => false,
        _ => {
            if let (Some(left), Some(right)) = (as_i64(left), as_i64(right)) {
                return left == right;
            }
            // Mixed String vs Int timestamp folding is the identity upgrade
            // for previously stored RFC3339 cells versus declared millis.
            if let (Some(left), Some(right)) = (left.timestamp_millis(), right.timestamp_millis())
                && left == right
            {
                return true;
            }
            if let (Some(left), Some(right)) = (bool_cell(left), bool_cell(right)) {
                return left == right;
            }
            // Int cells already had their chance via as_i64; do not round
            // them through f64 (2^53+ identity would collapse). Integral
            // Float cells still fold against string-form floats.
            if matches!(left, PropertyValue::Int(_)) || matches!(right, PropertyValue::Int(_)) {
                return false;
            }
            if let (Some(left), Some(right)) = (numeric_f64(left), numeric_f64(right)) {
                return left.to_bits() == right.to_bits();
            }
            false
        }
    }
}

pub fn property_maps_equivalent(
    left: &BTreeMap<String, PropertyValue>,
    right: &BTreeMap<String, PropertyValue>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(key, value)| {
            right
                .get(key)
                .is_some_and(|other| property_values_equivalent(value, other))
        })
}

fn as_i64(value: &PropertyValue) -> Option<i64> {
    match value {
        PropertyValue::Int(int) => Some(*int),
        PropertyValue::String(text) => text.parse::<i64>().ok(),
        PropertyValue::Float(float) => match int_from_integral_float("_", *float) {
            Ok(PropertyValue::Int(int)) => Some(int),
            _ => None,
        },
        _ => None,
    }
}

fn numeric_f64(value: &PropertyValue) -> Option<f64> {
    match value {
        PropertyValue::Int(int) => Some(*int as f64),
        PropertyValue::Float(float) if float.is_finite() => Some(*float),
        PropertyValue::String(text) => text.parse::<f64>().ok().filter(|float| float.is_finite()),
        _ => None,
    }
}

fn bool_cell(value: &PropertyValue) -> Option<bool> {
    match value {
        PropertyValue::Bool(flag) => Some(*flag),
        PropertyValue::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn coerce_struct_fields(
    property: &str,
    fields: &[StructFieldDef],
    mut values: BTreeMap<String, PropertyValue>,
) -> Result<BTreeMap<String, PropertyValue>, String> {
    let mut out = BTreeMap::new();
    for field in fields {
        match values.remove(&field.name) {
            Some(value) => {
                out.insert(
                    field.name.clone(),
                    coerce_declared(
                        &format!("{property}.{}", field.name),
                        field.prop_type.clone(),
                        &field.enum_values,
                        &[],
                        value,
                    )?,
                );
            }
            None if field.required => {
                return Err(format!(
                    "property {property}.{}: missing required field",
                    field.name
                ));
            }
            None => {}
        }
    }
    out.append(&mut values);
    Ok(out)
}

pub fn parse_timestamp_millis(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if let Ok(millis) = trimmed.parse::<i64>() {
        return Some(millis);
    }
    parse_rfc3339_ms(trimmed)
}

/// Minimal RFC3339 parser for `YYYY-MM-DDTHH:MM:SS[.sss]Z` or `±HH:MM`.
pub fn parse_rfc3339_ms(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let (datetime, offset_ms) = if let Some(prefix) = raw.strip_suffix('Z') {
        (prefix, 0i64)
    } else if raw.len() >= 6 {
        let sign_at = raw.len() - 6;
        let sign = raw.as_bytes().get(sign_at)?;
        if *sign != b'+' && *sign != b'-' {
            return None;
        }
        let (hours, minutes) = raw[sign_at + 1..].split_once(':')?;
        let hours: i64 = hours.parse().ok()?;
        let minutes: i64 = minutes.parse().ok()?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        let mut offset_ms = (hours * 60 + minutes) * 60 * 1000;
        if *sign == b'+' {
            offset_ms = -offset_ms;
        }
        (&raw[..sign_at], offset_ms)
    } else {
        return None;
    };
    let (date, time) = datetime.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() || !(0..=9999).contains(&year) {
        return None;
    }
    let (hms, frac) = match time.split_once('.') {
        Some((hms, frac)) => (hms, frac),
        None => (time, "0"),
    };
    if !frac.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let mut hms = hms.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let minute: i64 = hms.next()?.parse().ok()?;
    let second: i64 = hms.next()?.parse().ok()?;
    if hms.next().is_some() {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let last_day = days_in_month(year, month)?;
    if day < 1 || day > last_day {
        return None;
    }
    let mut digits: String = frac.chars().take(3).collect();
    if digits.is_empty() {
        return None;
    }
    while digits.len() < 3 {
        digits.push('0');
    }
    let millis: i64 = digits.parse().ok()?;
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(24)?
        .checked_add(hour)?
        .checked_mul(60)?
        .checked_add(minute)?
        .checked_mul(60)?
        .checked_add(second)?
        .checked_mul(1000)?
        .checked_add(millis)?
        .checked_add(offset_ms)
}

fn days_in_month(year: i64, month: i64) -> Option<i64> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => return None,
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let mut y = year;
    let m = month;
    if m <= 2 {
        y = y.checked_sub(1)?;
    }
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * if m > 2 { m - 3 } else { m + 9 } + 2) / 5 + day - 1;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146097)?
        .checked_add(doe)?
        .checked_sub(719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_type() -> ObjectType {
        ObjectType {
            kind: "Ticket".into(),
            description: String::new(),
            properties: vec![
                PropertyDef {
                    name: "count".into(),
                    prop_type: PropertyType::Int,
                    required: false,
                    description: String::new(),
                    enum_values: Vec::new(),
                    link_kind: String::new(),
                    compute_expr: String::new(),
                    classification: default_property_classification(),
                    struct_fields: Vec::new(),
                },
                PropertyDef {
                    name: "when".into(),
                    prop_type: PropertyType::Timestamp,
                    required: false,
                    description: String::new(),
                    enum_values: Vec::new(),
                    link_kind: String::new(),
                    compute_expr: String::new(),
                    classification: default_property_classification(),
                    struct_fields: Vec::new(),
                },
            ],
            is_builtin: false,
            implements: Vec::new(),
        }
    }

    #[test]
    fn coerce_properties_accepts_string_form_and_typed_json() {
        let object_type = sample_type();
        let coerced = coerce_properties(
            &object_type,
            BTreeMap::from([
                ("count".into(), PropertyValue::String("12".into())),
                (
                    "when".into(),
                    PropertyValue::String("1970-01-01T00:00:00.100Z".into()),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(coerced.get("count"), Some(&PropertyValue::Int(12)));
        assert_eq!(coerced.get("when"), Some(&PropertyValue::Int(100)));
        let typed = coerce_properties(
            &object_type,
            BTreeMap::from([("count".into(), PropertyValue::Int(12))]),
        )
        .unwrap();
        assert_eq!(typed.get("count"), Some(&PropertyValue::Int(12)));
    }

    #[test]
    fn coerce_properties_names_the_unfit_property() {
        let object_type = sample_type();
        let error = coerce_properties(
            &object_type,
            BTreeMap::from([("count".into(), PropertyValue::String("nope".into()))]),
        )
        .unwrap_err();
        assert!(error.contains("count"));
    }

    #[test]
    fn coerce_int_refuses_integral_floats_outside_i64() {
        let object_type = sample_type();
        let error = coerce_properties(
            &object_type,
            BTreeMap::from([("count".into(), PropertyValue::Float(1e30))]),
        )
        .unwrap_err();
        assert!(error.contains("count"), "{error}");
        let overflow = coerce_properties(
            &object_type,
            BTreeMap::from([("count".into(), PropertyValue::Float(9223372036854775808.0))]),
        )
        .unwrap_err();
        assert!(overflow.contains("count"), "{overflow}");
        let coerced = coerce_properties(
            &object_type,
            BTreeMap::from([("count".into(), PropertyValue::Float(12.0))]),
        )
        .unwrap();
        assert_eq!(coerced.get("count"), Some(&PropertyValue::Int(12)));
    }

    #[test]
    fn property_maps_equivalent_accepts_string_form_and_typed_cells() {
        let stored = BTreeMap::from([
            ("count".into(), PropertyValue::String("12".into())),
            (
                "when".into(),
                PropertyValue::String("1970-01-01T00:00:00.100Z".into()),
            ),
            ("ok".into(), PropertyValue::String("true".into())),
        ]);
        let incoming = BTreeMap::from([
            ("count".into(), PropertyValue::Int(12)),
            ("when".into(), PropertyValue::Int(100)),
            ("ok".into(), PropertyValue::Bool(true)),
        ]);
        assert!(property_maps_equivalent(&stored, &incoming));
        assert!(!property_maps_equivalent(
            &BTreeMap::from([("count".into(), PropertyValue::Int(12))]),
            &BTreeMap::from([("count".into(), PropertyValue::Int(13))]),
        ));
        assert!(!property_maps_equivalent(
            &BTreeMap::from([("count".into(), PropertyValue::String("001".into()))]),
            &BTreeMap::from([("count".into(), PropertyValue::String("1".into()))]),
        ));
        assert!(!property_maps_equivalent(
            &BTreeMap::from([("ok".into(), PropertyValue::String("yes".into()))]),
            &BTreeMap::from([("ok".into(), PropertyValue::String("true".into()))]),
        ));
        assert!(!property_values_equivalent(
            &PropertyValue::Int(9007199254740992),
            &PropertyValue::Int(9007199254740993),
        ));
        assert!(property_values_equivalent(
            &PropertyValue::Int(9007199254740993),
            &PropertyValue::String("9007199254740993".into()),
        ));
        assert!(!property_values_equivalent(
            &PropertyValue::Int(9007199254740993),
            &PropertyValue::String("9007199254740992.0".into()),
        ));
        assert!(property_values_equivalent(
            &PropertyValue::String("1".into()),
            &PropertyValue::Bool(true),
        ));
        assert!(property_values_equivalent(
            &PropertyValue::String("0".into()),
            &PropertyValue::Bool(false),
        ));
        assert!(property_values_equivalent(
            &PropertyValue::String("12.0".into()),
            &PropertyValue::Float(12.0),
        ));
        assert!(!property_values_equivalent(
            &PropertyValue::String("1970-01-01T00:00:00Z".into()),
            &PropertyValue::String("1970-01-01T01:00:00+01:00".into()),
        ));
        assert!(property_values_equivalent(
            &PropertyValue::String("1970-01-01T00:00:00Z".into()),
            &PropertyValue::Int(0),
        ));
    }

    #[test]
    fn parse_rfc3339_ms_rejects_impossible_dates_and_non_digit_frac() {
        assert_eq!(parse_rfc3339_ms("2026-02-31T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_ms("2025-02-29T00:00:00Z"), None);
        assert_eq!(
            parse_rfc3339_ms("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
        assert_eq!(parse_rfc3339_ms("2026-01-01T00:00:00.12xZ"), None);
        assert_eq!(parse_rfc3339_ms("2026-01-01-02T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_ms("2026-01-01T00:00:00:00Z"), None);
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.100Z"), Some(100));
        assert_eq!(
            parse_rfc3339_ms("9223372036854775807-01-01T00:00:00Z"),
            None
        );
        assert_eq!(parse_rfc3339_ms("10000-01-01T00:00:00Z"), None);
        assert!(parse_rfc3339_ms("9999-12-31T23:59:59Z").is_some());
    }
}
