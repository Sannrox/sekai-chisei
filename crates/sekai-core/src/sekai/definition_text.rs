//! Human text on object and link types (#2298): a description and the
//! alternative names people use for the type, the same per property, and
//! the texts that still await review.
//!
//! The fields are optional keys of `definition_json`:
//! - `description`: one string;
//! - `alternative_names`: a set of strings;
//! - `property_descriptions`: declared property to string (object types);
//! - `property_alternative_names`: declared property to a set of strings
//!   (object types);
//! - `unreviewed`: the paths of texts nobody has reviewed yet, such as
//!   `description` or `property_descriptions/shp_stat_cd`.
//!
//! A reviewer accepts a text by removing its path from `unreviewed`. Text
//! never touches facts, so changing any of these fields is compatible, and
//! [`crate::sekai::ontology_lint`] warns once per unreviewed path.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

pub const DESCRIPTION: &str = "description";
pub const ALTERNATIVE_NAMES: &str = "alternative_names";
pub const PROPERTY_DESCRIPTIONS: &str = "property_descriptions";
pub const PROPERTY_ALTERNATIVE_NAMES: &str = "property_alternative_names";
pub const UNREVIEWED: &str = "unreviewed";

/// Every text field, in the order they are validated.
pub const FIELDS: &[&str] = &[
    DESCRIPTION,
    ALTERNATIVE_NAMES,
    PROPERTY_DESCRIPTIONS,
    PROPERTY_ALTERNATIVE_NAMES,
    UNREVIEWED,
];

const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_NAME_BYTES: usize = 128;
const MAX_ALTERNATIVE_NAMES: usize = 32;

/// Member kinds whose definitions carry the text fields. On any other kind
/// the keys are not part of the document and stay unknown fields.
pub fn carries_text(member_kind: &str) -> bool {
    matches!(member_kind, "object_type" | "link_type")
}

/// Checks the text fields of an object or link type definition: bounded
/// strings without control characters or surrounding whitespace, property
/// keys that name declared properties, and `unreviewed` paths that name a
/// text the definition holds. Other member kinds are not checked.
pub fn validate(member_kind: &str, definition: &Value) -> Result<(), String> {
    if !carries_text(member_kind) {
        return Ok(());
    }
    if member_kind == "link_type" {
        for field in [PROPERTY_DESCRIPTIONS, PROPERTY_ALTERNATIVE_NAMES] {
            if definition.get(field).is_some() {
                return Err(format!("{field} applies to object types only"));
            }
        }
    }
    if let Some(description) = definition.get(DESCRIPTION) {
        check_description(DESCRIPTION, description)?;
    }
    if let Some(names) = definition.get(ALTERNATIVE_NAMES) {
        check_names(ALTERNATIVE_NAMES, names)?;
    }
    let declared = declared_properties(definition);
    if let Some(map) = property_map(definition, PROPERTY_DESCRIPTIONS, &declared)? {
        for (property, description) in map {
            check_description(&format!("{PROPERTY_DESCRIPTIONS}/{property}"), description)?;
        }
    }
    if let Some(map) = property_map(definition, PROPERTY_ALTERNATIVE_NAMES, &declared)? {
        for (property, names) in map {
            check_names(&format!("{PROPERTY_ALTERNATIVE_NAMES}/{property}"), names)?;
        }
    }
    let Some(unreviewed) = definition.get(UNREVIEWED) else {
        return Ok(());
    };
    let paths = string_set(UNREVIEWED, unreviewed)?;
    if let Some(missing) = paths.iter().find(|path| !holds_text(definition, path)) {
        return Err(format!(
            "{UNREVIEWED} names {missing:?}, which is not a text of this definition"
        ));
    }
    Ok(())
}

/// The `unreviewed` paths of a definition, sorted. A definition that fails
/// [`validate`] never reaches a revision, so a malformed list reads as none.
pub fn unreviewed_paths(definition: &Value) -> Vec<String> {
    definition
        .get(UNREVIEWED)
        .and_then(|value| string_set(UNREVIEWED, value).ok())
        .map(|paths| paths.into_iter().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Whether `path` names a text the definition holds: a top-level text
/// field, or one property's entry in a property text map.
fn holds_text(definition: &Value, path: &str) -> bool {
    match path.split_once('/') {
        None => matches!(path, DESCRIPTION | ALTERNATIVE_NAMES) && definition.get(path).is_some(),
        Some((field, property)) => {
            matches!(field, PROPERTY_DESCRIPTIONS | PROPERTY_ALTERNATIVE_NAMES)
                && definition
                    .get(field)
                    .and_then(|map| map.get(property))
                    .is_some()
        }
    }
}

/// Property names in `properties`, as a list of names or an object keyed by
/// name.
fn declared_properties(definition: &Value) -> BTreeSet<&str> {
    match definition.get("properties") {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        Some(Value::Object(map)) => map.keys().map(String::as_str).collect(),
        _ => BTreeSet::new(),
    }
}

fn property_map<'a>(
    definition: &'a Value,
    field: &str,
    declared: &BTreeSet<&str>,
) -> Result<Option<&'a Map<String, Value>>, String> {
    let Some(value) = definition.get(field) else {
        return Ok(None);
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("{field} must be an object keyed by property"))?;
    if let Some(unknown) = map.keys().find(|key| !declared.contains(key.as_str())) {
        return Err(format!(
            "{field} names {unknown:?}, which is not a declared property"
        ));
    }
    Ok(Some(map))
}

fn check_description(path: &str, value: &Value) -> Result<(), String> {
    check_text(path, value, MAX_DESCRIPTION_BYTES).map(|_| ())
}

fn check_names(path: &str, value: &Value) -> Result<(), String> {
    let names = value
        .as_array()
        .ok_or_else(|| format!("{path} must be a list of names"))?;
    if names.len() > MAX_ALTERNATIVE_NAMES {
        return Err(format!(
            "{path} holds at most {MAX_ALTERNATIVE_NAMES} names"
        ));
    }
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(check_text(path, name, MAX_NAME_BYTES)?) {
            return Err(format!("{path} lists a name twice"));
        }
    }
    Ok(())
}

fn string_set<'a>(path: &str, value: &'a Value) -> Result<BTreeSet<&'a str>, String> {
    let items = value
        .as_array()
        .ok_or_else(|| format!("{path} must be a list of strings"))?;
    let mut set = BTreeSet::new();
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| format!("{path} must be a list of strings"))?;
        if !set.insert(text) {
            return Err(format!("{path} lists {text:?} twice"));
        }
    }
    Ok(set)
}

fn check_text<'a>(path: &str, value: &'a Value, max_bytes: usize) -> Result<&'a str, String> {
    match value.as_str() {
        Some(text)
            if !text.is_empty()
                && text.len() <= max_bytes
                && text.trim() == text
                && !text.chars().any(char::is_control) =>
        {
            Ok(text)
        }
        _ => Err(format!(
            "{path} must be a non-empty string of at most {max_bytes} bytes without control characters or surrounding whitespace"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object_type(extra: Value) -> Value {
        let mut value = json!({"name": "Shipment", "properties": ["shp_stat_cd", "id"]});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        value
    }

    #[test]
    fn an_unreviewed_path_must_name_a_text_the_definition_holds() {
        for path in [
            "alternative_names",
            "property_descriptions/id",
            "property_alternative_names/shp_stat_cd",
            "name",
            "property_descriptions",
        ] {
            let value = object_type(json!({
                "description": "A parcel.",
                "property_descriptions": {"shp_stat_cd": "Status."},
                "unreviewed": [path],
            }));
            // Through member preparation, which every definition write runs.
            let error = crate::sekai::definition_branch::DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Shipment".into(),
                definition_json: value.to_string(),
                member_digest: String::new(),
            }
            .prepare("team-a")
            .unwrap_err();
            assert!(
                error.contains("not a text of this definition"),
                "{path}: {error}"
            );
        }
    }

    #[test]
    fn property_text_must_name_a_declared_property() {
        let value = object_type(json!({"property_alternative_names": {"legacy": ["old"]}}));
        let error = validate("object_type", &value).unwrap_err();
        assert!(error.contains("not a declared property"), "{error}");
    }

    #[test]
    fn link_types_take_no_property_text() {
        let error = validate(
            "link_type",
            &json!({"name": "ShippedTo", "property_descriptions": {}}),
        )
        .unwrap_err();
        assert!(error.contains("object types only"), "{error}");
    }

    #[test]
    fn malformed_text_is_refused() {
        for extra in [
            json!({"description": ""}),
            json!({"description": " padded"}),
            json!({"description": "two\nlines"}),
            json!({"description": "x".repeat(MAX_DESCRIPTION_BYTES + 1)}),
            json!({"alternative_names": "parcel"}),
            json!({"alternative_names": ["parcel", "parcel"]}),
            json!({"alternative_names": (0..=MAX_ALTERNATIVE_NAMES).map(|i| format!("n{i}")).collect::<Vec<_>>()}),
            json!({"unreviewed": "description", "description": "A parcel."}),
        ] {
            assert!(
                validate("object_type", &object_type(extra.clone())).is_err(),
                "{extra}"
            );
        }
    }

    #[test]
    fn other_member_kinds_are_not_checked() {
        validate("ontology_class", &json!({"description": ""})).unwrap();
    }
}
