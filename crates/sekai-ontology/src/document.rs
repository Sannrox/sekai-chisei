use super::{Error, ImportDocument, SCHEMA_VERSION};
use serde_json::{Map, Value};

/// Shared logical definition document used by portable `sekai` and
/// `sekaictl ontology apply`. Transport envelopes may differ; meaning may not.
pub const PRODUCT_DOC_VERSION: &str = "sekai.ontology-product/v1";
pub const DEFINITION_DOC_VERSION: &str = "sekai.ontology-definition/v1";

const APPLY_IO_FIELDS: [&str; 2] = ["ensure_kind", "kind_description"];

pub fn parse_definition_document(input: &str) -> Result<ImportDocument, Error> {
    let value: Value = serde_json::from_str(input)
        .map_err(|error| Error::Input(format!("invalid import document: {error}")))?;
    parse_definition_document_value(value)
}

pub fn parse_definition_document_value(value: Value) -> Result<ImportDocument, Error> {
    let value = unwrap_export_envelope(value)?;
    let value = normalize_definition_value(value)?;
    serde_json::from_value(value)
        .map_err(|error| Error::Input(format!("invalid import document: {error}")))
}

fn unwrap_export_envelope(value: Value) -> Result<Value, Error> {
    let Some(command) = value.get("command").and_then(Value::as_str) else {
        return Ok(value);
    };
    if command != "export" {
        return Err(Error::Input(format!(
            "JSON envelope has command '{command}', expected 'export'"
        )));
    }
    value
        .get("data")
        .cloned()
        .ok_or_else(|| Error::Input("JSON export envelope has no data field".into()))
}

fn normalize_definition_value(mut value: Value) -> Result<Value, Error> {
    let Some(object) = value.as_object_mut() else {
        return Err(Error::Input(
            "definition document must be a JSON object".into(),
        ));
    };
    let version = object
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let schema_version = object.get("schema_version").and_then(Value::as_u64);
    match (schema_version, version.as_deref()) {
        (Some(version), _) if version == u64::from(SCHEMA_VERSION) => {}
        (Some(version), _) => {
            return Err(Error::Input(format!(
                "unsupported import schema version {version}; expected {SCHEMA_VERSION}"
            )));
        }
        (None, Some(PRODUCT_DOC_VERSION | DEFINITION_DOC_VERSION)) => {
            object.insert("schema_version".into(), Value::from(SCHEMA_VERSION));
        }
        (None, Some(other)) => {
            return Err(Error::Input(format!(
                "unsupported definition version {other:?}; expected {PRODUCT_DOC_VERSION}, {DEFINITION_DOC_VERSION}, or schema_version {SCHEMA_VERSION}"
            )));
        }
        (None, None) => {
            return Err(Error::Input(format!(
                "definition document requires schema_version {SCHEMA_VERSION} or version {PRODUCT_DOC_VERSION}"
            )));
        }
    }
    object.remove("version");
    strip_apply_io_fields(object);
    if !object.contains_key("provenance") {
        object.insert("provenance".into(), Value::Array(Vec::new()));
    }
    Ok(value)
}

fn strip_apply_io_fields(object: &mut Map<String, Value>) {
    let Some(classes) = object.get_mut("classes").and_then(Value::as_array_mut) else {
        return;
    };
    for class in classes {
        let Some(class) = class.as_object_mut() else {
            continue;
        };
        for field in APPLY_IO_FIELDS {
            class.remove(field);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_and_portable_documents_share_definition_design() {
        let product = r#"{
            "version": "sekai.ontology-product/v1",
            "classes": [
                {
                    "name": "Receipt",
                    "description": "An inspectable operation outcome",
                    "mapped_kind": "receipt",
                    "ensure_kind": true,
                    "kind_description": "apply only",
                    "equivalent_classes": ["OperationReceipt"],
                    "properties": [{"name": "request_id", "type": "string", "required": true}]
                }
            ],
            "relations": [
                {
                    "name": "records",
                    "domain": "Receipt",
                    "range": "Receipt",
                    "mapped_relation": "records",
                    "transitive": false,
                    "cardinality": {"min": 0, "max": 1}
                }
            ]
        }"#;
        let portable = parse_definition_document(product).unwrap();
        assert_eq!(portable.schema_version, SCHEMA_VERSION);
        assert_eq!(portable.classes[0].name, "Receipt");
        assert_eq!(portable.classes[0].mapped_kind, "receipt");
        assert_eq!(portable.classes[0].equivalent_classes, ["OperationReceipt"]);
        assert_eq!(portable.classes[0].properties[0].name, "request_id");
        assert_eq!(portable.relations[0].mapped_relation, "records");
        assert_eq!(portable.relations[0].cardinality.max, Some(1));

        let exported = serde_json::to_string(&portable).unwrap();
        let round_trip = parse_definition_document(&exported).unwrap();
        assert_eq!(round_trip, portable);
    }
}
