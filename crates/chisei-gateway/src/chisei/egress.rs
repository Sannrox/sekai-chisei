use crate::domain::Object;
use sekai_proto::sekai::ObjectType;
use std::collections::HashSet;

pub const EXTERNAL_PROPERTIES_KEY: &str = "chisei.egress.external_properties";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextEgressRecord {
    pub object_ref: String,
    pub included_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
    pub reasons: Vec<String>,
}

pub fn include_identity(obj: &Object) -> bool {
    obj.properties
        .get("chisei.egress.include_identity")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn allowed_external_properties(obj: &Object) -> HashSet<String> {
    obj.properties
        .get(EXTERNAL_PROPERTIES_KEY)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn new_record(obj: &Object) -> ContextEgressRecord {
    ContextEgressRecord {
        object_ref: if obj.external_id.is_empty() {
            obj.id.clone()
        } else {
            obj.external_id.clone()
        },
        ..Default::default()
    }
}

pub fn filter_property(
    obj: &Object,
    field: &str,
    record: &mut ContextEgressRecord,
    external: bool,
) -> Option<String> {
    filter_property_with_schema(obj, field, None, record, external)
}

pub fn filter_property_with_schema(
    obj: &Object,
    field: &str,
    object_type: Option<&ObjectType>,
    record: &mut ContextEgressRecord,
    external: bool,
) -> Option<String> {
    let value = obj
        .properties
        .get(field)
        .filter(|value| !value.is_empty())?;
    let permitted = !external
        || (allowed_external_properties(obj).contains(field)
            && object_type
                .and_then(|kind| {
                    kind.properties
                        .iter()
                        .find(|property| property.name == field)
                })
                .is_none_or(|property| {
                    !crate::sekai::schema::is_restricted_property_classification(
                        &property.classification,
                    )
                }));
    if permitted {
        record.included_fields.push(field.to_string());
        Some(value.clone())
    } else {
        record.redacted_fields.push(field.to_string());
        record
            .reasons
            .push(format!("{field} denied by default egress policy"));
        None
    }
}
