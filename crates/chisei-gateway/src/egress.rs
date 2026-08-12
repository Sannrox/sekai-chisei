use crate::domain::Object;
use sekai_proto::sekai::ObjectType;

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

fn external_property_is_allowed(obj: &Object, field: &str) -> bool {
    obj.properties
        .get(EXTERNAL_PROPERTIES_KEY)
        .is_some_and(|raw| {
            raw.split(',')
                .map(str::trim)
                .any(|value| !value.is_empty() && value == field)
        })
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
        || (external_property_is_allowed(obj, field)
            && object_type
                .and_then(|kind| {
                    kind.properties
                        .iter()
                        .find(|property| property.name == field)
                })
                .is_none_or(|property| {
                    !crate::gateway_support::is_restricted_property_classification(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn object(properties: HashMap<String, String>) -> Object {
        Object {
            id: "obj-1".into(),
            kind: "fixture".into(),
            name: "Fixture".into(),
            namespace: "benchmark".into(),
            external_id: "fixture:1".into(),
            properties,
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn external_allowlist_matches_exact_trimmed_entries() {
        let obj = object(HashMap::from([
            ("".into(), "empty key".into()),
            ("score".into(), "90".into()),
            ("score_detail".into(), "synthetic".into()),
            (
                EXTERNAL_PROPERTIES_KEY.into(),
                " , verdict, score_detail, ".into(),
            ),
        ]));
        let mut record = new_record(&obj);

        assert_eq!(filter_property(&obj, "", &mut record, true), None);
        assert_eq!(filter_property(&obj, "score", &mut record, true), None);
        assert_eq!(
            filter_property(&obj, "score_detail", &mut record, true),
            Some("synthetic".into())
        );
        assert_eq!(record.redacted_fields, vec!["", "score"]);
        assert_eq!(record.included_fields, vec!["score_detail"]);
    }
}
