use crate::domain::Object;
use std::collections::HashSet;

pub const EXTERNAL_PROPERTIES_KEY: &str = "chisei.egress.external_properties";
pub const INCLUDE_IDENTITY_KEY: &str = "chisei.egress.include_identity";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextEgressRecord {
    pub object_ref: String,
    pub included_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
    pub reasons: Vec<String>,
}

pub fn is_external_provider(provider: &str) -> bool {
    matches!(provider, "openai" | "anthropic" | "native")
}

pub fn object_ref(obj: &Object) -> String {
    if !obj.external_id.is_empty() {
        obj.external_id.clone()
    } else {
        obj.id.clone()
    }
}

pub fn include_identity(obj: &Object) -> bool {
    obj.properties
        .get(INCLUDE_IDENTITY_KEY)
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn allowed_external_properties(obj: &Object) -> HashSet<String> {
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

pub fn filter_property(
    obj: &Object,
    field: &str,
    record: &mut ContextEgressRecord,
    external: bool,
) -> Option<String> {
    let value = obj
        .properties
        .get(field)
        .filter(|value| !value.is_empty())?;
    if !external || allowed_external_properties(obj).contains(field) {
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

pub fn new_record(obj: &Object) -> ContextEgressRecord {
    ContextEgressRecord {
        object_ref: object_ref(obj),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn object(properties: HashMap<String, String>) -> Object {
        Object {
            id: "obj-1".into(),
            kind: "ticker".into(),
            name: "AAPL".into(),
            namespace: String::new(),
            external_id: "ticker:AAPL".into(),
            properties,
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn external_provider_detection_matches_v1_scope() {
        assert!(is_external_provider("openai"));
        assert!(is_external_provider("anthropic"));
        assert!(is_external_provider("native"));
        assert!(!is_external_provider("ollama"));
    }

    #[test]
    fn properties_are_denied_by_default() {
        let obj = object(HashMap::from([("verdict".into(), "bullish".into())]));
        let mut record = new_record(&obj);
        assert_eq!(filter_property(&obj, "verdict", &mut record, true), None);
        assert_eq!(record.redacted_fields, vec!["verdict"]);
    }

    #[test]
    fn local_properties_are_allowed_by_default() {
        let obj = object(HashMap::from([("verdict".into(), "bullish".into())]));
        let mut record = new_record(&obj);
        assert_eq!(
            filter_property(&obj, "verdict", &mut record, false),
            Some("bullish".into())
        );
        assert_eq!(record.included_fields, vec!["verdict"]);
    }

    #[test]
    fn explicitly_allowed_properties_pass() {
        let obj = object(HashMap::from([
            ("verdict".into(), "bullish".into()),
            (EXTERNAL_PROPERTIES_KEY.into(), "verdict, score".into()),
        ]));
        let mut record = new_record(&obj);
        assert_eq!(
            filter_property(&obj, "verdict", &mut record, true),
            Some("bullish".into())
        );
        assert_eq!(record.included_fields, vec!["verdict"]);
    }
}
