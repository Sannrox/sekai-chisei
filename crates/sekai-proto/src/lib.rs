pub mod sekai {
    tonic::include_proto!("sekai");
}

pub mod chisei {
    tonic::include_proto!("chisei");
}

mod property_json;

#[cfg(test)]
mod tests {
    use super::sekai::PropertyValue;
    use super::sekai::property_value::Kind;
    use std::collections::HashMap;

    #[test]
    fn property_value_json_accepts_string_form_and_tagged_cells() {
        let properties: HashMap<String, PropertyValue> = serde_json::from_str(
            r#"{"title":"hello","count":12,"ratio":12.5,"ok":true,"meta":{"label":"x"}}"#,
        )
        .unwrap();
        assert!(matches!(
            &properties["title"].kind,
            Some(Kind::StringValue(text)) if text == "hello"
        ));
        assert!(matches!(properties["count"].kind, Some(Kind::IntValue(12))));
        assert!(matches!(
            properties["ratio"].kind,
            Some(Kind::FloatValue(value)) if value == 12.5
        ));
        assert!(matches!(properties["ok"].kind, Some(Kind::BoolValue(true))));
        let Some(Kind::StructValue(meta)) = &properties["meta"].kind else {
            panic!("expected struct");
        };
        assert!(matches!(
            &meta.fields["label"].kind,
            Some(Kind::StringValue(text)) if text == "x"
        ));

        let tagged: PropertyValue =
            serde_json::from_str(r#"{"kind":{"stringValue":"hello"}}"#).unwrap();
        assert!(matches!(
            tagged.kind,
            Some(Kind::StringValue(text)) if text == "hello"
        ));
        let flattened: PropertyValue = serde_json::from_str(r#"{"stringValue":"hello"}"#).unwrap();
        assert!(matches!(
            flattened.kind,
            Some(Kind::StringValue(text)) if text == "hello"
        ));
        assert_eq!(
            serde_json::to_value(&properties["title"]).unwrap(),
            serde_json::json!("hello")
        );
        assert_eq!(
            serde_json::to_value(&properties["count"]).unwrap(),
            serde_json::json!(12)
        );

        let nested_kind: PropertyValue =
            serde_json::from_str(r#"{"kind":{"stringValue":"x"},"other":12}"#).unwrap();
        let Some(Kind::StructValue(nested_kind)) = nested_kind.kind else {
            panic!("expected struct with object-valued kind");
        };
        assert!(matches!(
            nested_kind.fields["other"].kind,
            Some(Kind::IntValue(12))
        ));
        assert!(matches!(
            &nested_kind.fields["kind"].kind,
            Some(Kind::StringValue(text)) if text == "x"
        ));
        let named_string_value = PropertyValue {
            kind: Some(Kind::StructValue(super::sekai::StructValue {
                fields: HashMap::from([(
                    "stringValue".into(),
                    PropertyValue {
                        kind: Some(Kind::StringValue("x".into())),
                    },
                )]),
            })),
        };
        let encoded = serde_json::to_value(&named_string_value).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"kind":{"structValue":{"fields":{"stringValue":"x"}}}})
        );
        let round_trip: PropertyValue = serde_json::from_value(encoded).unwrap();
        assert_eq!(round_trip, named_string_value);
        let snake_struct: PropertyValue = serde_json::from_str(r#"{"string_value":"x"}"#).unwrap();
        let Some(Kind::StructValue(snake_struct)) = snake_struct.kind else {
            panic!("expected struct");
        };
        assert!(matches!(
            &snake_struct.fields["string_value"].kind,
            Some(Kind::StringValue(text)) if text == "x"
        ));
        let labeled_kind: PropertyValue =
            serde_json::from_str(r#"{"kind":{"label":"x"}}"#).unwrap();
        let Some(Kind::StructValue(labeled_kind)) = labeled_kind.kind else {
            panic!("expected struct");
        };
        let Some(Kind::StructValue(kind_cell)) = &labeled_kind.fields["kind"].kind else {
            panic!("expected nested struct");
        };
        assert!(matches!(
            &kind_cell.fields["label"].kind,
            Some(Kind::StringValue(text)) if text == "x"
        ));
        let ordinary: PropertyValue =
            serde_json::from_str(r#"{"kind":"issue","fields":{"label":"x"},"other":12}"#).unwrap();
        let Some(Kind::StructValue(fields)) = ordinary.kind else {
            panic!("expected struct");
        };
        assert!(matches!(
            &fields.fields["kind"].kind,
            Some(Kind::StringValue(text)) if text == "issue"
        ));
        assert!(matches!(
            fields.fields["other"].kind,
            Some(Kind::IntValue(12))
        ));
        let Some(Kind::StructValue(nested)) = &fields.fields["fields"].kind else {
            panic!("expected nested struct");
        };
        assert!(matches!(
            &nested.fields["label"].kind,
            Some(Kind::StringValue(text)) if text == "x"
        ));
    }
}
