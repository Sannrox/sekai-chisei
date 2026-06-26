use crate::domain::{Object, ObjectKind};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum PropertyType {
    String,
    Int,
    Bool,
    Enum,
    Link,
    Computed,
}

#[derive(Debug, Clone)]
pub struct PropertyDef {
    pub name: String,
    pub prop_type: PropertyType,
    pub required: bool,
    pub description: String,
    pub enum_values: Vec<String>,
    pub link_kind: String,
    pub compute_expr: String,
}

#[derive(Debug, Clone)]
pub struct ObjectType {
    pub kind: ObjectKind,
    pub description: String,
    pub properties: Vec<PropertyDef>,
}

pub struct SchemaRegistry {
    types: HashMap<ObjectKind, ObjectType>,
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
        }
    }

    pub fn register(&mut self, ot: ObjectType) {
        self.types.insert(ot.kind.clone(), ot);
    }

    pub fn get(&self, kind: &str) -> Option<&ObjectType> {
        self.types.get(kind)
    }

    pub fn all(&self) -> Vec<&ObjectType> {
        self.types.values().collect()
    }

    pub fn validate(&self, obj: &Object) -> Result<(), String> {
        let ot = match self.types.get(&obj.kind) {
            Some(t) => t,
            None => return Ok(()), // untyped kinds pass
        };
        let mut errs = Vec::new();
        for pd in &ot.properties {
            if pd.prop_type == PropertyType::Computed {
                continue;
            }
            let val = obj.properties.get(&pd.name);
            let empty = val.map(|v| v.is_empty()).unwrap_or(true);
            if pd.required && empty {
                errs.push(format!("missing required property: {}", pd.name));
                continue;
            }
            if empty {
                continue;
            }
            let v = val.unwrap();
            match &pd.prop_type {
                PropertyType::Enum => {
                    if !pd.enum_values.contains(v) {
                        errs.push(format!(
                            "property {}: value {:?} not in {:?}",
                            pd.name, v, pd.enum_values
                        ));
                    }
                }
                PropertyType::Bool => {
                    if v != "true" && v != "false" {
                        errs.push(format!("property {}: expected bool, got {:?}", pd.name, v));
                    }
                }
                PropertyType::Int if !v.chars().all(|c| c.is_ascii_digit()) => {
                    errs.push(format!("property {}: expected int, got {:?}", pd.name, v));
                }
                _ => {}
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn prop(name: &str, t: PropertyType, required: bool) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: t,
            required,
            description: String::new(),
            enum_values: vec![],
            link_kind: String::new(),
            compute_expr: String::new(),
        }
    }

    fn prop_enum(name: &str, values: &[&str], required: bool) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: PropertyType::Enum,
            required,
            description: String::new(),
            enum_values: values.iter().map(|s| s.to_string()).collect(),
            link_kind: String::new(),
            compute_expr: String::new(),
        }
    }

    fn widget_registry() -> SchemaRegistry {
        let mut r = SchemaRegistry::new();
        r.register(ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            properties: vec![
                prop_enum("color", &["red", "blue"], false),
                prop("name", PropertyType::String, true),
            ],
        });
        r
    }

    #[test]
    fn test_validate_passes_for_valid_object() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("color".to_string(), "red".to_string()),
                ("name".to_string(), "foo".to_string()),
            ]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_ok());
    }

    #[test]
    fn test_validate_rejects_bad_enum() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("color".to_string(), "green".to_string()),
                ("name".to_string(), "foo".to_string()),
            ]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_err());
    }

    #[test]
    fn test_validate_rejects_missing_required() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        let err = reg.validate(&obj).unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn test_validate_passes_untyped_kind() {
        let reg = SchemaRegistry::new();
        let obj = Object {
            id: "x".into(),
            kind: "anything".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_ok());
    }
}
