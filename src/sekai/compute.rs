use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, Object};
use crate::sekai::function;
use crate::sekai::schema::{PropertyType, SchemaRegistry};
use std::collections::HashMap;

type ComputeFn = Box<dyn Fn(&Object, &RuntimeDb) -> Option<String> + Send + Sync>;

pub struct ComputeRegistry {
    funcs: HashMap<String, ComputeFn>, // "kind:property" -> fn
}

impl Default for ComputeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeRegistry {
    pub fn new() -> Self {
        Self {
            funcs: HashMap::new(),
        }
    }

    pub fn register(&mut self, kind: &str, property: &str, f: ComputeFn) {
        self.funcs.insert(format!("{}:{}", kind, property), f);
    }

    pub fn resolve(&self, obj: &mut Object, db: &RuntimeDb) {
        for (key, f) in &self.funcs {
            let (k, prop) = key.split_once(':').unwrap_or((key, ""));
            if k != obj.kind {
                continue;
            }
            if let Some(val) = f(obj, db) {
                obj.properties.insert(prop.to_string(), val);
            }
        }
    }

    pub fn resolve_all(&self, objs: &mut [Object], db: &RuntimeDb) {
        for obj in objs.iter_mut() {
            self.resolve(obj, db);
        }
    }
}

pub fn default_compute_registry() -> ComputeRegistry {
    let mut c = ComputeRegistry::new();
    c.register(
        "namespace",
        "component_count",
        Box::new(|obj, db| {
            let linked = db
                .get_linked_objects(&obj.id, "contains", &Direction::Outgoing)
                .unwrap_or_default();
            let count = linked.iter().filter(|o| o.kind == KIND_COMPONENT).count();
            if count == 0 {
                None
            } else {
                Some(count.to_string())
            }
        }),
    );
    c.register(
        KIND_COMPONENT,
        "health",
        Box::new(|obj, _db| {
            let rate: i32 = obj
                .properties
                .get("success_rate")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let total: i32 = obj
                .properties
                .get("task_total")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if total == 0 {
                return Some("unknown".into());
            }
            Some(if rate >= 80 { "healthy" } else { "degraded" }.into())
        }),
    );
    c
}

pub fn resolve_schema_computed_with_filter<F>(
    obj: &mut Object,
    db: &RuntimeDb,
    schema: &SchemaRegistry,
    allow: F,
) -> Result<(), String>
where
    F: Fn(&Object) -> bool,
{
    let Some(object_type) = schema.get(&obj.kind) else {
        return Ok(());
    };
    let computed_properties = object_type
        .properties
        .iter()
        .filter(|property| property.prop_type == PropertyType::Computed)
        .collect::<Vec<_>>();
    for property in &computed_properties {
        obj.properties.remove(&property.name);
    }
    for property in computed_properties {
        let value = if property.compute_expr.trim().is_empty() {
            fallback_computed_value(obj, db, &property.name, &allow)?
        } else {
            function_computed_value(obj, db, &property.compute_expr, &property.name, &allow)?
        };
        if let Some(value) = value {
            obj.properties.insert(property.name.clone(), value);
        }
    }
    Ok(())
}

fn function_computed_value<F>(
    obj: &Object,
    db: &RuntimeDb,
    function_name: &str,
    property_name: &str,
    allow: &F,
) -> Result<Option<String>, String>
where
    F: Fn(&Object) -> bool,
{
    let function = db
        .get_function(function_name)?
        .ok_or_else(|| format!("computed function not found: {function_name}"))?;
    let params = HashMap::from([
        ("object_id".to_string(), obj.id.clone()),
        ("object_kind".to_string(), obj.kind.clone()),
        ("object_name".to_string(), obj.name.clone()),
        ("namespace".to_string(), obj.namespace.clone()),
        ("external_id".to_string(), obj.external_id.clone()),
    ]);
    let result = function::execute_for_object_with_filter(db, &function, obj, &params, allow)?;
    if let Some(value) = result.aggregates.get(property_name) {
        return Ok(Some(value.clone()));
    }
    if let Some(value) = result.aggregates.get("value") {
        return Ok(Some(value.clone()));
    }
    if result.aggregates.len() == 1 {
        return Ok(result.aggregates.values().next().cloned());
    }
    Ok(None)
}

fn fallback_computed_value<F>(
    obj: &Object,
    db: &RuntimeDb,
    property_name: &str,
    allow: &F,
) -> Result<Option<String>, String>
where
    F: Fn(&Object) -> bool,
{
    match (obj.kind.as_str(), property_name) {
        ("namespace", "component_count") => {
            let linked = db.get_linked_objects(&obj.id, "contains", &Direction::Outgoing)?;
            let count = linked
                .iter()
                .filter(|object| object.kind == KIND_COMPONENT && allow(object))
                .count();
            if count == 0 {
                Ok(None)
            } else {
                Ok(Some(count.to_string()))
            }
        }
        (KIND_COMPONENT, "health") => {
            let rate: i32 = obj
                .properties
                .get("success_rate")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let total: i32 = obj
                .properties
                .get("task_total")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if total == 0 {
                Ok(Some("unknown".into()))
            } else if rate >= 80 {
                Ok(Some("healthy".into()))
            } else {
                Ok(Some("degraded".into()))
            }
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KIND_COMPONENT, Link};

    #[test]
    fn test_compute_component_count() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let mut namespace = Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        db.create_object(&namespace).unwrap();
        let comp = Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        db.create_object(&comp).unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();

        let reg = default_compute_registry();
        reg.resolve(&mut namespace, &db);
        assert_eq!(namespace.properties.get("component_count").unwrap(), "1");
    }

    #[test]
    fn test_compute_health() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let reg = default_compute_registry();
        let mut comp = Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("success_rate".into(), "90".into()),
                ("task_total".into(), "10".into()),
            ]),
            created: 0,
            updated: 0,
        };
        reg.resolve(&mut comp, &db);
        assert_eq!(comp.properties.get("health").unwrap(), "healthy");

        comp.properties.insert("success_rate".into(), "30".into());
        reg.resolve(&mut comp, &db);
        assert_eq!(comp.properties.get("health").unwrap(), "degraded");
    }
}
