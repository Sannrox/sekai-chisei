use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, Object};
use std::collections::HashMap;

type ComputeFn = Box<dyn Fn(&Object, &SekaiDb) -> Option<String> + Send + Sync>;

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

    pub fn resolve(&self, obj: &mut Object, db: &SekaiDb) {
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

    pub fn resolve_all(&self, objs: &mut [Object], db: &SekaiDb) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KIND_COMPONENT, Link};

    #[test]
    fn test_compute_component_count() {
        let db = SekaiDb::new(":memory:").unwrap();
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
        let db = SekaiDb::new(":memory:").unwrap();
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
