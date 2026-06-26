use crate::db::sekai::SekaiDb;
use crate::domain::{Link, Object};
use std::collections::HashMap;

type ExecuteFn =
    Box<dyn Fn(&SekaiDb, &HashMap<String, String>) -> Result<String, String> + Send + Sync>;

pub struct ActionDef {
    pub name: String,
    pub required: Vec<String>,
    pub execute: ExecuteFn,
}

pub struct ActionExecutor {
    registry: HashMap<String, ActionDef>,
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor {
    pub fn new() -> Self {
        let mut e = Self {
            registry: HashMap::new(),
        };
        e.register_builtins();
        e
    }

    pub fn execute(
        &self,
        db: &SekaiDb,
        action: &str,
        params: &HashMap<String, String>,
        _actor: &str,
    ) -> Result<String, String> {
        let def = self
            .registry
            .get(action)
            .ok_or_else(|| format!("unknown action: {}", action))?;
        for r in &def.required {
            if !params.contains_key(r) {
                return Err(format!("missing required param: {}", r));
            }
        }
        (def.execute)(db, params)
    }

    fn register_builtins(&mut self) {
        self.registry.insert(
            "create_object".into(),
            ActionDef {
                name: "create_object".into(),
                required: vec!["id".into(), "kind".into(), "name".into()],
                execute: Box::new(|db, p| {
                    let now = chrono::Utc::now().timestamp();
                    let obj = Object {
                        id: p["id"].clone(),
                        kind: p["kind"].clone(),
                        name: p["name"].clone(),
                        namespace: p.get("namespace").cloned().unwrap_or_default(),
                        external_id: p.get("external_id").cloned().unwrap_or_default(),
                        properties: HashMap::new(),
                        created: now,
                        updated: now,
                    };
                    db.create_object(&obj)?;
                    Ok(format!("created object {}", obj.id))
                }),
            },
        );
        self.registry.insert(
            "set_property".into(),
            ActionDef {
                name: "set_property".into(),
                required: vec!["id".into(), "key".into(), "value".into()],
                execute: Box::new(|db, p| {
                    let mut obj = db.get_object(&p["id"])?.ok_or("object not found")?;
                    obj.properties.insert(p["key"].clone(), p["value"].clone());
                    obj.updated = chrono::Utc::now().timestamp();
                    db.update_object(&obj)?;
                    Ok(format!("set {}.{} = {}", obj.id, p["key"], p["value"]))
                }),
            },
        );
        self.registry.insert(
            "create_link".into(),
            ActionDef {
                name: "create_link".into(),
                required: vec!["from_id".into(), "to_id".into(), "relation".into()],
                execute: Box::new(|db, p| {
                    let id = format!("{}->{}", p["from_id"], p["to_id"]);
                    let link = Link {
                        id: id.clone(),
                        from_id: p["from_id"].clone(),
                        to_id: p["to_id"].clone(),
                        relation: p["relation"].clone(),
                        created: chrono::Utc::now().timestamp(),
                    };
                    db.create_link(&link)?;
                    Ok(format!("created link {}", id))
                }),
            },
        );
        self.registry.insert(
            "delete_link".into(),
            ActionDef {
                name: "delete_link".into(),
                required: vec!["id".into()],
                execute: Box::new(|db, p| {
                    db.delete_link(&p["id"])?;
                    Ok(format!("deleted link {}", p["id"]))
                }),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_object_action() {
        let db = SekaiDb::new(":memory:").unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([
            ("id".into(), "o1".into()),
            ("kind".into(), "repo".into()),
            ("name".into(), "test".into()),
        ]);
        let msg = exec.execute(&db, "create_object", &params, "user").unwrap();
        assert!(msg.contains("o1"));
        assert!(db.get_object("o1").unwrap().is_some());
    }

    #[test]
    fn test_set_property_action() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "o1".into(),
            kind: "repo".into(),
            name: "r".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([
            ("id".into(), "o1".into()),
            ("key".into(), "language".into()),
            ("value".into(), "rust".into()),
        ]);
        exec.execute(&db, "set_property", &params, "user").unwrap();
        let obj = db.get_object("o1").unwrap().unwrap();
        assert_eq!(obj.properties["language"], "rust");
    }

    #[test]
    fn test_missing_param() {
        let db = SekaiDb::new(":memory:").unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([("id".into(), "o1".into())]);
        assert!(exec.execute(&db, "create_object", &params, "user").is_err());
    }
}
