use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Link, Object};
use crate::sekai::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet, VecDeque};

const MAX_DEPTH: i32 = 10;

#[derive(Debug, Clone, Default)]
pub struct GraphQuery {
    pub start_id: String,
    pub start_external_id: String,
    pub relations: Vec<String>,
    pub direction: Direction,
    pub max_depth: i32,
    pub kind_filter: Vec<String>,
    pub interface_filter: Vec<String>,
    pub property_filter: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct GraphResult {
    pub objects: Vec<Object>,
    pub links: Vec<Link>,
}

pub fn traverse(
    db: &RuntimeDb,
    q: &GraphQuery,
    schema: Option<&SchemaRegistry>,
) -> Result<GraphResult, String> {
    let start_id = if !q.start_id.is_empty() {
        q.start_id.clone()
    } else if !q.start_external_id.is_empty() {
        match db.find_by_external_id(&q.start_external_id)? {
            Some(obj) => obj.id,
            None => return Ok(GraphResult::default()),
        }
    } else {
        return Err("start_id or start_external_id required".into());
    };

    let depth = q.max_depth.clamp(1, MAX_DEPTH);
    let rel_set: HashSet<&str> = q.relations.iter().map(|s| s.as_str()).collect();
    let kind_set: HashSet<&str> = q.kind_filter.iter().map(|s| s.as_str()).collect();

    let mut visited = HashSet::new();
    visited.insert(start_id.clone());
    let mut frontier = VecDeque::new();
    frontier.push_back(start_id);
    let mut result = GraphResult::default();

    for _ in 0..depth {
        let mut next = VecDeque::new();
        while let Some(node_id) = frontier.pop_front() {
            let rels: Vec<String> = if rel_set.is_empty() {
                vec!["".to_string()]
            } else {
                rel_set.iter().map(|s| s.to_string()).collect()
            };
            for rel in &rels {
                let links = db.get_links(&node_id, rel, &q.direction)?;
                for link in links {
                    let target = match &q.direction {
                        Direction::Outgoing => &link.to_id,
                        Direction::Incoming => &link.from_id,
                    };
                    if visited.contains(target) {
                        continue;
                    }
                    visited.insert(target.clone());

                    if let Some(obj) = db.get_object(target)? {
                        next.push_back(target.clone());
                        if matches_filters(
                            &obj,
                            &kind_set,
                            &q.interface_filter,
                            &q.property_filter,
                            schema,
                        ) {
                            result.objects.push(obj);
                            result.links.push(link);
                        }
                    }
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    Ok(result)
}

fn matches_filters(
    obj: &Object,
    kind_set: &HashSet<&str>,
    interface_filter: &[String],
    prop_filter: &HashMap<String, String>,
    schema: Option<&SchemaRegistry>,
) -> bool {
    if !kind_set.is_empty() && !kind_set.contains(obj.kind.as_str()) {
        return false;
    }
    if !interface_filter.is_empty()
        && !schema
            .map(|schema| schema.kind_implements_all(&obj.kind, interface_filter))
            .unwrap_or(false)
    {
        return false;
    }
    for (k, v) in prop_filter {
        if obj.properties.get(k).map(|pv| pv != v).unwrap_or(true) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::KIND_COMPONENT;
    use crate::sekai::schema::{
        InterfaceDef, ObjectType, PropertyDef, PropertyType, SchemaRegistry,
    };

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        // namespace -> comp1, comp2; comp1 -> file1
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "namespace:main".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp1".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c2".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp2".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "go".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "f1".into(),
            kind: "file".into(),
            name: "main.rs".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l2".into(),
            from_id: "r1".into(),
            to_id: "c2".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l3".into(),
            from_id: "c1".into(),
            to_id: "f1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db
    }

    #[test]
    fn test_single_hop() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2); // comp1, comp2
    }

    #[test]
    fn test_multi_hop() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 3); // comp1, comp2, file1
    }

    #[test]
    fn test_kind_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            kind_filter: vec![KIND_COMPONENT.into()],
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2); // only components
    }

    #[test]
    fn test_property_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            property_filter: HashMap::from([("language".into(), "rust".into())]),
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 1);
        assert_eq!(res.objects[0].name, "comp1");
    }

    #[test]
    fn test_start_external_id() {
        let db = setup();
        let q = GraphQuery {
            start_external_id: "namespace:main".into(),
            max_depth: 1,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2);
    }

    #[test]
    fn test_relation_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            relations: vec!["owns".into()],
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 0); // no "owns" links
    }

    #[test]
    fn test_interface_filter() {
        let db = setup();
        let mut schema = SchemaRegistry::new();
        schema.register_interface(InterfaceDef {
            name: "RiskScored".into(),
            description: "Risk scored".into(),
            properties: vec![],
            is_builtin: false,
        });
        schema.register(ObjectType {
            kind: KIND_COMPONENT.into(),
            description: "Component".into(),
            properties: vec![PropertyDef {
                name: "language".into(),
                prop_type: PropertyType::String,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: crate::sekai::schema::default_property_classification(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec!["RiskScored".into()],
        });
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            interface_filter: vec!["RiskScored".into()],
            property_filter: HashMap::from([("language".into(), "rust".into())]),
            ..Default::default()
        };
        let res = traverse(&db, &q, Some(&schema)).unwrap();
        assert_eq!(res.objects.len(), 1);
        assert_eq!(res.objects[0].id, "c1");
    }
}
